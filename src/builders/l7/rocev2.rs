//! RDMA over Converged Ethernet v2 (RoCEv2, IBTA Annex A17) wire payload builder and ICRC engine.
//!
//! This module implements [`compute_rocev2_icrc`] and [`build_rocev2_payload`], which serialize a
//! [`Rocev2Spec`] AST node into an IBTA Annex A17 RoCEv2 datagram over UDP port 4791. It constructs
//! the 12-byte big-endian Base Transport Header (`BTH` with Opcode, PadCount, Partition Key
//! `P_Key`, Destination Queue Pair `DestQP`, Acknowledge Request bit, and Packet Sequence Number
//! `PSN`), extended headers (`RETH`, `AETH`, `ImmDt`, `DETH`), 4-byte alignment padding, and the
//! 4-byte Invariant CRC (`ICRC`) computed over the virtual LRH (`0xFF` * 8), masked IP/UDP headers,
//! and masked `BTH`.

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::{build_ipv4_header, build_ipv6_header, ieee8023_crc32};
use alloc::vec::Vec;
use core::net::IpAddr;

/// Parses a RoCEv2 BTH opcode name or numeric code into an 8-bit InfiniBand transport opcode.
fn parse_rocev2_opcode(raw: &str) -> u8 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(val) = u8::from_str_radix(hex, 16)
    {
        return val;
    }
    if let Ok(val) = trimmed.parse::<u8>() {
        return val;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "SENDFIRST" => 0x00,
        "SENDMIDDLE" => 0x01,
        "SENDLAST" => 0x02,
        "SENDLASTIMM" => 0x03,
        "SENDONLY" | "SEND" => 0x04,
        "SENDONLYIMM" => 0x05,
        "RDMAWRITEFIRST" => 0x06,
        "RDMAWRITEMIDDLE" => 0x07,
        "RDMAWRITELAST" => 0x08,
        "RDMAWRITELASTIMM" => 0x09,
        "RDMAWRITE" | "RDMAWRITEONLY" | "WRITE" => 0x0A,
        "RDMAWRITEIMM" | "RDMAWRITEONLYIMM" => 0x0B,
        "RDMAREAD" | "RDMAREADREQ" | "RDMAREADREQUEST" | "READ" => 0x0C,
        "RDMAREADFIRST" => 0x0D,
        "RDMAREADMIDDLE" => 0x0E,
        "RDMAREADLAST" => 0x0F,
        "RDMAREADRESP" | "RDMAREADRESPONSE" => 0x10,
        "ACK" | "ACKNOWLEDGE" => 0x11,
        "ATOMICSWAP" | "CMPANDSWAP" => 0x12,
        "ATOMICADD" | "FETCHANDADD" => 0x13,
        "ATOMICACK" => 0x14,
        "UDSEND" | "UDSENDONLY" => 0x64,
        _ => 0x0A,
    }
}

/// Computes the 32-bit IBTA Annex A17 RoCEv2 Invariant CRC (`ICRC`) over `bth_and_body`.
pub fn compute_rocev2_icrc(ctx: &WireContext, bth_and_body: &[u8]) -> u32 {
    let udp_len = 8usize.saturating_add(bth_and_body.len()).saturating_add(4);
    let mut masked = Vec::with_capacity(8 + 40 + 8 + bth_and_body.len());

    // 8-byte virtual InfiniBand Local Route Header (all 0xFF)
    masked.extend_from_slice(&[0xFF; 8]);

    match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut ip_hdr = build_ipv4_header(s.octets(), d.octets(), 17, ctx.l3, udp_len)
                .unwrap_or_else(|_| alloc::vec![0u8; 20]);
            if ip_hdr.len() >= 12 {
                ip_hdr[1] = 0xFF; // TOS / DSCP+ECN masked
                ip_hdr[8] = 0xFF; // TTL masked
                ip_hdr[10] = 0xFF; // Header checksum masked
                ip_hdr[11] = 0xFF;
            }
            masked.extend_from_slice(&ip_hdr);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut ip_hdr = build_ipv6_header(s.octets(), d.octets(), 17, ctx.l3, udp_len)
                .unwrap_or_else(|_| alloc::vec![0u8; 40]);
            if ip_hdr.len() >= 8 {
                ip_hdr[0] = (ip_hdr[0] & 0xF0) | 0x0F; // Traffic Class + Flow Label masked
                ip_hdr[1] = 0xFF;
                ip_hdr[2] = 0xFF;
                ip_hdr[3] = 0xFF;
                ip_hdr[7] = 0xFF; // Hop Limit masked
            }
            masked.extend_from_slice(&ip_hdr);
        }
        _ => {
            masked.extend_from_slice(&[0x45, 0xFF, 0, 0, 0, 0, 0, 0, 0xFF, 17, 0xFF, 0xFF]);
            masked.extend_from_slice(&[0u8; 8]);
        }
    }

    // UDP header with checksum masked to 0xFFFF
    let udp_len_u16 = u16::try_from(udp_len).unwrap_or(u16::MAX);
    masked.extend_from_slice(&ctx.src_port.to_be_bytes());
    masked.extend_from_slice(&ctx.dst_port.to_be_bytes());
    masked.extend_from_slice(&udp_len_u16.to_be_bytes());
    masked.extend_from_slice(&[0xFF, 0xFF]);

    // BTH + Extended Headers + Padded Payload with BTH byte 4 (FECN/BECN/Resv6) masked to 0xFF
    let bth_off = masked.len();
    masked.extend_from_slice(bth_and_body);
    if let Some(resv8) = masked.get_mut(bth_off + 4) {
        *resv8 = 0xFF;
    }

    ieee8023_crc32(&masked)
}

/// Builds an IBTA Annex A17 RoCEv2 UDP datagram payload (`BTH + ExtHdr + Payload + Pad + ICRC`).
pub fn build_rocev2_payload(
    ctx: &WireContext,
    spec: &Rocev2Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let opcode = parse_rocev2_opcode(spec.opcode.unwrap_or("rdmawrite"));
    let pkey = spec.pkey.unwrap_or(0xFFFF);
    let dest_qp = spec.dest_qp.unwrap_or(2) & 0x00FF_FFFF;
    let psn = spec.psn.unwrap_or(1) & 0x00FF_FFFF;
    let va = spec.va.unwrap_or(0x1000);
    let rkey = spec.rkey.unwrap_or(0x1234);
    let syndrome = spec.syndrome.unwrap_or(0);
    let msn = spec.msn.unwrap_or(1) & 0x00FF_FFFF;

    let mut body = Vec::new();
    match opcode {
        0x06 | 0x0A | 0x0B => {
            let default_len = if payload_bytes.is_empty() {
                4u32
            } else {
                u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX)
            };
            let dmalen = spec.dma_len.unwrap_or(default_len);
            body.extend_from_slice(&va.to_be_bytes());
            body.extend_from_slice(&rkey.to_be_bytes());
            body.extend_from_slice(&dmalen.to_be_bytes());
            if opcode == 0x0B {
                body.extend_from_slice(&0u32.to_be_bytes()); // ImmDt
            }
            if payload_bytes.is_empty() {
                let fill_len = usize::try_from(dmalen).unwrap_or(1024).min(1024);
                body.resize(body.len() + fill_len, 0x00);
            } else {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0C => {
            let dmalen = spec.dma_len.unwrap_or(64);
            body.extend_from_slice(&va.to_be_bytes());
            body.extend_from_slice(&rkey.to_be_bytes());
            body.extend_from_slice(&dmalen.to_be_bytes());
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x0D | 0x0F | 0x10 | 0x11 => {
            let aeth = ((u32::from(syndrome)) << 24) | msn;
            body.extend_from_slice(&aeth.to_be_bytes());
            if opcode != 0x11 && payload_bytes.is_empty() {
                let fill_len = usize::try_from(spec.dma_len.unwrap_or(4))
                    .unwrap_or(1024)
                    .min(1024);
                body.resize(body.len() + fill_len, 0x00);
            } else if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x64 => {
            body.extend_from_slice(&0x8001_0000u32.to_be_bytes()); // Q_Key
            body.push(0x00);
            body.extend_from_slice(&2u32.to_be_bytes()[1..4]); // SrcQP = 2
            if payload_bytes.is_empty() {
                body.extend_from_slice(&[0u8; 4]);
            } else {
                body.extend_from_slice(payload_bytes);
            }
        }
        _ => {
            if matches!(opcode, 0x03 | 0x05 | 0x09) {
                body.extend_from_slice(&0u32.to_be_bytes()); // ImmDt
            }
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
    }

    let pad_cnt = (4 - (body.len() % 4)) % 4;
    body.resize(body.len() + pad_cnt, 0x00);

    let mut pkt = Vec::with_capacity(12 + body.len() + 4);
    pkt.push(opcode);
    pkt.push(((pad_cnt as u8) & 0x03) << 4);
    pkt.extend_from_slice(&pkey.to_be_bytes());
    pkt.push(0x00); // Reserved8
    let qp_be = dest_qp.to_be_bytes();
    pkt.extend_from_slice(&qp_be[1..4]);
    pkt.push(if spec.ack_req { 0x80 } else { 0x00 });
    let psn_be = psn.to_be_bytes();
    pkt.extend_from_slice(&psn_be[1..4]);
    pkt.extend_from_slice(&body);

    if let Some(explicit_icrc) = spec.icrc {
        pkt.extend_from_slice(&explicit_icrc.to_be_bytes());
    } else {
        let icrc = compute_rocev2_icrc(ctx, &pkt);
        pkt.extend_from_slice(&icrc.to_le_bytes());
    }
    pkt
}
