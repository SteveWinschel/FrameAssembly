//! RDMA over Converged Ethernet v2 (RoCEv2, IBTA Annex A17) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `rocev2` datagrams over UDP or
//! SCTP port `4791`. It validates the 12-byte InfiniBand Base Transport Header (`BTH` with
//! `tver == 0`, `resv8 == 0`, `resv7 == 0`), strips 4-byte trailing `ICRC` and `PadCount`
//! zero-padding bytes, decodes `opcode`, `pkey`, `destqp`, `ackreq`, `seqnum`, `RETH` (`addr`,
//! `key`, `count`), `AETH` (`status`, `msgid`), and `DETH` fields while eliding defaults.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects an IBTA Annex A17 `rocev2` UDP or SCTP datagram on port `4791`.
pub(crate) fn dissect_rocev2(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Udp | TransportProto::Sctp)
        || !(src_port == 4791 || dst_port == 4791)
        || payload.len() < 16
        || !(payload.len() - 4).is_multiple_of(4)
    {
        return None;
    }

    let bth = &payload[0..12];
    let opcode = bth[0];
    let flags_byte = bth[1];
    if (flags_byte & 0xCF) != 0 || bth[4] != 0x00 || (bth[8] & 0x7F) != 0 {
        return None;
    }

    let pad_cnt = usize::from((flags_byte >> 4) & 0x03);
    let body_end = payload.len() - 4;
    if body_end < 12usize.checked_add(pad_cnt)? {
        return None;
    }
    let pad_start = body_end - pad_cnt;
    if payload[pad_start..body_end].iter().any(|&b| b != 0) {
        return None;
    }
    let body = &payload[12..pad_start];

    let pkey = u16::from_be_bytes([bth[2], bth[3]]);
    let dest_qp = u32::from_be_bytes([0, bth[5], bth[6], bth[7]]);
    let ack_req = (bth[8] & 0x80) != 0;
    let psn = u32::from_be_bytes([0, bth[9], bth[10], bth[11]]);

    let mut tokens = String::from("rocev2");
    match opcode {
        0x00 => tokens.push_str(" opcode \"sendfirst\""),
        0x01 => tokens.push_str(" opcode \"sendmiddle\""),
        0x02 => tokens.push_str(" opcode \"sendlast\""),
        0x03 => tokens.push_str(" opcode \"sendlastimm\""),
        0x04 => tokens.push_str(" opcode \"sendonly\""),
        0x05 => tokens.push_str(" opcode \"sendonlyimm\""),
        0x06 => tokens.push_str(" opcode \"rdmawritefirst\""),
        0x07 => tokens.push_str(" opcode \"rdmawritemiddle\""),
        0x08 => tokens.push_str(" opcode \"rdmawritelast\""),
        0x09 => tokens.push_str(" opcode \"rdmawritelastimm\""),
        0x0A => {}
        0x0B => tokens.push_str(" opcode \"rdmawriteimm\""),
        0x0C => tokens.push_str(" read"),
        0x0D => tokens.push_str(" opcode \"rdmareadfirst\""),
        0x0E => tokens.push_str(" opcode \"rdmareadmiddle\""),
        0x0F => tokens.push_str(" opcode \"rdmareadlast\""),
        0x10 => tokens.push_str(" opcode \"rdmareadresp\""),
        0x11 => tokens.push_str(" opcode \"ack\""),
        0x64 => tokens.push_str(" opcode \"udsend\""),
        other => tokens.push_str(&format!(" opcode 0x{other:02x}")),
    }

    if pkey != 0xFFFF {
        tokens.push_str(&format!(" pkey 0x{pkey:04x}"));
    }
    if dest_qp != 2 {
        tokens.push_str(&format!(" destqp {dest_qp}"));
    }
    if ack_req {
        tokens.push_str(" ackreq");
    }
    if psn != 1 {
        tokens.push_str(&format!(" seqnum {psn}"));
    }

    let residual: &[u8] = match opcode {
        0x06 | 0x0A | 0x0B => {
            let min_hdr = if opcode == 0x0B { 20 } else { 16 };
            if body.len() < min_hdr {
                return None;
            }
            let va = u64::from_be_bytes([
                body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
            ]);
            let rkey = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let dmalen = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
            if opcode == 0x0B && body[16..20] != [0, 0, 0, 0] {
                return None;
            }
            if va != 0x1000 {
                tokens.push_str(&format!(" addr 0x{va:x}"));
            }
            if rkey != 0x1234 {
                tokens.push_str(&format!(" key 0x{rkey:x}"));
            }
            let data = &body[min_hdr..];
            if data.len() <= 1024
                && dmalen == data.len() as u32
                && data.iter().all(|&b| b == 0)
                && !data.is_empty()
            {
                if dmalen != 4 {
                    tokens.push_str(&format!(" count {dmalen}"));
                }
                &[]
            } else {
                if dmalen != data.len() as u32 {
                    tokens.push_str(&format!(" count {dmalen}"));
                }
                data
            }
        }
        0x0C => {
            if body.len() < 16 {
                return None;
            }
            let va = u64::from_be_bytes([
                body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
            ]);
            let rkey = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let dmalen = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
            if va != 0x1000 {
                tokens.push_str(&format!(" addr 0x{va:x}"));
            }
            if rkey != 0x1234 {
                tokens.push_str(&format!(" key 0x{rkey:x}"));
            }
            if dmalen != 64 {
                tokens.push_str(&format!(" count {dmalen}"));
            }
            &body[16..]
        }
        0x0D | 0x0F | 0x10 | 0x11 => {
            if body.len() < 4 {
                return None;
            }
            let syndrome = body[0];
            let msn = u32::from_be_bytes([0, body[1], body[2], body[3]]);
            if syndrome != 0 {
                tokens.push_str(&format!(" status {syndrome}"));
            }
            if msn != 1 {
                tokens.push_str(&format!(" msgid {msn}"));
            }
            let data = &body[4..];
            if opcode != 0x11 && data == [0u8; 4] {
                &[]
            } else {
                data
            }
        }
        0x64 => {
            if body.len() < 8
                || body[0..4] != 0x8001_0000u32.to_be_bytes()
                || body[4..8] != [0x00, 0x00, 0x00, 0x02]
            {
                return None;
            }
            let data = &body[8..];
            if data == [0u8; 4] { &[] } else { data }
        }
        _ => {
            let hdr = if matches!(opcode, 0x03 | 0x05 | 0x09) {
                if body.len() < 4 || body[0..4] != [0, 0, 0, 0] {
                    return None;
                }
                4
            } else {
                0
            };
            &body[hdr..]
        }
    };

    Some(ProtocolDissection {
        protocol: Protocol::Rocev2,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
