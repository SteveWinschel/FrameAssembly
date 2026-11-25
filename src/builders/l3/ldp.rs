//! Label Distribution Protocol (LDP, RFC 5036) Layer 3 wire builder.
//!
//! Serializes an [`LdpSpec`] into an RFC 5036 LDP PDU carried over TCP port `646` (or UDP port
//! `646` when `transport udp` is selected). Encodes the 10-byte LDP PDU Header (`Version = 1`,
//! `PDU Length = 6 + msgs_len`, 4-byte `LSR ID`, 2-byte `Label Space ID`) followed by an LDP
//! Message (`hello` `0x0100`, `init` `0x0200`, `keepalive` `0x0201`, `notification` `0x0001`,
//! `labelmapping` `0x0400`, `labelrequest` `0x0401`, `labelwithdraw` `0x0402`, or `labelrelease`
//! `0x0403`) and RFC 5036 mandatory TLVs (`FEC`, `Generic Label`, `Status`, `Common Hello/Session Params`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b [transport udp] ldp [hello | init | keepalive | notification | labelmapping | labelrequest | labelwithdraw | labelrelease] [lsrid <ipv4>] [labelspace <u16>] [msgid <u32>] [holdtime <u16>] [label <u32>] [prefix "<cidr>"] [status <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Encodes a CIDR prefix string into `(afi_be16, plen, prefix_octets)` for RFC 5036 FEC TLVs.
fn encode_ldp_fec_prefix(prefix_opt: Option<&str>, prefer_v6: bool) -> (u16, u8, Vec<u8>) {
    if let Some(raw) = prefix_opt {
        let s = raw.trim();
        let (ip_str, len_opt) = match s.split_once('/') {
            Some((ip, l)) => (ip.trim(), l.trim().parse::<u8>().ok()),
            None => (s, None),
        };
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    let plen = len_opt.unwrap_or(24).min(32);
                    let blen = usize::from(plen).div_ceil(8);
                    return (1, plen, v4.octets()[..blen].to_vec());
                }
                IpAddr::V6(v6) => {
                    let plen = len_opt.unwrap_or(64).min(128);
                    let blen = usize::from(plen).div_ceil(8);
                    return (2, plen, v6.octets()[..blen].to_vec());
                }
            }
        }
    }
    if prefer_v6 {
        (2, 32, alloc::vec![0x20, 0x01, 0x0d, 0xb8])
    } else {
        (1, 24, alloc::vec![10, 0, 0])
    }
}

/// Appends an RFC 5036 FEC TLV (`0x0100`) containing a single Address Prefix FEC element (`0x02`).
fn push_fec_tlv(out: &mut Vec<u8>, prefix_opt: Option<&str>, prefer_v6: bool) {
    let (afi, plen, octets) = encode_ldp_fec_prefix(prefix_opt, prefer_v6);
    let tlv_len = (4 + octets.len()) as u16;
    out.extend_from_slice(&0x0100_u16.to_be_bytes());
    out.extend_from_slice(&tlv_len.to_be_bytes());
    out.push(0x02); // Address Prefix FEC Element
    out.extend_from_slice(&afi.to_be_bytes());
    out.push(plen);
    out.extend_from_slice(&octets);
}

/// Builds an RFC 5036 Label Distribution Protocol (`ldp`) PDU and returns `(bytes, 646)`.
pub fn build_ldp_payload(ctx: &WireContext, spec: &LdpSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let is_v6 = ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6();
    let is_udp = ctx.transport == Some(TransportProto::Udp);
    let msg_type = spec.msg_type.unwrap_or(
        if spec.label.is_some() || spec.prefix.is_some() {
            LdpType::LabelMapping
        } else if is_udp {
            LdpType::Hello
        } else {
            LdpType::Keepalive
        },
    );

    let lsr_id = match spec.lsr_id {
        Some(IpAddr::V4(v4)) => v4.octets(),
        _ => match ctx.src_ip {
            IpAddr::V4(v4) if !v4.is_unspecified() => v4.octets(),
            _ => [10, 0, 0, 1],
        },
    };
    let peer_lsr_id = match ctx.dst_ip {
        IpAddr::V4(v4) if !v4.is_unspecified() => v4.octets(),
        _ => [10, 0, 0, 2],
    };
    let label_space = spec.label_space.unwrap_or(0);
    let msg_id = spec.msg_id.unwrap_or(1);

    let mut tlvs = Vec::new();
    let msg_code: u16 = match msg_type {
        LdpType::Hello => {
            // Common Hello Parameters TLV (0x0400, len 4)
            let hold = spec.holdtime.unwrap_or(15);
            tlvs.extend_from_slice(&0x0400_u16.to_be_bytes());
            tlvs.extend_from_slice(&4_u16.to_be_bytes());
            tlvs.extend_from_slice(&hold.to_be_bytes());
            tlvs.extend_from_slice(&0_u16.to_be_bytes());
            0x0100
        }
        LdpType::Init => {
            // Common Session Parameters TLV (0x0500, len 14)
            let keepalive = spec.holdtime.unwrap_or(45);
            tlvs.extend_from_slice(&0x0500_u16.to_be_bytes());
            tlvs.extend_from_slice(&14_u16.to_be_bytes());
            tlvs.extend_from_slice(&1_u16.to_be_bytes()); // Protocol Version 1
            tlvs.extend_from_slice(&keepalive.to_be_bytes()); // KeepAlive Time
            tlvs.extend_from_slice(&0_u16.to_be_bytes()); // A/D flags + PVLim
            tlvs.extend_from_slice(&4096_u16.to_be_bytes()); // Max PDU Length
            tlvs.extend_from_slice(&peer_lsr_id); // Receiver LDP ID
            tlvs.extend_from_slice(&0_u16.to_be_bytes()); // Receiver Label Space
            0x0200
        }
        LdpType::Keepalive => 0x0201,
        LdpType::Notification => {
            // Status TLV (0x0300, len 10)
            let status = spec.status.unwrap_or(0);
            tlvs.extend_from_slice(&0x0300_u16.to_be_bytes());
            tlvs.extend_from_slice(&10_u16.to_be_bytes());
            tlvs.extend_from_slice(&status.to_be_bytes());
            tlvs.extend_from_slice(&0_u32.to_be_bytes());
            tlvs.extend_from_slice(&0_u16.to_be_bytes());
            0x0001
        }
        LdpType::LabelMapping => {
            push_fec_tlv(&mut tlvs, spec.prefix, is_v6);
            // Generic Label TLV (0x0200, len 4)
            let label = spec.label.unwrap_or(16) & 0x000F_FFFF;
            tlvs.extend_from_slice(&0x0200_u16.to_be_bytes());
            tlvs.extend_from_slice(&4_u16.to_be_bytes());
            tlvs.extend_from_slice(&label.to_be_bytes());
            0x0400
        }
        LdpType::LabelRequest => {
            push_fec_tlv(&mut tlvs, spec.prefix, is_v6);
            0x0401
        }
        LdpType::LabelWithdraw | LdpType::LabelRelease => {
            push_fec_tlv(&mut tlvs, spec.prefix, is_v6);
            if let Some(lbl) = spec.label {
                tlvs.extend_from_slice(&0x0200_u16.to_be_bytes());
                tlvs.extend_from_slice(&4_u16.to_be_bytes());
                tlvs.extend_from_slice(&(lbl & 0x000F_FFFF).to_be_bytes());
            }
            if msg_type == LdpType::LabelWithdraw {
                0x0402
            } else {
                0x0403
            }
        }
    };

    let msg_len = (4 + tlvs.len()) as u16;
    let pdu_len = (6 + 4 + usize::from(msg_len)) as u16;

    let mut ldp = Vec::with_capacity(4 + usize::from(pdu_len) + payload.len());
    ldp.extend_from_slice(&1_u16.to_be_bytes()); // Version 1
    ldp.extend_from_slice(&pdu_len.to_be_bytes());
    ldp.extend_from_slice(&lsr_id);
    ldp.extend_from_slice(&label_space.to_be_bytes());
    ldp.extend_from_slice(&msg_code.to_be_bytes());
    ldp.extend_from_slice(&msg_len.to_be_bytes());
    ldp.extend_from_slice(&msg_id.to_be_bytes());
    ldp.extend_from_slice(&tlvs);
    ldp.extend_from_slice(payload);

    (ldp, 646)
}
