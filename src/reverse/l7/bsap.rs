//! Bristol Standard Asynchronous Protocol over IP (BSAP-IP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `bsap` Local (6-byte header) and
//! Global (9-byte header) telemetry messages over UDP, TCP, and SCTP port `1234`. It validates
//! the `0x01` `SER` header and `CTL` control bits (`0x00`/`0x40` Local, `0x80`/`0xC0` Global with
//! `NSB == 0x00`), decodes `dst`, `src`, `func` (`read`, `write`, `poll`, or hex/numeric code),
//! `seqnum`, `addr`, `count`, `value`, `isresponse`, and preserves explicit `transport tcp` overrides.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a Bristol `bsap` Local or Global BSAP-IP message on port `1234`.
pub(crate) fn dissect_bsap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Udp | TransportProto::Tcp | TransportProto::Sctp
    ) || !(src_port == 1234 || dst_port == 1234)
        || payload.len() < 6
        || payload[0] != 0x01
    {
        return None;
    }

    let (dst, src, is_resp, func, seq, body) = if matches!(payload[3], 0x00 | 0x40) {
        (
            u16::from(payload[1]),
            u16::from(payload[2]),
            payload[3] == 0x40,
            payload[4],
            payload[5],
            &payload[6..],
        )
    } else if payload.len() >= 9 && matches!(payload[5], 0x80 | 0xC0) && payload[6] == 0x00 {
        let d = u16::from_le_bytes([payload[1], payload[2]]);
        let s = u16::from_le_bytes([payload[3], payload[4]]);
        if d <= 0xFF && s <= 0xFF {
            return None;
        }
        (d, s, payload[5] == 0xC0, payload[7], payload[8], &payload[9..])
    } else {
        return None;
    };

    let mut tokens = String::from("bsap");
    match func {
        0x01 => {}
        0x02 => tokens.push_str(" write"),
        0x0C => tokens.push_str(" poll"),
        0x41 => tokens.push_str(" func \"ident\""),
        other => tokens.push_str(&format!(" func \"0x{other:02x}\"")),
    }
    if dst != 1 {
        tokens.push_str(&format!(" dst {dst}"));
    }
    if src != 2 {
        tokens.push_str(&format!(" src {src}"));
    }
    if seq != 1 {
        tokens.push_str(&format!(" seqnum {seq}"));
    }

    let residual: &[u8] = match func {
        0x01 => {
            if !is_resp && body.len() >= 3 {
                let addr = u16::from_le_bytes([body[0], body[1]]);
                let count = body[2];
                if addr != 0 {
                    tokens.push_str(&format!(" addr {addr}"));
                }
                if count != 1 {
                    tokens.push_str(&format!(" count {count}"));
                }
                &body[3..]
            } else if is_resp && body.len() >= 7 {
                let addr = u16::from_le_bytes([body[0], body[1]]);
                let count = body[2];
                let val = u32::from_le_bytes([body[3], body[4], body[5], body[6]]);
                if addr != 0 {
                    tokens.push_str(&format!(" addr {addr}"));
                }
                if count != 1 {
                    tokens.push_str(&format!(" count {count}"));
                }
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                &body[7..]
            } else {
                return None;
            }
        }
        0x02 => {
            if !is_resp && body.len() >= 6 {
                let addr = u16::from_le_bytes([body[0], body[1]]);
                let val = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
                if addr != 0 {
                    tokens.push_str(&format!(" addr {addr}"));
                }
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                &body[6..]
            } else if is_resp && body.len() >= 3 && body[2] == 0x00 {
                let addr = u16::from_le_bytes([body[0], body[1]]);
                if addr != 0 {
                    tokens.push_str(&format!(" addr {addr}"));
                }
                &body[3..]
            } else {
                return None;
            }
        }
        _ => body,
    };

    if is_resp {
        tokens.push_str(" isresponse");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Bsap,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: matches!(transport, TransportProto::Tcp).then_some(TransportProto::Tcp),
    })
}
