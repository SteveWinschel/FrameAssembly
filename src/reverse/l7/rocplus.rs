//! Emerson ROC Plus (ROC+) SCADA RTU Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `rocplus` frames over TCP, UDP,
//! or SCTP port `4000` (and custom serial-over-IP ports validated by the 16-bit ROC+ CRC-16).
//! It decodes the 6-byte routing header (`dst`, `group`, `src`, `opcode`, `data_len`),
//! Type-Logical-Parameter (`TLP`) selectors (`type`, `addr`, `param`), 32-bit `value` fields,
//! `isresponse` markers, optional corrupted `crc` overrides, and explicit `transport udp` flags.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::builders::l7::rocplus::compute_rocplus_crc16;
use crate::reverse::ProtocolDissection;

/// Appends non-default ROC+ TLP modifiers (`type`, `addr`, `param`) onto `tokens`.
fn push_tlp_tokens(tokens: &mut String, ptype: u8, addr: u8, param: u8) {
    if ptype != 7 {
        tokens.push_str(&format!(" type {ptype}"));
    }
    if addr != 0 {
        tokens.push_str(&format!(" addr {addr}"));
    }
    if param != 14 {
        tokens.push_str(&format!(" param {param}"));
    }
}

/// Dissects an Emerson `rocplus` frame (`6B header + data + 2B CRC-16`) over TCP, UDP, or SCTP.
pub(crate) fn dissect_rocplus(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
    ) || payload.len() < 8
        || payload[3] != 0x00
    {
        return None;
    }

    let data_len = payload[5] as usize;
    if data_len > 240 || 6usize.checked_add(data_len)?.checked_add(2)? != payload.len() {
        return None;
    }

    let crc_wire = u16::from_le_bytes([payload[payload.len() - 2], payload[payload.len() - 1]]);
    let crc_calc = compute_rocplus_crc16(&payload[..payload.len() - 2]);
    let on_known_port = src_port == 4000 || dst_port == 4000;
    let op = payload[4];
    if !on_known_port
        && (crc_wire != crc_calc
            || !matches!(op, 7 | 8 | 17 | 18 | 166 | 167 | 180 | 181 | 255))
    {
        return None;
    }

    let dst = payload[0];
    let group = payload[1];
    let src = payload[2];
    let data = &payload[6..6 + data_len];

    let mut tokens = String::from("rocplus");
    match op {
        180 => {}
        181 => tokens.push_str(" write"),
        255 => tokens.push_str(" error"),
        7 => tokens.push_str(" opcode \"login\""),
        8 => tokens.push_str(" opcode \"settime\""),
        17 => tokens.push_str(" opcode \"readconfig\""),
        18 => tokens.push_str(" opcode \"storeconfig\""),
        166 => tokens.push_str(" opcode \"readparams\""),
        167 => tokens.push_str(" opcode \"writeparams\""),
        other => tokens.push_str(&format!(" opcode {other}")),
    }
    if dst != 1 {
        tokens.push_str(&format!(" dst {dst}"));
    }
    if group != 2 {
        tokens.push_str(&format!(" group {group}"));
    }
    if src != 3 {
        tokens.push_str(&format!(" src {src}"));
    }

    let residual: &[u8] = match op {
        180 => {
            if data.len() >= 8 && data[0] == 1 {
                push_tlp_tokens(&mut tokens, data[1], data[2], data[3]);
                tokens.push_str(" isresponse");
                let val = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                &data[8..]
            } else if data.len() >= 4 && data[0] == 1 {
                push_tlp_tokens(&mut tokens, data[1], data[2], data[3]);
                &data[4..]
            } else {
                return None;
            }
        }
        181 => {
            if data.len() >= 8 && data[0] == 1 {
                push_tlp_tokens(&mut tokens, data[1], data[2], data[3]);
                let val = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                &data[8..]
            } else {
                tokens.push_str(" isresponse");
                data
            }
        }
        166 => {
            if data.len() >= 8 && data[2] == 1 {
                push_tlp_tokens(&mut tokens, data[0], data[1], data[3]);
                tokens.push_str(" isresponse");
                let val = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                &data[8..]
            } else if data.len() >= 4 && data[2] == 1 {
                push_tlp_tokens(&mut tokens, data[0], data[1], data[3]);
                &data[4..]
            } else {
                return None;
            }
        }
        167 => {
            if data.len() >= 8 && data[2] == 1 {
                push_tlp_tokens(&mut tokens, data[0], data[1], data[3]);
                let val = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                &data[8..]
            } else {
                tokens.push_str(" isresponse");
                data
            }
        }
        17 => {
            if data.is_empty() {
                data
            } else if let Some(rest) = data.strip_prefix(&[1, 0, 0, 0]) {
                tokens.push_str(" isresponse");
                rest
            } else {
                tokens.push_str(" isresponse");
                data
            }
        }
        7 => {
            if let Some(rest) = data.strip_prefix(b"LOG\0") {
                rest
            } else if let Some(rest) = data.strip_prefix(&[0x00]) {
                tokens.push_str(" isresponse");
                rest
            } else {
                data
            }
        }
        255 => {
            if data.len() >= 2 && data[1] == 0 {
                if data[0] != 1 {
                    tokens.push_str(&format!(" value {}", data[0]));
                }
                &data[2..]
            } else {
                data
            }
        }
        _ => data,
    };

    if crc_wire != crc_calc {
        tokens.push_str(&format!(" crc 0x{crc_wire:04x}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Rocplus,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: matches!(transport, TransportProto::Udp).then_some(TransportProto::Udp),
    })
}
