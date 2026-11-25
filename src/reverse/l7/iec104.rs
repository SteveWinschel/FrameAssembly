//! IEC 60870-5-104 (Telecontrol APCI + ASDU) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `iec104` frames starting with
//! `0x68` and matching APDU length over TCP and SCTP (port `2404` and custom gateway ports for
//! valid I-frames). It decodes 6-byte `U`-frames (`startdt`, `stopdt`, `testfr` with optional
//! `confirm`), 6-byte `S`-frames (`sframe` with `rxseq`), and `I`-frames (`txseq`, `rxseq`,
//! `typeid`, `cot`/`confirm`, `ca`, 24-bit `ioa`, integer `value`, and finite IEEE 754 `real`
//! values for `M_ME_NC_1`).

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Fixed deterministic 7-byte CP56Time2a timestamp (`2025-01-01 00:00:00.000`).
const DEFAULT_CP56_TIME: [u8; 7] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 25];

/// Formats a finite little-endian IEEE 754 `f32` value as a canonical `real` modifier token.
fn push_iec104_real_token(tokens: &mut String, bytes: [u8; 4]) -> Option<()> {
    let val = f32::from_le_bytes(bytes);
    if !val.is_finite() {
        return None;
    }
    let rendered = format!("{val}");
    if rendered.contains(['e', 'E']) {
        tokens.push_str(&format!(" real \"{rendered}\""));
    } else {
        tokens.push_str(&format!(" real {rendered}"));
    }
    Some(())
}

/// Dissects an IEC 60870-5-104 APCI (`U`/`S`/`I`) frame and ASDU over TCP or SCTP.
pub(crate) fn dissect_iec104(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || payload.len() < 6
        || payload[0] != 0x68
        || payload[1] < 4
        || usize::from(payload[1]) + 2 != payload.len()
    {
        return None;
    }
    let on_known_port = src_port == 2404 || dst_port == 2404;
    let mut tokens = String::from("iec104");

    if payload.len() == 6 {
        if !on_known_port {
            return None;
        }
        if payload[3..6] == [0x00, 0x00, 0x00] {
            match payload[2] {
                0x07 => tokens.push_str(" startdt"),
                0x0B => tokens.push_str(" startdt confirm"),
                0x13 => tokens.push_str(" stopdt"),
                0x23 => tokens.push_str(" stopdt confirm"),
                0x43 => tokens.push_str(" testfr"),
                0x83 => tokens.push_str(" testfr confirm"),
                _ => return None,
            }
            return Some(ProtocolDissection {
                protocol: Protocol::Iec104,
                tokens,
                residual_payload: alloc::vec::Vec::new(),
                explicit_transport: None,
            });
        }
        if payload[2] == 0x01 && payload[3] == 0x00 && (payload[4] & 0x01) == 0 {
            let rx_seq = u16::from_le_bytes([payload[4], payload[5]]) >> 1;
            tokens.push_str(" sframe");
            if rx_seq != 0 {
                tokens.push_str(&format!(" rxseq {rx_seq}"));
            }
            return Some(ProtocolDissection {
                protocol: Protocol::Iec104,
                tokens,
                residual_payload: alloc::vec::Vec::new(),
                explicit_transport: None,
            });
        }
        return None;
    }

    if payload.len() < 16
        || (payload[2] & 0x01) != 0
        || (payload[4] & 0x01) != 0
        || payload[7] != 0x01
        || (payload[8] & 0xC0) != 0
        || payload[9] != 0x00
    {
        return None;
    }

    let tx_seq = u16::from_le_bytes([payload[2], payload[3]]) >> 1;
    let rx_seq = u16::from_le_bytes([payload[4], payload[5]]) >> 1;
    let type_id = payload[6];
    let cot = payload[8] & 0x3F;
    let ca = u16::from_le_bytes([payload[10], payload[11]]);
    let ioa = u32::from(payload[12]) | (u32::from(payload[13]) << 8) | (u32::from(payload[14]) << 16);
    if type_id == 0 {
        return None;
    }

    if !on_known_port && !matches!(type_id, 1 | 3 | 9 | 11 | 13 | 30 | 45 | 46 | 100 | 103) {
        return None;
    }

    let elem = &payload[15..];
    let mut val_opt: Option<(u32, u32)> = None;
    let mut real_bytes: Option<[u8; 4]> = None;
    let residual: &[u8];

    match type_id {
        1 | 3 | 45 | 46 => {
            let v = *elem.first()?;
            val_opt = Some((u32::from(v), 1));
            residual = &elem[1..];
        }
        9 | 11 => {
            if elem.len() < 3 || elem[2] != 0x00 {
                return None;
            }
            let v = u16::from_le_bytes([elem[0], elem[1]]);
            val_opt = Some((u32::from(v), 0));
            residual = &elem[3..];
        }
        13 => {
            if elem.len() < 5 || elem[4] != 0x00 {
                return None;
            }
            real_bytes = Some([elem[0], elem[1], elem[2], elem[3]]);
            residual = &elem[5..];
        }
        30 => {
            if elem.len() < 8 || elem[1..8] != DEFAULT_CP56_TIME {
                return None;
            }
            val_opt = Some((u32::from(elem[0]), 1));
            residual = &elem[8..];
        }
        100 => {
            let v = *elem.first()?;
            val_opt = Some((u32::from(v), 20));
            residual = &elem[1..];
        }
        103 => {
            if elem.len() < 7 || elem[0..7] != DEFAULT_CP56_TIME {
                return None;
            }
            residual = &elem[7..];
        }
        _ => {
            if elem == [0x00] {
                residual = &[];
            } else {
                residual = elem;
            }
        }
    }

    let default_cot = if type_id >= 45 { 6 } else { 3 };
    let default_ioa = if matches!(type_id, 100 | 103) { 0 } else { 1 };

    if cot == 7 {
        tokens.push_str(" confirm");
    } else if cot != default_cot {
        tokens.push_str(&format!(" cot {cot}"));
    }
    if tx_seq != 0 {
        tokens.push_str(&format!(" txseq {tx_seq}"));
    }
    if rx_seq != 0 {
        tokens.push_str(&format!(" rxseq {rx_seq}"));
    }
    if type_id != 100 {
        tokens.push_str(&format!(" typeid {type_id}"));
    }
    if ca != 1 {
        tokens.push_str(&format!(" ca {ca}"));
    }
    if ioa != default_ioa {
        tokens.push_str(&format!(" ioa {ioa}"));
    }
    if let Some((val, default_val)) = val_opt
        && val != default_val
    {
        tokens.push_str(&format!(" value {val}"));
    }
    if let Some(rb) = real_bytes {
        push_iec104_real_token(&mut tokens, rb)?;
    }

    Some(ProtocolDissection {
        protocol: Protocol::Iec104,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
