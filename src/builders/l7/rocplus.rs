//! Emerson ROC Plus (ROC+) SCADA RTU wire payload builder and CRC-16 engine.
//!
//! This module implements [`compute_rocplus_crc16`] and [`build_rocplus_payload`], which
//! serialize a [`RocplusSpec`] AST node into an Emerson Bristol ROC Plus (`rocplus`) message over
//! TCP or UDP port 4000. It constructs the 6-byte ROC+ routing header (Destination Unit,
//! Destination Group, Source Unit, Source Group `0`, Opcode, and Data Length `0..=240`),
//! Type-Logical-Parameter (`TLP`) request/response bodies, and appends the 16-bit little-endian
//! ROC+ CRC-16 (`0xA001` reflected polynomial, initial `0x0000`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Computes the Emerson ROC Plus 16-bit CRC over `data` (polynomial `0xA001`, initial `0x0000`).
pub fn compute_rocplus_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if (crc & 0x0001) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Parses a ROC+ opcode name or numeric code into an 8-bit command byte.
fn parse_rocplus_opcode(raw: &str) -> u8 {
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
        "LOGIN" | "SECURITY" => 7,
        "SETTIME" | "CLOCK" => 8,
        "READCONFIG" | "CONFIG" => 17,
        "STORECONFIG" | "WRITECONFIG" => 18,
        "READPARAMS" => 166,
        "WRITEPARAMS" => 167,
        "READ" | "READTLP" => 180,
        "WRITE" | "WRITETLP" => 181,
        "ERROR" => 255,
        _ => 180,
    }
}

/// Builds an Emerson ROC Plus (ROC+) TCP/UDP packet payload with 16-bit CRC trailer.
pub fn build_rocplus_payload(
    _ctx: &WireContext,
    spec: &RocplusSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let dst = spec.dst.unwrap_or(1);
    let group = spec.group.unwrap_or(2);
    let src = spec.src.unwrap_or(3);
    let op = parse_rocplus_opcode(spec.opcode.unwrap_or("read"));
    let ptype = spec.point_type.unwrap_or(7);
    let addr = spec.addr.unwrap_or(0);
    let param = spec.param.unwrap_or(14);

    let mut body = Vec::new();
    match op {
        180 => {
            body.extend_from_slice(&[1, ptype, addr, param]);
            if spec.is_response {
                body.extend_from_slice(&spec.value.unwrap_or(0).to_le_bytes());
            }
        }
        181 => {
            if !spec.is_response {
                body.extend_from_slice(&[1, ptype, addr, param]);
                body.extend_from_slice(&spec.value.unwrap_or(0).to_le_bytes());
            }
        }
        166 => {
            body.extend_from_slice(&[ptype, addr, 1, param]);
            if spec.is_response {
                body.extend_from_slice(&spec.value.unwrap_or(0).to_le_bytes());
            }
        }
        167 => {
            if !spec.is_response {
                body.extend_from_slice(&[ptype, addr, 1, param]);
                body.extend_from_slice(&spec.value.unwrap_or(0).to_le_bytes());
            }
        }
        17 => {
            if spec.is_response && payload_bytes.is_empty() {
                body.extend_from_slice(&[1, 0, 0, 0]);
            }
        }
        7 => {
            if payload_bytes.is_empty() {
                if spec.is_response {
                    body.push(0x00);
                } else {
                    body.extend_from_slice(b"LOG\0");
                }
            }
        }
        255 => {
            let err_code = (spec.value.unwrap_or(1) & 0xFF) as u8;
            body.extend_from_slice(&[err_code, 0x00]);
        }
        _ => {
            if spec.point_type.is_some()
                || spec.addr.is_some()
                || spec.param.is_some()
                || spec.value.is_some()
            {
                body.extend_from_slice(&[ptype, addr, param]);
                if let Some(v) = spec.value {
                    body.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
    }

    if !payload_bytes.is_empty() {
        let avail = 240usize.saturating_sub(body.len());
        body.extend_from_slice(&payload_bytes[..payload_bytes.len().min(avail)]);
    }
    body.truncate(240);

    let mut pkt = Vec::with_capacity(6 + body.len() + 2);
    pkt.push(dst);
    pkt.push(group);
    pkt.push(src);
    pkt.push(0x00);
    pkt.push(op);
    pkt.push(body.len() as u8);
    pkt.extend_from_slice(&body);

    let crc = spec.crc.unwrap_or_else(|| compute_rocplus_crc16(&pkt));
    pkt.extend_from_slice(&crc.to_le_bytes());
    pkt
}
