//! Bristol Standard Asynchronous Protocol over IP (BSAP-IP) wire payload builder.
//!
//! This module implements [`build_bsap_payload`], which serializes a [`BsapSpec`] AST node into
//! an Emerson Bristol ControlWave / OpenBSI BSAP-IP telemetry packet over UDP or TCP port 1234.
//! It supports both Local BSAP framing (`SER`, 8-bit `DADD`, 8-bit `SADD`, `CTL` `0x00`/`0x40`,
//! function code, and sequence byte) and Global BSAP framing (`16-bit` little-endian `DADD`/`SADD`,
//! `CTL` `0x80`/`0xC0`, and `NSB`) for Read Data Block (`0x01`), Write Data Block (`0x02`), Poll
//! (`0x0C`), and Ident (`0x41`) messages.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Parses a BSAP function name or numeric code into an 8-bit BSAP function byte.
fn parse_bsap_func(raw: &str) -> u8 {
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
        "READ" | "RDB" | "READDATABLOCK" => 0x01,
        "WRITE" | "WDB" | "WRITEDATABLOCK" => 0x02,
        "READLIST" | "RDLIST" => 0x03,
        "WRITELIST" | "WRLIST" => 0x04,
        "POLL" => 0x0C,
        "IDENT" | "STATUS" => 0x41,
        _ => 0x01,
    }
}

/// Builds an Emerson Bristol BSAP-IP UDP or TCP packet payload.
pub fn build_bsap_payload(
    _ctx: &WireContext,
    spec: &BsapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let dst = spec.dst.unwrap_or(1);
    let src = spec.src.unwrap_or(2);
    let func = parse_bsap_func(spec.func.unwrap_or("read"));
    let seq = spec.seq_num.unwrap_or(1);
    let is_global = dst > 0xFF || src > 0xFF;

    let mut pkt = Vec::with_capacity(16 + payload_bytes.len());
    pkt.push(0x01); // SER header byte

    if is_global {
        pkt.extend_from_slice(&dst.to_le_bytes());
        pkt.extend_from_slice(&src.to_le_bytes());
        pkt.push(if spec.is_response { 0xC0 } else { 0x80 }); // Global CTL
        pkt.push(0x00); // NSB (Node Status Byte)
    } else {
        pkt.push(dst as u8);
        pkt.push(src as u8);
        pkt.push(if spec.is_response { 0x40 } else { 0x00 }); // Local CTL
    }
    pkt.push(func);
    pkt.push(seq);

    let addr = spec.addr.unwrap_or(0);
    let count = spec.count.unwrap_or(1);

    match func {
        0x01 => {
            pkt.extend_from_slice(&addr.to_le_bytes());
            pkt.push(count);
            if spec.is_response {
                pkt.extend_from_slice(&spec.value.unwrap_or(0).to_le_bytes());
            }
        }
        0x02 => {
            pkt.extend_from_slice(&addr.to_le_bytes());
            if spec.is_response {
                pkt.push(0x00);
            } else {
                pkt.extend_from_slice(&spec.value.unwrap_or(0).to_le_bytes());
            }
        }
        _ => {
            if spec.addr.is_some() || spec.count.is_some() || spec.value.is_some() {
                pkt.extend_from_slice(&addr.to_le_bytes());
                pkt.push(count);
                if let Some(v) = spec.value {
                    pkt.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
