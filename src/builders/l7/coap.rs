//! Constrained Application Protocol (CoAP, RFC 7252) wire payload builder.
//!
//! This module implements [`build_coap_payload`], which serializes a [`CoapSpec`]
//! AST specification into an RFC 7252 CoAP binary frame over UDP port 5683 (or 5684 for CoAPS).
//! It packs the 4-byte CoAP header (Version `1`, 2-bit Type `CON`/`NON`/`ACK`/`RST`, Token Length,
//! `c.dd` Code byte `(class << 5) | detail`, and 16-bit Message ID), appends the optional 32-bit
//! Token, delta-encodes `Uri-Path` (Option 11) and `Content-Format` (Option 12), and appends the
//! `0xFF` payload marker when payload bytes are present.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 7252 CoAP packet payload.
pub fn build_coap_payload(
    _ctx: &WireContext,
    spec: &CoapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let type_val = match spec.msg_type.unwrap_or("CON").to_ascii_uppercase().as_str() {
        "CON" => 0u8,
        "NON" => 1u8,
        "ACK" => 2u8,
        "RST" => 3u8,
        _ => 0u8,
    };

    let code_byte = if let Some(code_str) = spec.code {
        let upper = code_str.trim().to_ascii_uppercase();
        if let Some((c_str, d_str)) = upper.split_once('.') {
            let c = c_str.parse::<u8>().unwrap_or(0) & 0x07;
            let d = d_str.parse::<u8>().unwrap_or(1) & 0x1F;
            (c << 5) | d
        } else {
            match upper.as_str() {
                "EMPTY" => 0x00,
                "GET" => 0x01,
                "POST" => 0x02,
                "PUT" => 0x03,
                "DELETE" => 0x04,
                _ => {
                    if let Ok(n) = upper.parse::<u16>() {
                        if n >= 100 {
                            let c = ((n / 100) as u8) & 0x07;
                            let d = ((n % 100) as u8) & 0x1F;
                            (c << 5) | d
                        } else {
                            n as u8
                        }
                    } else {
                        0x01
                    }
                }
            }
        }
    } else {
        0x01 // Code 0.01: GET
    };

    let tkl: u8 = if spec.token.is_some() { 4 } else { 0 };
    let b0 = 0x40 | (type_val << 4) | (tkl & 0x0F); // Ver 1 (0x40) | Type | TKL
    pkt.push(b0);
    pkt.push(code_byte);
    pkt.extend_from_slice(&spec.msgid.unwrap_or(0x1234).to_be_bytes());

    if let Some(tok) = spec.token {
        pkt.extend_from_slice(&tok.to_be_bytes());
    }

    let mut prev_opt: u8 = 0;
    if let Some(uri_path) = spec.uri_path {
        let bytes = uri_path.trim_start_matches('/').as_bytes();
        let len = bytes.len();
        if len < 13 {
            pkt.push(0xB0 | (len as u8)); // Option 11: Uri-Path (delta 11)
        } else {
            pkt.push(0xBD); // Delta 11, Len 13 (extended 1-byte length)
            pkt.push((len - 13) as u8);
        }
        pkt.extend_from_slice(bytes);
        prev_opt = 11;
    }

    if let Some(cf) = spec.content_format {
        let delta = 12 - prev_opt;
        if cf <= 0xFF {
            pkt.push((delta << 4) | 1);
            pkt.push(cf as u8);
        } else {
            pkt.push((delta << 4) | 2);
            pkt.extend_from_slice(&cf.to_be_bytes());
        }
    }

    if !payload_bytes.is_empty() {
        pkt.push(0xFF); // Payload marker
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
