//! Constrained Application Protocol (CoAP, RFC 7252) wire payload builder.
//!
//! This module implements [`build_coap_payload`], which serializes a [`CoapSpec`]
//! AST specification into an RFC 7252 CoAP binary frame over UDP port 5683 (or 5684 for CoAPS).
//! It packs the 4-byte CoAP header (Version `1`, 2-bit Type `con`/`non`/`ack`/`rst`, Token Length,
//! `c.dd` Code byte `(class << 5) | detail`, and 16-bit Message ID), appends the optional 32-bit
//! Token, delta-encodes `Uri-Path` (Option 11) and `Content-Format` (Option 12), and appends the
//! `0xFF` payload marker when payload bytes are present.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Encodes an RFC 7252 CoAP option with 4-bit, 1-byte (`13`), or 2-byte (`14`) extended delta and length.
fn push_coap_option(pkt: &mut Vec<u8>, delta: u16, val: &[u8]) {
    let (d_nib, d_ext1, d_ext2) = if delta < 13 {
        (delta as u8, None, None)
    } else if delta < 269 {
        (13u8, Some((delta - 13) as u8), None)
    } else {
        (14u8, None, Some(delta - 269))
    };
    let len = val.len();
    let (l_nib, l_ext1, l_ext2) = if len < 13 {
        (len as u8, None, None)
    } else if len < 269 {
        (13u8, Some((len - 13) as u8), None)
    } else {
        (14u8, None, Some((len - 269) as u16))
    };
    pkt.push((d_nib << 4) | l_nib);
    if let Some(b) = d_ext1 {
        pkt.push(b);
    } else if let Some(w) = d_ext2 {
        pkt.extend_from_slice(&w.to_be_bytes());
    }
    if let Some(b) = l_ext1 {
        pkt.push(b);
    } else if let Some(w) = l_ext2 {
        pkt.extend_from_slice(&w.to_be_bytes());
    }
    pkt.extend_from_slice(val);
}

/// Builds an RFC 7252 CoAP packet payload.
pub fn build_coap_payload(
    _ctx: &WireContext,
    spec: &CoapSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let type_norm = spec
        .msg_type
        .unwrap_or("con")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let type_val = match type_norm.as_str() {
        "CON" => 0u8,
        "NON" => 1u8,
        "ACK" => 2u8,
        "RST" => 3u8,
        _ => 0u8,
    };

    let code_byte = if let Some(code_str) = spec.code {
        let trimmed = code_str.trim();
        if let Some((c_str, d_str)) = trimmed.split_once('.') {
            let c = c_str.parse::<u8>().unwrap_or(0) & 0x07;
            let d = d_str.parse::<u8>().unwrap_or(1) & 0x1F;
            (c << 5) | d
        } else {
            let norm = trimmed.to_ascii_uppercase().replace(['_', '-'], "");
            match norm.as_str() {
                "EMPTY" => 0x00,
                "GET" => 0x01,
                "POST" => 0x02,
                "PUT" => 0x03,
                "DELETE" => 0x04,
                "CREATED" => 0x41,
                "DELETED" => 0x42,
                "VALID" => 0x43,
                "CHANGED" => 0x44,
                "CONTENT" => 0x45,
                "NOTFOUND" => 0x84,
                _ => {
                    if let Ok(n) = norm.parse::<u16>() {
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

    let mut prev_opt: u16 = 0;
    if let Some(uri_path) = spec.uri_path {
        for seg in uri_path.split('/').filter(|s| !s.is_empty()) {
            let delta = 11 - prev_opt;
            push_coap_option(&mut pkt, delta, seg.as_bytes());
            prev_opt = 11;
        }
    }

    if let Some(cf) = spec.content_format {
        let delta = (12 - prev_opt) as u8;
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
