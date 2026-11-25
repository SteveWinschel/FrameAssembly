//! Distributed Network Protocol v3 (DNP3, IEEE 1815-2012) wire payload builder and CRC-16 engine.
//!
//! This module implements [`calculate_dnp3_crc`] and [`build_dnp3_payload`], which serialize a
//! [`Dnp3Spec`] AST node into an IEEE 1815-2012 DNP3 frame over TCP or UDP port 20000. It
//! constructs the 10-byte Data Link Layer header (`0x0564` sync bytes, length `<= 255`, control
//! byte `0xC4` for master requests or `0x44` with `DIR = 0` for outstation responses, 16-bit
//! little-endian `dst` default `10` and `src` default `1`, and reflected `0xA653` CRC-16), and
//! segments transport+application payloads cleanly with per-16-byte chunk CRC-16 trailers.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Computes the IEEE 1815 DNP3 16-bit CRC over a byte slice.
///
/// Uses the DNP3 CRC polynomial `0xA653` (bit-reflected `0x3D65`) with initial value `0x0000`
/// and bitwise inverted final remainder.
pub fn calculate_dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in data {
        let mut byte = b;
        for _ in 0..8 {
            let bit = (crc ^ u16::from(byte)) & 0x0001;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xA653;
            }
            byte >>= 1;
        }
    }
    !crc
}

/// Parses a DNP3 function name or numeric code into an IEEE 1815 application function byte.
fn parse_dnp3_func_code(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "CONFIRM" => 0,
        "READ" => 1,
        "WRITE" => 2,
        "SELECT" => 3,
        "OPERATE" => 4,
        "DIRECTOPERATE" => 5,
        "RESPONSE" => 129,
        "UNSOLICITEDRESPONSE" => 130,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u8::from_str_radix(hex, 16).unwrap_or(1)
            } else {
                norm.parse::<u8>().unwrap_or(1)
            }
        }
    }
}

/// Appends one IEEE 1815 Data Link frame (`<= 250` user data octets) with per-16B CRC-16 chunks.
fn push_dnp3_link_frame(
    pkt: &mut Vec<u8>,
    ctrl: u8,
    dst: u16,
    src: u16,
    crc_override: Option<u16>,
    transport_segment: &[u8],
) {
    let link_len = u8::try_from(5usize.saturating_add(transport_segment.len())).unwrap_or(255);
    let mut link_header = [0u8; 8];
    link_header[0] = 0x05;
    link_header[1] = 0x64;
    link_header[2] = link_len;
    link_header[3] = ctrl;
    link_header[4..6].copy_from_slice(&dst.to_le_bytes());
    link_header[6..8].copy_from_slice(&src.to_le_bytes());

    let header_crc = crc_override.unwrap_or_else(|| calculate_dnp3_crc(&link_header));
    pkt.extend_from_slice(&link_header);
    pkt.extend_from_slice(&header_crc.to_le_bytes());

    for chunk in transport_segment.chunks(16) {
        pkt.extend_from_slice(chunk);
        let chunk_crc = calculate_dnp3_crc(chunk);
        pkt.extend_from_slice(&chunk_crc.to_le_bytes());
    }
}

/// Builds an IEEE 1815-2012 DNP3 packet payload with Data Link, Transport, and Application layers.
pub fn build_dnp3_payload(
    _ctx: &WireContext,
    spec: &Dnp3Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let func_code = parse_dnp3_func_code(spec.func.unwrap_or("read"));
    let is_outstation = matches!(func_code, 129 | 130);
    let ctrl = if is_outstation { 0x44u8 } else { 0xC4u8 };
    let src = spec.src.unwrap_or(1);
    let dst = spec.dst.unwrap_or(10);

    let mut app_layer = Vec::new();
    app_layer.push(0xC0); // App Control: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
    app_layer.push(func_code);
    if is_outstation {
        // Mandatory 2-byte Internal Indications (IIN1, IIN2) on Response (0x81) & Unsolicited Response (0x82)
        app_layer.extend_from_slice(&[0x00, 0x00]);
    }

    if spec.group.is_some() || spec.variation.is_some() {
        let group = spec.group.unwrap_or(60);
        let variation = spec.variation.unwrap_or(1);
        app_layer.push(group);
        app_layer.push(variation);
        app_layer.push(0x06); // Qualifier: 0x06 (all objects)
    }

    if !payload_bytes.is_empty() {
        app_layer.extend_from_slice(payload_bytes);
    }

    // Segment application layer into <= 249-byte transport payloads so each Data Link frame stays <= 250 bytes (link_len <= 255).
    let app_chunks: Vec<&[u8]> = app_layer.chunks(249).collect();
    let total_segs = app_chunks.len();
    let mut pkt = Vec::new();
    let mut transport_seg = Vec::with_capacity(250);

    for (seg_idx, app_chunk) in app_chunks.into_iter().enumerate() {
        let fir = if seg_idx == 0 { 0x40 } else { 0x00 };
        let fin = if seg_idx + 1 == total_segs { 0x80 } else { 0x00 };
        let th = fir | fin | ((seg_idx as u8) & 0x3F);

        transport_seg.clear();
        transport_seg.push(th);
        transport_seg.extend_from_slice(app_chunk);

        let crc_override = if seg_idx == 0 { spec.crc } else { None };
        push_dnp3_link_frame(&mut pkt, ctrl, dst, src, crc_override, &transport_seg);
    }

    pkt
}
