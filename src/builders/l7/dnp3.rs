//! Distributed Network Protocol v3 (DNP3, IEEE 1815-2012) wire payload builder and CRC-16 engine.
//!
//! This module implements [`calculate_dnp3_crc`] and [`build_dnp3_payload`], which serialize a
//! [`Dnp3Spec`] AST node into an IEEE 1815-2012 DNP3 frame over
//! TCP or UDP port 20000. It constructs the 10-byte Data Link Layer header (`0x0564` sync bytes,
//! length, control `0xC4`, 16-bit little-endian destination and source addresses, and reflected
//! polynomial `0xA653` CRC-16) and appends the Transport Header (`0xC0`), Application Layer header,
//! Object Header (`group`, `variation`, qualifier `0x06`), and per-16-byte chunk CRCs.

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
            let bit = (crc ^ (byte as u16)) & 0x0001;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xA653;
            }
            byte >>= 1;
        }
    }
    !crc
}

/// Builds an IEEE 1815-2012 DNP3 packet payload with Data Link, Transport, and Application layers.
pub fn build_dnp3_payload(
    _ctx: &WireContext,
    spec: &Dnp3Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let func_code: u8 = match spec.func.unwrap_or("READ").to_ascii_uppercase().as_str() {
        "CONFIRM" => 0,
        "READ" => 1,
        "WRITE" => 2,
        "SELECT" => 3,
        "OPERATE" => 4,
        "DIRECT_OPERATE" => 5,
        "RESPONSE" => 129,
        "UNSOLICITED_RESPONSE" => 130,
        _ => 1,
    };

    let mut app_layer = Vec::new();
    app_layer.push(0xC0); // App Control: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
    app_layer.push(func_code);

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

    // Transport layer: FIN=1, FIR=1, SEQ=0
    let mut transport_layer = Vec::with_capacity(1 + app_layer.len());
    transport_layer.push(0xC0);
    transport_layer.extend_from_slice(&app_layer);

    let user_data_len = transport_layer.len();
    let link_len = (5 + user_data_len) as u8; // 5 = Control(1) + Dst(2) + Src(2)

    let mut link_header = [0u8; 8];
    link_header[0] = 0x05;
    link_header[1] = 0x64;
    link_header[2] = link_len;
    link_header[3] = 0xC4; // DIR=1, PRM=1, FCB=0, FCV=0, Function 4 (Reset/User Data)
    link_header[4..6].copy_from_slice(&spec.dst.unwrap_or(1).to_le_bytes());
    link_header[6..8].copy_from_slice(&spec.src.unwrap_or(100).to_le_bytes());

    let header_crc = spec.crc.unwrap_or_else(|| calculate_dnp3_crc(&link_header));

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&link_header);
    pkt.extend_from_slice(&header_crc.to_le_bytes());

    // User data is chunked into blocks of up to 16 bytes, each followed by a 16-bit CRC
    for chunk in transport_layer.chunks(16) {
        pkt.extend_from_slice(chunk);
        let chunk_crc = calculate_dnp3_crc(chunk);
        pkt.extend_from_slice(&chunk_crc.to_le_bytes());
    }

    pkt
}
