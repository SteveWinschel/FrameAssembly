//! WEBSOCKET protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 6455 WebSocket frame payload.
pub fn build_websocket_payload(
    _ctx: &WireContext,
    spec: &WebsocketSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let fin_bit = spec.fin_bit.unwrap_or(1) & 0x01;
    let opcode = match spec.opcode.unwrap_or("TEXT").to_ascii_uppercase().as_str() {
        "TEXT" => 1u8,
        "BINARY" => 2u8,
        "CLOSE" => 8u8,
        "PING" => 9u8,
        "PONG" => 10u8,
        _ => 1u8,
    };

    let b0 = (fin_bit << 7) | opcode;

    let content = if let Some(p) = spec.payload {
        p.as_bytes()
    } else if !payload_bytes.is_empty() {
        payload_bytes
    } else {
        b"ping"
    };

    let mask_key = spec.mask_key.unwrap_or(0x12345678);
    let mask_bytes = mask_key.to_be_bytes();

    let mut pkt = Vec::with_capacity(6 + content.len());
    pkt.push(b0);

    let len = content.len();
    if len <= 125 {
        pkt.push(0x80 | (len as u8)); // Masked bit set
    } else if len <= 65535 {
        pkt.push(0x80 | 126);
        pkt.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        pkt.push(0x80 | 127);
        pkt.extend_from_slice(&(len as u64).to_be_bytes());
    }

    pkt.extend_from_slice(&mask_bytes);

    for (i, &b) in content.iter().enumerate() {
        pkt.push(b ^ mask_bytes[i % 4]);
    }
    pkt
}
