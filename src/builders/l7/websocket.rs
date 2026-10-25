//! The WebSocket Protocol (RFC 6455) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire The WebSocket Protocol frames over TCP port 80 (ws://) or TCP port 443 (wss://).
//! The wire encoder constructs a 2-to-14-byte RFC 6455 binary frame header: Byte 0 packs 1-bit `FIN` flag, 3-bit `RSV1..3` extension bits, and 4-bit `Opcode` (`0x1` TEXT, `0x2` BINARY, `0x8` CLOSE, `0x9` PING, `0xA` PONG); Byte 1 packs 1-bit `MASK` flag and 7-bit Payload Length (with optional 16-bit or 64-bit extended length), followed by an optional 32-bit XOR `Masking-Key` and masked/unmasked application payload. When optional fields in [`WebsocketSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b WEBSOCKET [OPCODE <str>] [FIN_BIT <u8>] [MASK_KEY <u32>] [PAYLOAD <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 6455 WebSocket frame payload.
/// Syntax mapping: `WEBSOCKET [OPCODE <str>] [FIN_BIT <u8>] [MASK_KEY <u32>] [PAYLOAD <str>]`
#[doc(alias = "WEBSOCKET")]
#[doc(alias = "WS")]
#[doc(alias = "WSS")]
#[doc(alias = "RFC6455")]
#[doc(alias = "MASK_KEY")]
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
