//! COAP protocol wire builder.

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

    let b0 = 0x40 | (type_val << 4); // Ver 1 (0x40) | Type
    pkt.push(b0);
    pkt.push(0x01); // Code 0.01: GET
    pkt.extend_from_slice(&spec.msgid.unwrap_or(0x1234).to_be_bytes());

    if let Some(uri_path) = spec.uri_path {
        let bytes = uri_path.trim_start_matches('/').as_bytes();
        let len = bytes.len() as u8;
        pkt.push(0xB0 | (len & 0x0F)); // Option 11: Uri-Path
        pkt.extend_from_slice(bytes);
    }

    if !payload_bytes.is_empty() {
        pkt.push(0xFF); // Payload marker
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
