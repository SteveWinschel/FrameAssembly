//! Hypertext Transfer Protocol Version 2 (HTTP/2) (RFC 9113 (HTTP/2) / RFC 7541 (HPACK)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Hypertext Transfer Protocol Version 2 (HTTP/2) frames over TCP port 443 (h2 over TLS) or TCP port 80 (h2c cleartext).
//! The wire encoder constructs a 24-octet client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and 9-octet binary frame headers containing 24-bit payload Length, 8-bit Frame Type (`0x0` DATA, `0x1` HEADERS, `0x4` SETTINGS, `0x6` PING, `0x7` GOAWAY, `0x8` WINDOW_UPDATE), 8-bit Flags (`END_STREAM = 0x1`, `END_HEADERS = 0x4`, `ACK = 0x1`), 1-bit Reserved flag, and 31-bit Stream Identifier. When optional fields in [`Http2Spec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b HTTP2 [PREFACE | SETTINGS | HEADERS | DATA | WINDOW_UPDATE | PING | GOAWAY] [STREAM_ID <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9113 HTTP/2 connection preface or binary frame.
/// Syntax mapping: `HTTP2 [PREFACE | SETTINGS | HEADERS | DATA | WINDOW_UPDATE | PING | GOAWAY] [STREAM_ID <u32>]`
#[doc(alias = "HTTP2")]
#[doc(alias = "H2")]
#[doc(alias = "RFC9113")]
#[doc(alias = "RFC7540")]
#[doc(alias = "STREAM_ID")]
pub fn build_http2_payload(
    _ctx: &WireContext,
    spec: &Http2Spec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    if spec.is_preface {
        let mut pkt = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
        return pkt;
    }

    let (frame_type, flags) = if spec.is_headers {
        (1u8, 0x05u8) // HEADERS + END_STREAM + END_HEADERS
    } else if spec.is_data {
        (0u8, 0x01u8) // DATA + END_STREAM
    } else if spec.is_window_update {
        (8u8, 0x00u8) // WINDOW_UPDATE
    } else if spec.is_ping {
        (6u8, 0x00u8) // PING
    } else if spec.is_goaway {
        (7u8, 0x00u8) // GOAWAY
    } else if spec.is_settings {
        (4u8, 0x00u8) // SETTINGS
    } else {
        // Default: SETTINGS frame (Type 4)
        (4u8, 0x00u8)
    };

    let stream_id = spec.stream_id.unwrap_or(0);
    let length = payload_bytes.len() as u32;

    let mut pkt = Vec::with_capacity(9 + payload_bytes.len());
    // 24-bit Length
    pkt.push((length >> 16) as u8);
    pkt.push((length >> 8) as u8);
    pkt.push(length as u8);
    pkt.push(frame_type);
    pkt.push(flags);
    // 31-bit Stream ID
    pkt.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());
    pkt.extend_from_slice(payload_bytes);
    pkt
}
