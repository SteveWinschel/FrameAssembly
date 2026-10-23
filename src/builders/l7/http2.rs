//! HTTP2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9113 HTTP/2 connection preface or binary frame.
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
