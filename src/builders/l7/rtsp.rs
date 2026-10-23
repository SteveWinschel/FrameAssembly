//! RTSP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 7826 RTSP streaming control message.
pub fn build_rtsp_payload(
    _ctx: &WireContext,
    spec: &RtspSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cseq = spec.cseq.unwrap_or(1);
    let mut out = String::new();

    if let Some(status) = spec.status {
        out.push_str(&format!("RTSP/1.0 {} OK\r\nCSeq: {}\r\n\r\n", status, cseq));
    } else {
        let method = spec.method.unwrap_or("OPTIONS");
        let uri = spec.uri.unwrap_or("rtsp://localhost/live");
        out.push_str(&format!("{} {} RTSP/1.0\r\nCSeq: {}\r\n", method, uri, cseq));
        if let Some(sess) = spec.session {
            out.push_str(&format!("Session: {}\r\n", sess));
        }
        if let Some(trans) = spec.transport_hdr {
            out.push_str(&format!("Transport: {}\r\n", trans));
        }
        out.push_str("\r\n");
    }

    let mut bytes = out.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
