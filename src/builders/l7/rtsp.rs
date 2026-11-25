//! Real-Time Streaming Protocol (RTSP) (RFC 7826 (RTSP 2.0) / RFC 2326 (RTSP 1.0)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Real-Time Streaming Protocol (RTSP) frames over TCP port 554 (and alternate port 8554).
//! The wire encoder constructs a CRLF-delimited text control protocol starting with a Request-Line (`<METHOD> <URI> RTSP/1.0\r\n` for `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `PAUSE`, `RECORD`, `ANNOUNCE`, `GET_PARAMETER`, `TEARDOWN`) or Status-Line (`RTSP/1.0 <STATUS> OK\r\n`), followed by `CSeq:`, `Transport:` (e.g. `RTP/AVP;unicast;client_port=5004-5005`), `Session:`, and `Content-Length:` headers. When optional fields in [`RtspSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b rtsp [options | method <str>] [uri <str>] [status <u16>] [cseq <u32>] [transporthdr <str>] [session <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 7826 RTSP streaming control message.
/// Syntax mapping: `rtsp [options | method <str>] [uri <str>] [status <u16>] [cseq <u32>] [transporthdr <str>] [session <str>]`
#[doc(alias = "RTSP")]
#[doc(alias = "RFC7826")]
#[doc(alias = "RFC2326")]
#[doc(alias = "TRANSPORT_HDR")]
pub fn build_rtsp_payload(
    _ctx: &WireContext,
    spec: &RtspSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cseq = spec.cseq.unwrap_or(1);
    let mut out = String::new();

    if let Some(status) = spec.status {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            454 => "Session Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };
        out.push_str(&format!("RTSP/1.0 {status} {reason}\r\nCSeq: {cseq}\r\n"));
        if let Some(sess) = spec.session {
            out.push_str(&format!("Session: {sess}\r\n"));
        }
        if let Some(trans) = spec.transport_hdr {
            out.push_str(&format!("Transport: {trans}\r\n"));
        }
    } else {
        let method = spec.method.unwrap_or("OPTIONS");
        let uri = spec.uri.unwrap_or("rtsp://localhost/live");
        out.push_str(&format!("{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n"));
        if let Some(sess) = spec.session {
            out.push_str(&format!("Session: {sess}\r\n"));
        }
        if let Some(trans) = spec.transport_hdr {
            out.push_str(&format!("Transport: {trans}\r\n"));
        } else if method.eq_ignore_ascii_case("SETUP") {
            out.push_str("Transport: RTP/AVP;unicast;client_port=8000-8001\r\n");
        }
    }

    if !payload_bytes.is_empty() {
        out.push_str(&format!("Content-Length: {}\r\n\r\n", payload_bytes.len()));
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(payload_bytes);
        bytes
    } else {
        out.push_str("\r\n");
        out.into_bytes()
    }
}
