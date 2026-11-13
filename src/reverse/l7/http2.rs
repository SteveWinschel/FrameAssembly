//! HTTP/2 (`http2`, RFC 9113) Layer 7 binary framing PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 9113 HTTP/2 connection preface
//! strings (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and 9-byte binary frame headers carried over TCP
//! ports `80`, `443`, `8080`, and `8443`. It validates the 24-bit big-endian payload length against
//! the enclosing TCP segment, decodes canonical frame types (`preface`, `data`, `headers`,
//! `settings`, `ping`, `goaway`, `windowupdate`) and 31-bit stream identifiers (`streamid`), and
//! preserves frame payload bytes via residual payload or returns `None` to step down cleanly.

use alloc::format;
use alloc::string::ToString;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::checked_be_u32;

/// HTTP/2 client connection preface string (RFC 9113 §3.4).
pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Dissects an RFC 9113 HTTP/2 connection preface or 9-byte frame header.
pub(crate) fn dissect_http2(payload: &[u8]) -> Option<ProtocolDissection> {
    if let Some(rest) = payload.strip_prefix(H2_PREFACE) {
        return Some(sd(
            Protocol::Http2,
            "http2 preface".to_string(),
            rest.to_vec(),
        ));
    }
    if payload.len() < 9 {
        return None;
    }
    let len = ((payload[0] as usize) << 16) | ((payload[1] as usize) << 8) | (payload[2] as usize);
    if 9usize.checked_add(len)? != payload.len() {
        return None;
    }
    let type_kw = match payload[3] {
        0 => "data",
        1 => "headers",
        4 => "settings",
        6 => "ping",
        7 => "goaway",
        8 => "windowupdate",
        _ => return None,
    };
    let stream_id = checked_be_u32(payload, 5)? & 0x7FFFFFFF;
    let mut tokens = format!("http2 {type_kw}");
    if stream_id != 0 {
        let _ = write!(tokens, " streamid {stream_id}");
    }
    Some(sd(Protocol::Http2, tokens, payload.get(9..)?.to_vec()))
}
