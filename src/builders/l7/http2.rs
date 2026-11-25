//! Hypertext Transfer Protocol Version 2 (HTTP/2) (RFC 9113 (HTTP/2) / RFC 7541 (HPACK)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Hypertext Transfer Protocol Version 2 (HTTP/2) frames over TCP port 443 (h2 over TLS) or TCP port 80 (h2c cleartext).
//! The wire encoder constructs a 24-octet client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and 9-octet binary frame headers containing 24-bit payload Length, 8-bit Frame Type (`0x0` DATA, `0x1` HEADERS with RFC 7541 HPACK header blocks, `0x4` SETTINGS, `0x6` PING, `0x7` GOAWAY, `0x8` WINDOW_UPDATE), 8-bit Flags (`END_STREAM = 0x1`, `END_HEADERS = 0x4`, `ACK = 0x1`), 1-bit Reserved flag, and 31-bit Stream Identifier. When optional fields in [`Http2Spec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b http2 [preface | settings | headers | data | windowupdate | ping | goaway] [streamid <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Formats an IP address and port into an HTTP `:authority` / `Host` value, bracketing IPv6 literals.
pub(crate) fn format_authority(ip: IpAddr, port: u16, is_tls: bool) -> String {
    let default_port = if is_tls { 443 } else { 80 };
    let host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    };
    if port == default_port || port == 0 {
        host
    } else {
        format!("{}:{}", host, port)
    }
}

/// Appends an RFC 9113 HTTP/2 9-byte frame header and its payload to `out`.
pub(crate) fn push_http2_frame(
    out: &mut Vec<u8>,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    body: &[u8],
) {
    let length = body.len().min(0x00FF_FFFF) as u32;
    out.reserve(9 + length as usize);
    out.push((length >> 16) as u8);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(&body[..length as usize]);
}

/// Encodes an RFC 7541 §5.1 variable-length HPACK integer.
fn encode_hpack_int(out: &mut Vec<u8>, prefix_mask: u8, prefix_bits: u8, value: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if value < max_prefix {
        out.push(prefix_mask | (value as u8));
        return;
    }
    out.push(prefix_mask | (max_prefix as u8));
    let mut rem = value - max_prefix;
    while rem >= 128 {
        out.push((rem as u8 & 0x7F) | 0x80);
        rem >>= 7;
    }
    out.push(rem as u8);
}

/// Encodes an RFC 7541 §5.2 uncompressed (`H = 0`) HPACK string literal.
fn encode_hpack_str(out: &mut Vec<u8>, s: &[u8]) {
    encode_hpack_int(out, 0x00, 7, s.len());
    out.extend_from_slice(s);
}

/// Returns the RFC 7541 Appendix A static table index for an exact `(name, value)` pair.
fn static_exact_index(name_lower: &str, value: &str) -> Option<usize> {
    match (name_lower, value) {
        (":method", "GET") => Some(2),
        (":method", "POST") => Some(3),
        (":path", "/") => Some(4),
        (":path", "/index.html") => Some(5),
        (":scheme", "http") => Some(6),
        (":scheme", "https") => Some(7),
        (":status", "200") => Some(8),
        (":status", "204") => Some(9),
        (":status", "206") => Some(10),
        (":status", "304") => Some(11),
        (":status", "400") => Some(12),
        (":status", "404") => Some(13),
        (":status", "500") => Some(14),
        ("accept-encoding", "gzip, deflate") => Some(16),
        _ => None,
    }
}

/// Returns the RFC 7541 Appendix A static table index for a header field name.
fn static_name_index(name_lower: &str) -> Option<usize> {
    match name_lower {
        ":authority" => Some(1),
        ":method" => Some(2),
        ":path" => Some(4),
        ":scheme" => Some(6),
        ":status" => Some(8),
        "accept" => Some(19),
        "authorization" => Some(23),
        "content-length" => Some(28),
        "content-type" => Some(31),
        "host" => Some(38),
        "server" => Some(54),
        "user-agent" => Some(58),
        _ => None,
    }
}

/// Encodes a slice of `(name, value)` HTTP headers into an RFC 7541 HPACK header block.
pub(crate) fn encode_hpack_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        let name_lower = name.to_ascii_lowercase();
        if let Some(idx) = static_exact_index(&name_lower, value) {
            encode_hpack_int(&mut out, 0x80, 7, idx);
        } else if let Some(name_idx) = static_name_index(&name_lower) {
            encode_hpack_int(&mut out, 0x00, 4, name_idx);
            encode_hpack_str(&mut out, value.as_bytes());
        } else {
            out.push(0x00);
            encode_hpack_str(&mut out, name_lower.as_bytes());
            encode_hpack_str(&mut out, value.as_bytes());
        }
    }
    out
}

/// Parses textual HTTP/2 header lines (`key: value` or `:pseudo value`) into HPACK bytes when all non-empty lines are valid headers.
fn parse_text_hpack_headers(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(bytes).ok()?;
    let mut pairs: Vec<(String, String)> = Vec::new();
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let search_start = usize::from(trimmed.starts_with(':'));
        let (name, val) = if let Some(rel) = trimmed[search_start..].find(':') {
            let split_at = search_start + rel;
            (trimmed[..split_at].trim_end(), trimmed[split_at + 1..].trim())
        } else if trimmed.starts_with(':') {
            let (n, v) = trimmed.split_once(|c: char| c.is_ascii_whitespace())?;
            (n, v.trim())
        } else {
            return None;
        };
        if name.len() <= search_start {
            return None;
        }
        if !name[search_start..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        pairs.push((name.to_string(), val.to_string()));
    }
    if pairs.is_empty() {
        return None;
    }
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Some(encode_hpack_headers(&refs))
}

/// Returns `true` when the HTTP/2 packet originates from the server side of the connection.
fn is_http2_server_src(ctx: &WireContext) -> bool {
    let web_port = |p: u16| matches!(p, 80 | 443 | 8080 | 8443);
    (web_port(ctx.src_port) && !web_port(ctx.dst_port))
        || (ctx.src_port < 1024 && ctx.dst_port >= 1024)
}

/// Builds an RFC 9113 HTTP/2 connection preface or binary frame.
/// Syntax mapping: `http2 [preface | settings | headers | data | windowupdate | ping | goaway] [streamid <u32>]`
#[doc(alias = "HTTP2")]
#[doc(alias = "H2")]
#[doc(alias = "RFC9113")]
#[doc(alias = "RFC7540")]
#[doc(alias = "STREAM_ID")]
pub fn build_http2_payload(
    ctx: &WireContext,
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

    let hpack_body: Option<Vec<u8>> = if spec.is_headers {
        if !payload_bytes.is_empty() {
            parse_text_hpack_headers(payload_bytes)
        } else if is_http2_server_src(ctx) {
            Some(encode_hpack_headers(&[(":status", "200")]))
        } else {
            let is_tls = ctx.dst_port == 443 || ctx.dst_port == 8443;
            let scheme = if is_tls { "https" } else { "http" };
            let authority = format_authority(ctx.dst_ip, ctx.dst_port, is_tls);
            Some(encode_hpack_headers(&[
                (":method", "GET"),
                (":path", "/"),
                (":scheme", scheme),
                (":authority", &authority),
            ]))
        }
    } else {
        None
    };

    let default_body: &[u8] = if let Some(ref encoded) = hpack_body {
        encoded.as_slice()
    } else if !payload_bytes.is_empty() {
        payload_bytes
    } else if spec.is_ping || spec.is_goaway {
        &[0u8; 8]
    } else if spec.is_window_update {
        &[0, 0, 0, 1]
    } else {
        &[]
    };

    let default_stream = if spec.is_headers || spec.is_data { 1 } else { 0 };
    let stream_id = spec.stream_id.unwrap_or(default_stream);

    let mut pkt = Vec::new();
    push_http2_frame(&mut pkt, frame_type, flags, stream_id, default_body);
    pkt
}
