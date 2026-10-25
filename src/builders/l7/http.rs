//! Hypertext Transfer Protocol (HTTP/1.1) (RFC 9110 (HTTP Semantics) / RFC 9112 (HTTP/1.1)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Hypertext Transfer Protocol (HTTP/1.1) frames over TCP port 80 (HTTP) or custom ports (8080, 8000, 8443).
//! The wire encoder constructs a CRLF-delimited text message starting with a Request-Line (`<METHOD> <URI> HTTP/<VERSION>\r\n`) or Status-Line (`HTTP/<VERSION> <STATUS> <REASON>\r\n`), followed by `Host:`, `User-Agent:`, `Content-Type:`, `Content-Length:`, and custom `Header: Value\r\n` fields, an empty line (`\r\n`), and an optional entity body. When optional fields in [`HttpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b HTTP [METHOD <str>] [URI <str>] [VERSION <str>] [HOST_HDR <str>] [USER_AGENT <str>] [CONTENT_TYPE <str>] [STATUS <u16>] [REASON <str>] [HEADER <key> <val>] [BODY <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9110 HTTP/1.1 request or response payload.
/// Syntax mapping: `HTTP [METHOD <str>] [URI <str>] [VERSION <str>] [HOST_HDR <str>] [USER_AGENT <str>] [CONTENT_TYPE <str>] [STATUS <u16>] [REASON <str>] [HEADER <key> <val>] [BODY <str>]`
#[doc(alias = "HTTP")]
#[doc(alias = "HTTP11")]
#[doc(alias = "RFC9110")]
#[doc(alias = "RFC9112")]
#[doc(alias = "USER_AGENT")]
pub fn build_http_payload(
    ctx: &WireContext,
    spec: &HttpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut out = String::new();
    let version = spec.version.unwrap_or("1.1");

    if let Some(status) = spec.status {
        let reason = spec.reason.unwrap_or("OK");
        out.push_str(&format!("HTTP/{} {} {}\r\n", version, status, reason));
        if let Some(ct) = spec.content_type {
            out.push_str(&format!("Content-Type: {}\r\n", ct));
        }
        for (k, v) in &spec.headers {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }
        if let Some(body) = spec.body {
            out.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        } else if !payload_bytes.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n\r\n", payload_bytes.len()));
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(payload_bytes);
            return bytes;
        } else {
            out.push_str("Content-Length: 0\r\n\r\n");
        }
    } else {
        let method = spec.method.unwrap_or("GET");
        let uri = spec.uri.unwrap_or("/");
        let host = spec.host_hdr.map(|h| h.to_string()).unwrap_or_else(|| ctx.dst_ip.to_string());

        out.push_str(&format!("{} {} HTTP/{}\r\nHost: {}\r\n", method, uri, version, host));
        if let Some(ua) = spec.user_agent {
            out.push_str(&format!("User-Agent: {}\r\n", ua));
        }
        if let Some(ct) = spec.content_type {
            out.push_str(&format!("Content-Type: {}\r\n", ct));
        }
        for (k, v) in &spec.headers {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }
        if let Some(body) = spec.body {
            out.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        } else if !payload_bytes.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n\r\n", payload_bytes.len()));
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(payload_bytes);
            return bytes;
        } else {
            out.push_str("\r\n");
        }
    }

    out.into_bytes()
}
