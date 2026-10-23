//! HTTP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9110 HTTP/1.1 request or response payload.
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
