//! Hypertext Transfer Protocol (HTTP/1.1) (RFC 9110 (HTTP Semantics) / RFC 9112 (HTTP/1.1)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Hypertext Transfer Protocol (HTTP/1.1) frames over TCP port 80 (HTTP) or custom ports (8080, 8000, 8443).
//! The wire encoder constructs a CRLF-delimited text message starting with a Request-Line (`<METHOD> <URI> HTTP/<VERSION>\r\n`) or Status-Line (`HTTP/<VERSION> <STATUS> <REASON>\r\n`), followed by `Host:`, `User-Agent:`, `Content-Type:`, `Content-Length:`, and custom `Header: Value\r\n` fields, an empty line (`\r\n`), and an optional entity body. When optional fields in [`HttpSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b http [method <str>] [uri <str>] [version <str>] [hosthdr <str>] [useragent <str>] [contenttype <str>] [status <u16>] [reason <str>] [header <key> <val>] [body <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Formats a `Host` header value, bracketing bare IPv6 literals and appending `:port` when non-80.
fn format_http_host(ctx: &WireContext, host_hdr: Option<&str>) -> String {
    if let Some(h) = host_hdr {
        if !h.starts_with('[') && h.parse::<core::net::Ipv6Addr>().is_ok() {
            return format!("[{h}]");
        }
        return h.to_string();
    }
    let base = match ctx.dst_ip {
        core::net::IpAddr::V4(v4) => v4.to_string(),
        core::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    if ctx.dst_port != 80 && ctx.dst_port != 0 {
        format!("{base}:{}", ctx.dst_port)
    } else {
        base
    }
}

/// Appends custom HTTP headers and finalizes `Content-Length` + body/payload bytes.
fn finalize_http_message(
    mut out: String,
    headers: &[(&str, &str)],
    body: Option<&str>,
    payload_bytes: &[u8],
    omit_zero_content_length: bool,
    forbid_content_length: bool,
) -> Vec<u8> {
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }

    let body_slice = body.map(str::as_bytes).unwrap_or(&[]);
    let total_len = body_slice.len() + payload_bytes.len();
    let has_cl_header = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Content-Length"));

    if !forbid_content_length
        && !has_cl_header
        && (total_len > 0 || !omit_zero_content_length)
    {
        out.push_str(&format!("Content-Length: {total_len}\r\n"));
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    if !body_slice.is_empty() {
        bytes.extend_from_slice(body_slice);
    }
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}

/// Builds an RFC 9110 HTTP/1.1 request or response payload.
/// Syntax mapping: `http [method <str>] [uri <str>] [version <str>] [hosthdr <str>] [useragent <str>] [contenttype <str>] [status <u16>] [reason <str>] [header <key> <val>] [body <str>]`
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
        out.push_str(&format!("HTTP/{version} {status} {reason}\r\n"));
        if let Some(ct) = spec.content_type {
            out.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        let forbid_cl = (100..=199).contains(&status) || status == 204 || status == 304;
        finalize_http_message(
            out,
            &spec.headers,
            spec.body,
            payload_bytes,
            forbid_cl,
            forbid_cl,
        )
    } else {
        let method = spec.method.unwrap_or("GET");
        let uri = spec.uri.unwrap_or("/");
        let host = format_http_host(ctx, spec.host_hdr);

        out.push_str(&format!("{method} {uri} HTTP/{version}\r\nHost: {host}\r\n"));
        let has_ua_header = spec
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("User-Agent"));
        if let Some(ua) = spec.user_agent {
            out.push_str(&format!("User-Agent: {ua}\r\n"));
        } else if !has_ua_header {
            out.push_str(concat!(
                "User-Agent: FrameAssembly/",
                env!("CARGO_PKG_VERSION"),
                "\r\n"
            ));
        }
        if let Some(ct) = spec.content_type {
            out.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        let method_upper = method.to_ascii_uppercase();
        let omit_zero_cl = matches!(method_upper.as_str(), "GET" | "HEAD" | "DELETE");
        finalize_http_message(
            out,
            &spec.headers,
            spec.body,
            payload_bytes,
            omit_zero_cl,
            false,
        )
    }
}
