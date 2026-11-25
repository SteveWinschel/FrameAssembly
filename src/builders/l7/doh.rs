//! DNS over HTTPS (DoH, RFC 8484) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic cleartext RFC 8484 DNS over HTTPS (`doh`) requests
//! and responses over TCP port 80. Requests wrap a binary RFC 1035 / RFC 6891 DNS message
//! (defaulting to Transaction ID `0` per RFC 8484 §4.1) inside `POST /dns-query HTTP/1.1` with
//! `Accept: application/dns-message`, `Content-Type: application/dns-message`, and
//! `Content-Length` headers (or unpadded `base64url` `?dns=` for `GET`). Responses emit
//! `HTTP/1.1 200 OK` with `Content-Type: application/dns-message` and the binary DNS answer.
//!
//! Canonical `.frasm` syntax:
//! `a -> b doh [query | response] [get | post | method <str>] [uri <str>] [hosthdr <str>] [useragent <str>] [status <u16>] [reason <str>] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>]... [rcode <u8>] [ansttl <u32>] [edns0] [udpsize <u16>] [dobit]`

use super::dns::build_dns_or_mdns_payload;
use crate::ast::*;
use crate::builders::WireContext;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Base64url alphabet (RFC 4648 §5, unpadded for RFC 8484 §4.1.1 GET requests).
const B64URL_ALPHA: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `input` as an unpadded RFC 4648 §5 Base64url string.
fn encode_base64url_nopad(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16)
            | ((input[i + 1] as u32) << 8)
            | (input[i + 2] as u32);
        out.push(B64URL_ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHA[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHA[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64URL_ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHA[((n >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64URL_ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHA[((n >> 6) & 0x3F) as usize] as char);
    }
    out
}

/// Returns `true` when the resolved source port identifies a DoH server endpoint.
fn is_doh_server_src(ctx: &WireContext) -> bool {
    let web_port = |p: u16| matches!(p, 80 | 443 | 8080 | 8443);
    (web_port(ctx.src_port) && !web_port(ctx.dst_port))
        || (ctx.src_port < 1024 && ctx.dst_port >= 1024)
}

/// Formats an HTTP `Host` header value from `host_hdr` or destination IP and port.
fn format_doh_host(ctx: &WireContext, host_hdr: Option<&str>) -> String {
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

/// Builds a cleartext RFC 8484 DNS over HTTPS HTTP/1.1 request or response payload.
///
/// Syntax mapping: `doh [query | response] [get | post | method <str>] [uri <str>] [hosthdr <str>] [useragent <str>] [status <u16>] [reason <str>] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>]... [rcode <u8>] [ansttl <u32>] [edns0] [udpsize <u16>] [dobit]`
#[doc(alias = "DOH")]
#[doc(alias = "RFC8484")]
pub fn build_doh_payload(
    ctx: &WireContext,
    spec: &DohSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let has_dns_answers = spec.rdata.is_some() || !spec.rdata_list.is_empty();
    let is_server_bare = is_doh_server_src(ctx)
        && !spec.is_query
        && spec.method.is_none()
        && spec.uri.is_none()
        && spec.host_hdr.is_none()
        && spec.user_agent.is_none();
    let is_resp = (spec.is_response && !spec.is_query)
        || spec.status.is_some()
        || (has_dns_answers && !spec.is_query)
        || is_server_bare;

    let dns_spec = DnsSpec {
        is_query: spec.is_query,
        is_response: is_resp && !spec.is_query,
        txid: Some(spec.txid.unwrap_or(0)),
        qname: spec.qname,
        qtype: spec.qtype,
        rdata: spec.rdata,
        rcode: spec.rcode,
        ans_ttl: spec.ans_ttl,
        edns0: spec.edns0,
        udp_size: spec.udp_size,
        do_bit: spec.do_bit,
        rdata_list: spec.rdata_list.clone(),
    };

    let mut hdr = String::new();
    if is_resp {
        let status = spec.status.unwrap_or(200);
        let reason = spec.reason.unwrap_or("OK");
        let has_explicit_dns = spec.is_response
            || spec.qname.is_some()
            || spec.qtype.is_some()
            || spec.rdata.is_some()
            || !spec.rdata_list.is_empty()
            || spec.rcode.is_some()
            || spec.ans_ttl.is_some()
            || spec.txid.is_some()
            || spec.edns0
            || spec.udp_size.is_some()
            || spec.do_bit;
        let dns_body = if status >= 400 && !has_explicit_dns {
            Vec::new()
        } else {
            build_dns_or_mdns_payload(ctx, &dns_spec, &[], false, false)
        };
        hdr.push_str(&format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            dns_body.len()
        ));
        let mut out = hdr.into_bytes();
        out.extend_from_slice(&dns_body);
        if !payload_bytes.is_empty() {
            out.extend_from_slice(payload_bytes);
        }
        return out;
    }

    let method = spec.method.unwrap_or("POST").to_ascii_uppercase();
    let uri = spec.uri.unwrap_or("/dns-query");
    let host = format_doh_host(ctx, spec.host_hdr);
    let ua = spec.user_agent.unwrap_or(concat!(
        "FrameAssembly/",
        env!("CARGO_PKG_VERSION")
    ));
    let dns_body = build_dns_or_mdns_payload(ctx, &dns_spec, &[], false, false);

    if method == "GET" {
        let b64 = encode_base64url_nopad(&dns_body);
        let sep = if uri.contains('?') { "&" } else { "?" };
        hdr.push_str(&format!(
            "GET {uri}{sep}dns={b64} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: application/dns-message\r\n\r\n"
        ));
        let mut out = hdr.into_bytes();
        if !payload_bytes.is_empty() {
            out.extend_from_slice(payload_bytes);
        }
        out
    } else {
        hdr.push_str(&format!(
            "{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            dns_body.len()
        ));
        let mut out = hdr.into_bytes();
        out.extend_from_slice(&dns_body);
        if !payload_bytes.is_empty() {
            out.extend_from_slice(payload_bytes);
        }
        out
    }
}
