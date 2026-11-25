//! DNS over HTTPS (`doh`, RFC 8484) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for cleartext RFC 8484 DNS over HTTPS
//! (`doh`) HTTP/1.1 requests and responses carried over TCP or SCTP ports `80` and `443` (as
//! well as dynamic HTTP `application/dns-message` traffic). It decodes `POST /dns-query` bodies,
//! unpadded `base64url` `GET /dns-query?dns=...` queries, and `HTTP/1.1 <status> <reason>`
//! `application/dns-message` responses while reusing FrameAssembly's cycle-hardened DNS parser.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{be_u16, ProtocolDissection, sd};

use super::dns::dissect_dns_or_mdns;
use super::{push_str_mod, split_crlf_headers};

/// Default HTTP `User-Agent` synthesized when `useragent` is omitted in `.frasm`.
const DEFAULT_DOH_USER_AGENT: &str = concat!("FrameAssembly/", env!("CARGO_PKG_VERSION"));

/// Returns `true` when `(src_port, dst_port)` identifies a DoH server endpoint.
fn is_doh_server_src(src_port: u16, dst_port: u16) -> bool {
    let web_port = |p: u16| matches!(p, 80 | 443 | 8080 | 8443);
    (web_port(src_port) && !web_port(dst_port)) || (src_port < 1024 && dst_port >= 1024)
}

/// Decodes an unpadded RFC 4648 §5 Base64url string into raw octets.
fn decode_base64url_nopad(s: &str) -> Option<Vec<u8>> {
    let bytes = s.trim_end_matches('=').as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let val_of = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let n = (val_of(bytes[i])? << 18)
            | (val_of(bytes[i + 1])? << 12)
            | (val_of(bytes[i + 2])? << 6)
            | val_of(bytes[i + 3])?;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    match bytes.len() - i {
        2 => {
            let n = (val_of(bytes[i])? << 18) | (val_of(bytes[i + 1])? << 12);
            out.push((n >> 16) as u8);
        }
        3 => {
            let n = (val_of(bytes[i])? << 18)
                | (val_of(bytes[i + 1])? << 12)
                | (val_of(bytes[i + 2])? << 6);
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
        }
        0 => {}
        _ => return None,
    }
    Some(out)
}

/// Computes the expected default `Host` header string for `(dst_ip, dst_port)`.
fn default_host_for_dst(dst_ip: Option<IpAddr>, dst_port: u16) -> Option<String> {
    let ip = dst_ip?;
    let base = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    if dst_port != 80 && dst_port != 0 {
        Some(format!("{base}:{dst_port}"))
    } else {
        Some(base)
    }
}

/// Checks whether a header value declares the `application/dns-message` media type.
fn is_dns_message_mime(val: &str) -> bool {
    let media = val.split(';').next().unwrap_or(val).trim();
    media.eq_ignore_ascii_case("application/dns-message")
}

/// Translates `dissect_dns_or_mdns` tokens (`"dns query ..."` / `"dns response ..."`) into DoH modifiers
/// with DoH's RFC 8484 default `txid == 0` elision.
fn append_doh_dns_modifiers(
    tokens: &mut String,
    dns_body: &[u8],
    is_response_http: bool,
    omit_direction_kw: bool,
) -> Option<()> {
    let dis = dissect_dns_or_mdns(dns_body, false, false)?;
    if !dis.residual_payload.is_empty() {
        return None;
    }
    let body_tokens = dis.tokens.strip_prefix("dns ")?;
    let (dir_kw, rest) = match body_tokens.split_once(' ') {
        Some((d, r)) => (d, r),
        None => (body_tokens, ""),
    };
    let wire_txid = be_u16(dns_body, 0);

    if !omit_direction_kw {
        let emit_dir = match (is_response_http, dir_kw) {
            (true, "response") => "response",
            (false, "query") => "query",
            (_, other) => other,
        };
        if !(emit_dir == "query" && rest.is_empty() && wire_txid == 0) {
            let _ = write!(tokens, " {emit_dir}");
        }
    }

    if wire_txid == 0x0000 {
        let cleaned = rest
            .strip_prefix("txid 0x0000 ")
            .or_else(|| rest.strip_prefix("txid 0x0000"))
            .unwrap_or(rest);
        if !cleaned.is_empty() {
            let _ = write!(tokens, " {cleaned}");
        }
    } else if wire_txid == 0x1234 {
        tokens.push_str(" txid 0x1234");
        if !rest.is_empty() {
            let _ = write!(tokens, " {rest}");
        }
    } else if !rest.is_empty() {
        let _ = write!(tokens, " {rest}");
    }
    Some(())
}

/// Dissects a cleartext RFC 8484 DNS over HTTPS HTTP/1.1 request or response on TCP/SCTP ports `80` or `443`.
pub(crate) fn dissect_doh(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    let (hdr_str, body_bytes) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;
    let server_src = is_doh_server_src(src_port, dst_port);

    if let Some(after_http) = first_line.strip_prefix("HTTP/1.1 ") {
        let (status_str, reason) = after_http.split_once(' ')?;
        let status: u16 = status_str.parse().ok()?;
        let mut content_type_ok = false;
        let mut content_len: Option<usize> = None;

        for hline in lines {
            let (k, v) = hline.split_once(": ")?;
            if k.eq_ignore_ascii_case("Content-Type") {
                if !is_dns_message_mime(v) {
                    return None;
                }
                content_type_ok = true;
            } else if k.eq_ignore_ascii_case("Content-Length") {
                content_len = Some(v.parse::<usize>().ok()?);
            } else {
                return None;
            }
        }
        if !content_type_ok {
            return None;
        }
        let body_len = content_len.unwrap_or(body_bytes.len());
        let dns_body = body_bytes.get(..body_len)?;
        let trailing = body_bytes.get(body_len..)?.to_vec();

        let mut tokens = String::from("doh");
        if status != 200 {
            let _ = write!(tokens, " status {status}");
            if reason != "OK" {
                push_str_mod(&mut tokens, "reason", reason);
            }
        } else if reason != "OK" {
            let _ = write!(tokens, " status {status}");
            push_str_mod(&mut tokens, "reason", reason);
        }

        if dns_body.is_empty() {
            if status < 400 {
                return None;
            }
            return Some(sd(Protocol::Doh, tokens, trailing));
        }

        let is_qr1 = dns_body.len() >= 12 && (be_u16(dns_body, 2) & 0x8000) != 0;
        let omit_dir = status == 200 && reason == "OK" && server_src && is_qr1;
        if status == 200 && reason == "OK" && !is_qr1 {
            tokens.push_str(" status 200");
        }
        let mut dns_mods = String::new();
        append_doh_dns_modifiers(&mut dns_mods, dns_body, true, omit_dir)?;
        tokens.push_str(&dns_mods);
        return Some(sd(Protocol::Doh, tokens, trailing));
    }

    let (method, rest) = first_line.split_once(' ')?;
    let (raw_uri, http_ver) = rest.split_once(' ')?;
    if http_ver != "HTTP/1.1" {
        return None;
    }

    let mut host_hdr: Option<&str> = None;
    let mut user_agent: Option<&str> = None;
    let mut has_accept_dns = false;
    let mut has_ct_dns = false;
    let mut content_len: Option<usize> = None;

    for hline in lines {
        let (k, v) = hline.split_once(": ")?;
        if k.eq_ignore_ascii_case("Host") {
            host_hdr = Some(v);
        } else if k.eq_ignore_ascii_case("User-Agent") {
            user_agent = Some(v);
        } else if k.eq_ignore_ascii_case("Accept") {
            if is_dns_message_mime(v) {
                has_accept_dns = true;
            }
        } else if k.eq_ignore_ascii_case("Content-Type") {
            if !is_dns_message_mime(v) {
                return None;
            }
            has_ct_dns = true;
        } else if k.eq_ignore_ascii_case("Content-Length") {
            content_len = Some(v.parse::<usize>().ok()?);
        } else {
            return None;
        }
    }

    let host_val = host_hdr?;
    let expected_default_host = default_host_for_dst(dst_ip, dst_port);
    let emit_host = expected_default_host.as_deref() != Some(host_val);
    let emit_ua = user_agent.is_some_and(|ua| ua != DEFAULT_DOH_USER_AGENT);

    let mut tokens = String::from("doh");
    let (dns_wire_owned, uri_for_tokens, trailing) = if method == "GET" {
        if !has_accept_dns {
            return None;
        }
        let (base_path, query) = raw_uri.split_once('?')?;
        let mut dns_param: Option<&str> = None;
        let mut extra_params: Vec<&str> = Vec::new();
        for kv in query.split('&') {
            if let Some(val) = kv.strip_prefix("dns=") {
                dns_param = Some(val);
            } else if !kv.is_empty() {
                extra_params.push(kv);
            }
        }
        let b64 = dns_param?;
        let decoded = decode_base64url_nopad(b64)?;
        let rebuilt_uri = if extra_params.is_empty() {
            base_path.to_string()
        } else {
            format!("{base_path}?{}", extra_params.join("&"))
        };
        tokens.push_str(" get");
        (decoded, rebuilt_uri, body_bytes.to_vec())
    } else {
        if !has_ct_dns {
            return None;
        }
        if method != "POST" {
            push_str_mod(&mut tokens, "method", method);
        }
        let blen = content_len.unwrap_or(body_bytes.len());
        let dns_slice = body_bytes.get(..blen)?.to_vec();
        let rem = body_bytes.get(blen..)?.to_vec();
        (dns_slice, raw_uri.to_string(), rem)
    };

    if uri_for_tokens != "/dns-query" {
        push_str_mod(&mut tokens, "uri", &uri_for_tokens);
    }
    if emit_host {
        push_str_mod(&mut tokens, "hosthdr", host_val);
    }
    if emit_ua && let Some(ua) = user_agent {
        push_str_mod(&mut tokens, "useragent", ua);
    }

    let mut dns_mods = String::new();
    append_doh_dns_modifiers(&mut dns_mods, &dns_wire_owned, false, false)?;
    let dns_clean = dns_mods.trim();
    if dns_clean == "query" {
        let bare_would_emit_response = server_src
            && method == "POST"
            && uri_for_tokens == "/dns-query"
            && !emit_host
            && !emit_ua;
        if bare_would_emit_response {
            tokens.push_str(" query");
        }
    } else if let Some(after_q) = dns_clean.strip_prefix("query ") {
        let _ = write!(tokens, " {after_q}");
    } else if !dns_clean.is_empty() {
        let _ = write!(tokens, " {dns_clean}");
    }

    Some(sd(Protocol::Doh, tokens, trailing))
}
