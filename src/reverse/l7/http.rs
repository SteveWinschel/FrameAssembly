//! Hypertext Transfer Protocol (`HTTP`, RFC 9110 / RFC 9112) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 9110 and RFC 9112 HTTP/1.x
//! request and response frames carried over TCP ports `80`, `8080`, `8000`, `443`, `8443`, and
//! `6443`, or identified dynamically via CRLF request/response line signatures. It decodes HTTP
//! request methods (`get`, `post`, `put`, `delete`, `head`, `options`, `patch`, or arbitrary
//! `method`), target `uri`, protocol `version`, numeric `status`, `reason` phrase, `host_hdr`,
//! `user_agent`, `content_type`, custom `header` pairs, and UTF-8 `body` or binary residual
//! payloads while omitting redundant `Content-Length` headers that match the body byte length.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{attach_text_body, first_crlf_line, push_str_mod, quote_web_str, split_crlf_headers};

/// Checks whether `payload` begins with an HTTP/1.x or HTTP/2.x request or response line.
pub(crate) fn is_http_signature(payload: &[u8]) -> bool {
    let Some(line) = first_crlf_line(payload) else {
        return false;
    };
    if line.starts_with("HTTP/1.") || line.starts_with("HTTP/2.") {
        return true;
    }
    !line.starts_with("M-SEARCH ")
        && !line.starts_with("NOTIFY ")
        && (line.contains(" HTTP/1.") || line.contains(" HTTP/2."))
}

/// Dissects an RFC 9110 / RFC 9112 HTTP/1.x request or response frame.
pub(crate) fn dissect_http(payload: &[u8]) -> Option<ProtocolDissection> {
    let (hdr_str, body_bytes) = split_crlf_headers(payload)?;
    let mut lines = hdr_str.split("\r\n");
    let first_line = lines.next()?;
    let header_lines: Vec<&str> = lines.collect();

    let mut tokens = String::from("http");

    if let Some(after_http) = first_line.strip_prefix("HTTP/") {
        let (version, status_and_reason) = after_http.split_once(' ')?;
        let (status_str, reason) = status_and_reason
            .split_once(' ')
            .unwrap_or((status_and_reason, ""));
        let status: u16 = status_str.parse().ok()?;

        if version != "1.1" {
            push_str_mod(&mut tokens, "version", version);
        }
        let _ = write!(tokens, " status {status}");
        if reason != "OK" {
            push_str_mod(&mut tokens, "reason", reason);
        }

        let (mut custom_started, mut content_type_used) = (false, false);
        for (idx, &hline) in header_lines.iter().enumerate() {
            let (k, v) = hline.split_once(": ")?;
            if idx + 1 == header_lines.len()
                && k == "Content-Length"
                && v.parse::<usize>().ok() == Some(body_bytes.len())
            {
                continue;
            }
            if !custom_started && !content_type_used && k == "Content-Type" {
                push_str_mod(&mut tokens, "content_type", v);
                content_type_used = true;
            } else {
                custom_started = true;
                let _ = write!(tokens, " header {} {}", quote_web_str(k), quote_web_str(v));
            }
        }
    } else {
        let (method, rest) = first_line.split_once(' ')?;
        let (uri, http_ver) = rest.split_once(' ')?;
        let version = http_ver.strip_prefix("HTTP/")?;

        if matches!(
            method,
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
        ) {
            let _ = write!(tokens, " {}", method.to_ascii_lowercase());
        } else {
            push_str_mod(&mut tokens, "method", method);
        }
        if uri != "/" {
            push_str_mod(&mut tokens, "uri", uri);
        }
        if version != "1.1" {
            push_str_mod(&mut tokens, "version", version);
        }

        let (mut host_seen, mut ua_seen, mut ct_seen, mut custom_started) =
            (false, false, false, false);
        for (idx, &hline) in header_lines.iter().enumerate() {
            let (k, v) = hline.split_once(": ")?;
            if idx + 1 == header_lines.len()
                && k == "Content-Length"
                && !body_bytes.is_empty()
                && v.parse::<usize>().ok() == Some(body_bytes.len())
            {
                continue;
            }
            if idx == 0 && !host_seen && k == "Host" {
                push_str_mod(&mut tokens, "host_hdr", v);
                host_seen = true;
            } else if !custom_started && !ct_seen && !ua_seen && k == "User-Agent" {
                push_str_mod(&mut tokens, "user_agent", v);
                ua_seen = true;
            } else if !custom_started && !ct_seen && k == "Content-Type" {
                push_str_mod(&mut tokens, "content_type", v);
                ct_seen = true;
            } else {
                custom_started = true;
                let _ = write!(tokens, " header {} {}", quote_web_str(k), quote_web_str(v));
            }
        }
    }

    let residual_payload = attach_text_body(&mut tokens, "body", body_bytes);
    Some(sd(Protocol::Http, tokens, residual_payload))
}
