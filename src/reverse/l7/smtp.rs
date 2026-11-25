//! Simple Mail Transfer Protocol (SMTP, RFC 5321) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `smtp` client commands and server
//! reply frames carried over TCP or SCTP ports `25`, `465`, `587`, and `2525`. It validates CRLF
//! line framing, decodes three-digit numeric status replies (`code`, `reply`), standard verbs
//! (`ehlo`, `helo`, `mailfrom` via `MAIL FROM:<...>`, `rcptto` via `RCPT TO:<...>`, `data`,
//! `quit`, and generic `cmd`/`param` pairs), and standalone or attached `\r\n.\r\n`-terminated
//! message `body` sections without inserting unwanted `EHLO localhost` prefixes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::is_valid_raw_string_body;

/// Finds the first `\r\n` sequence in `bytes` and returns `(line_str, remainder)`.
fn split_crlf_line(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let pos = bytes.windows(2).position(|w| w == b"\r\n")?;
    let line = core::str::from_utf8(&bytes[..pos]).ok()?;
    if !is_valid_raw_string_body(line) {
        return None;
    }
    Some((line, &bytes[pos + 2..]))
}

/// Parses an RFC 5321 envelope parameter (`:<addr>`) from `MAIL FROM:` or `RCPT TO:`.
fn parse_envelope_addr(raw: &str) -> Option<&str> {
    let inner = raw.strip_prefix('<')?.strip_suffix('>')?;
    is_valid_raw_string_body(inner).then_some(inner)
}

/// Dissects an `smtp` command, reply, or standalone message body over TCP/SCTP ports `25`/`465`/`587`/`2525`.
pub(crate) fn dissect_smtp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(matches!(dst_port, 25 | 465 | 587 | 2525)
            || matches!(src_port, 25 | 465 | 587 | 2525))
    {
        return None;
    }

    let explicit_transport =
        matches!(transport, TransportProto::Sctp).then_some(TransportProto::Sctp);

    let (line, rem) = split_crlf_line(payload)?;
    let has_attached_body = rem.ends_with(b"\r\n.\r\n");

    if (line.is_empty() || !has_attached_body)
        && let Some(full_body) = payload.strip_suffix(b"\r\n.\r\n")
        && let Ok(body_str) = core::str::from_utf8(full_body)
        && is_valid_raw_string_body(body_str)
    {
        return Some(ProtocolDissection {
            protocol: Protocol::Smtp,
            tokens: format!("smtp body \"{body_str}\""),
            residual_payload: Vec::new(),
            explicit_transport,
        });
    }

    if line.is_empty() {
        return None;
    }

    let mut tokens = String::from("smtp");

    if line.len() >= 3 && line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
        let code: u16 = line[..3].parse().ok()?;
        let reply = if line.len() == 3 {
            ""
        } else if line.as_bytes()[3] == b' ' {
            &line[4..]
        } else {
            return None;
        };
        if !is_valid_raw_string_body(reply) {
            return None;
        }
        tokens.push_str(&format!(" code {code}"));
        if reply != "OK" {
            tokens.push_str(&format!(" reply \"{reply}\""));
        }
    } else if line == "EHLO localhost" && !has_attached_body && rem.is_empty() {
        // Default client greeting with zero payload.
    } else if line == "QUIT" {
        tokens.push_str(" quit");
    } else if line == "DATA" {
        tokens.push_str(" data");
    } else if line == "EHLO" {
        tokens.push_str(" ehlo");
    } else if line == "HELO" {
        tokens.push_str(" helo");
    } else if let Some(dom) = line.strip_prefix("EHLO ") {
        if !is_valid_raw_string_body(dom) {
            return None;
        }
        tokens.push_str(&format!(" ehlo \"{dom}\""));
    } else if let Some(dom) = line.strip_prefix("HELO ") {
        if !is_valid_raw_string_body(dom) {
            return None;
        }
        tokens.push_str(&format!(" helo \"{dom}\""));
    } else if let Some(rest) = line.strip_prefix("MAIL FROM:") {
        let addr = parse_envelope_addr(rest)?;
        tokens.push_str(&format!(" mailfrom \"{addr}\""));
    } else if let Some(rest) = line.strip_prefix("RCPT TO:") {
        let addr = parse_envelope_addr(rest)?;
        tokens.push_str(&format!(" rcptto \"{addr}\""));
    } else if let Some((cmd, param)) = line.split_once(' ') {
        if cmd.is_empty()
            || !is_valid_raw_string_body(cmd)
            || !is_valid_raw_string_body(param)
        {
            return None;
        }
        if cmd != "EHLO" {
            tokens.push_str(&format!(" cmd \"{cmd}\""));
        }
        tokens.push_str(&format!(" param \"{param}\""));
    } else {
        if !is_valid_raw_string_body(line) {
            return None;
        }
        tokens.push_str(&format!(" cmd \"{line}\""));
    }

    let residual_payload = if let Some(body_bytes) = rem.strip_suffix(b"\r\n.\r\n") {
        if let Ok(body_str) = core::str::from_utf8(body_bytes)
            && is_valid_raw_string_body(body_str)
        {
            tokens.push_str(&format!(" body \"{body_str}\""));
            Vec::new()
        } else {
            rem.to_vec()
        }
    } else {
        rem.to_vec()
    };

    Some(ProtocolDissection {
        protocol: Protocol::Smtp,
        tokens,
        residual_payload,
        explicit_transport,
    })
}
