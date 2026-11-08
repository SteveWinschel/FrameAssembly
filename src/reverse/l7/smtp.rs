//! Simple Mail Transfer Protocol (SMTP, RFC 5321) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `SMTP` client commands and server
//! reply frames carried over TCP ports `25`, `465`, `587`, and `2525`. It validates CRLF line
//! framing, decodes three-digit numeric status replies (`code`, `reply`), standard verbs (`ehlo`,
//! `helo`, `mail_from`, `rcpt_to`, `quit`, and generic `cmd`/`param` pairs), and optional
//! `\r\n.\r\n`-terminated message `body` sections while eliding default `EHLO localhost` / `OK`
//! values and routing unparsed trailing bytes into `residual_payload`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Finds the first `\r\n` sequence in `bytes` and returns `(line_str, remainder)`.
fn split_crlf_line(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let pos = bytes.windows(2).position(|w| w == b"\r\n")?;
    let line = core::str::from_utf8(&bytes[..pos]).ok()?;
    if !is_valid_raw_str(line) {
        return None;
    }
    Some((line, &bytes[pos + 2..]))
}

/// Dissects an `SMTP` command or reply payload over TCP ports `25`, `465`, `587`, or `2525`.
pub(crate) fn dissect_smtp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(transport, TransportProto::Tcp)
        || !(matches!(dst_port, 25 | 465 | 587 | 2525)
            || matches!(src_port, 25 | 465 | 587 | 2525))
    {
        return None;
    }

    let (line, rem) = split_crlf_line(payload)?;
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
        if !is_valid_raw_str(reply) {
            return None;
        }
        tokens.push_str(&format!(" code {code}"));
        if reply != "OK" {
            tokens.push_str(&format!(" reply \"{reply}\""));
        }
    } else if line == "EHLO localhost" {
        // Default command; no modifiers required unless body is attached.
    } else if line == "QUIT" {
        tokens.push_str(" quit");
    } else if line == "EHLO" {
        tokens.push_str(" ehlo");
    } else if line == "HELO" {
        tokens.push_str(" helo");
    } else if let Some(dom) = line.strip_prefix("EHLO ") {
        if !is_valid_raw_str(dom) {
            return None;
        }
        tokens.push_str(&format!(" ehlo \"{dom}\""));
    } else if let Some(dom) = line.strip_prefix("HELO ") {
        if !is_valid_raw_str(dom) {
            return None;
        }
        tokens.push_str(&format!(" helo \"{dom}\""));
    } else if let Some(addr) = line.strip_prefix("MAIL FROM ") {
        if !is_valid_raw_str(addr) {
            return None;
        }
        tokens.push_str(&format!(" mail_from \"{addr}\""));
    } else if let Some(addr) = line.strip_prefix("RCPT TO ") {
        if !is_valid_raw_str(addr) {
            return None;
        }
        tokens.push_str(&format!(" rcpt_to \"{addr}\""));
    } else if let Some((cmd, param)) = line.split_once(' ') {
        if cmd.is_empty() || !is_valid_raw_str(cmd) || !is_valid_raw_str(param) {
            return None;
        }
        if cmd != "EHLO" {
            tokens.push_str(&format!(" cmd \"{cmd}\""));
        }
        tokens.push_str(&format!(" param \"{param}\""));
    } else {
        if !is_valid_raw_str(line) {
            return None;
        }
        tokens.push_str(&format!(" cmd \"{line}\""));
    }

    let residual_payload = if let Some(body_bytes) = rem.strip_suffix(b"\r\n.\r\n") {
        if let Ok(body_str) = core::str::from_utf8(body_bytes)
            && is_valid_raw_str(body_str)
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
        explicit_transport: None,
    })
}
