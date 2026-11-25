//! Post Office Protocol Version 3 (POP3, RFC 1939) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `pop3` client commands and server
//! status responses over TCP or SCTP ports `110`, `995`, and `2110`. It decodes CRLF-terminated
//! `+OK` and `-ERR` response banners (`ok`, `err`, `response`) as well as `USER`, `PASS`, `STAT`,
//! `LIST`, `RETR`, `DELE`, `QUIT`, and custom commands (`cmd`, `arg`) while eliding default `USER`,
//! `OK`, and `Error` values and validating raw string literal safety.

use alloc::format;
use alloc::string::String;

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

/// Dissects a `pop3` command or `+OK` / `-ERR` status response over TCP or SCTP ports `110`, `995`, or `2110`.
pub(crate) fn dissect_pop3(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(matches!(dst_port, 110 | 995 | 2110) || matches!(src_port, 110 | 995 | 2110))
    {
        return None;
    }

    let (line, rem) = split_crlf_line(payload)?;
    if line.is_empty() {
        return None;
    }

    let mut tokens = String::from("pop3");
    if let Some(resp) = line.strip_prefix("+OK ") {
        if !is_valid_raw_string_body(resp) {
            return None;
        }
        tokens.push_str(" ok");
        if resp != "OK" {
            tokens.push_str(&format!(" response \"{resp}\""));
        }
    } else if line == "+OK" {
        tokens.push_str(" ok response \"\"");
    } else if let Some(resp) = line.strip_prefix("-ERR ") {
        if !is_valid_raw_string_body(resp) {
            return None;
        }
        tokens.push_str(" err");
        if resp != "Error" {
            tokens.push_str(&format!(" response \"{resp}\""));
        }
    } else if line == "-ERR" {
        tokens.push_str(" err response \"\"");
    } else if let Some((cmd, arg)) = line.split_once(' ') {
        if cmd.is_empty() || !is_valid_raw_string_body(cmd) || !is_valid_raw_string_body(arg) {
            return None;
        }
        if cmd != "USER" {
            tokens.push_str(&format!(" cmd \"{cmd}\""));
        }
        tokens.push_str(&format!(" arg \"{arg}\""));
    } else {
        if !is_valid_raw_string_body(line) {
            return None;
        }
        if line != "USER" {
            tokens.push_str(&format!(" cmd \"{line}\""));
        }
    }

    Some(ProtocolDissection {
        protocol: Protocol::Pop3,
        tokens,
        residual_payload: rem.to_vec(),
        explicit_transport: matches!(transport, TransportProto::Sctp).then_some(TransportProto::Sctp),
    })
}
