//! Internet Message Access Protocol v4rev1 (IMAP4, RFC 3501 / RFC 9051) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `imap` client command and server
//! response frames over TCP ports `143` and `993`. It parses CRLF-delimited tagged (`A01` and
//! custom tags) and untagged (`*`) lines, distinguishing completion status responses (`OK`, `NO`,
//! `BAD` with `status` and `response` modifiers) from command invocations (`cmd`, `arg`) while
//! eliding default `A01`, `NOOP`, and `Completed` tokens and preserving trailing bytes in
//! `residual_payload`.

use alloc::format;
use alloc::string::String;

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

/// Dissects an `imap` tagged or untagged command or response line over TCP ports `143` or `993`.
pub(crate) fn dissect_imap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(transport, TransportProto::Tcp)
        || !(matches!(dst_port, 143 | 993) || matches!(src_port, 143 | 993))
    {
        return None;
    }

    let (line, rem) = split_crlf_line(payload)?;
    let (tag, rest) = line.split_once(' ')?;
    if tag.is_empty() || rest.is_empty() || !is_valid_raw_str(tag) {
        return None;
    }

    let mut tokens = String::from("imap");
    if let Some((second, third)) = rest.split_once(' ') {
        if !is_valid_raw_str(second) || !is_valid_raw_str(third) {
            return None;
        }
        if matches!(second, "OK" | "NO" | "BAD") {
            if tag == "*" && second == "OK" {
                tokens.push_str(&format!(" response \"{third}\""));
            } else {
                if tag != "A01" {
                    tokens.push_str(&format!(" tag \"{tag}\""));
                }
                tokens.push_str(&format!(" status \"{second}\""));
                if third != "Completed" {
                    tokens.push_str(&format!(" response \"{third}\""));
                }
            }
        } else {
            if tag != "A01" {
                tokens.push_str(&format!(" tag \"{tag}\""));
            }
            if second != "NOOP" {
                tokens.push_str(&format!(" cmd \"{second}\""));
            }
            tokens.push_str(&format!(" arg \"{third}\""));
        }
    } else {
        if !is_valid_raw_str(rest) {
            return None;
        }
        if tag != "A01" {
            tokens.push_str(&format!(" tag \"{tag}\""));
        }
        if rest != "NOOP" {
            tokens.push_str(&format!(" cmd \"{rest}\""));
        }
    }

    Some(ProtocolDissection {
        protocol: Protocol::Imap,
        tokens,
        residual_payload: rem.to_vec(),
        explicit_transport: None,
    })
}
