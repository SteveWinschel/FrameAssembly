//! Redis Serialization Protocol v2 (RESP2) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `redis` RESP2 command arrays and
//! typed server replies over TCP and SCTP ports `6379` and `26379` (Redis Sentinel). It decodes
//! Simple Strings (`+`), Errors (`-`), Integers (`:`), Bulk Strings (`$`), and multibulk Command
//! Arrays (`*`, including `ping`, `get`, `set`, and custom commands with `args`) into `.frasm`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Checks whether `s` contains no control characters so it can safely be emitted inside quotes.
fn is_printable_redis_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

/// Checks whether `s` can be emitted verbatim inside `"..."` for `parse_any_str` fields (`cmd`).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
        && crate::parser::unescape_string(s).is_ok()
}

/// Finds the first `\r\n` sequence in `bytes` and returns `(line_str, remainder)`.
fn split_crlf_line(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let pos = bytes.windows(2).position(|w| w == b"\r\n")?;
    let line = core::str::from_utf8(&bytes[..pos]).ok()?;
    if !is_printable_redis_str(line) {
        return None;
    }
    Some((line, &bytes[pos + 2..]))
}

/// Dissects a `redis` RESP2 command array or typed reply over TCP or SCTP ports `6379` or `26379`.
pub(crate) fn dissect_redis(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(matches!(dst_port, 6379 | 26379) || matches!(src_port, 6379 | 26379))
    {
        return None;
    }

    let mut tokens = String::from("redis");
    let residual: &[u8];

    match payload[0] {
        b'+' => {
            let (val, rem) = split_crlf_line(&payload[1..])?;
            tokens.push_str(" replytype \"status\"");
            if val != "OK" {
                tokens.push_str(&format!(" value \"{}\"", quote_raw_str(val)));
            }
            residual = rem;
        }
        b'-' => {
            let (val, rem) = split_crlf_line(&payload[1..])?;
            tokens.push_str(" replytype \"err\"");
            let clean = val.strip_prefix("ERR ").unwrap_or(val);
            if clean != "unknown command" {
                tokens.push_str(&format!(" value \"{}\"", quote_raw_str(clean)));
            }
            residual = rem;
        }
        b':' => {
            let (val, rem) = split_crlf_line(&payload[1..])?;
            tokens.push_str(" replytype \"int\"");
            if val != "1" {
                tokens.push_str(&format!(" value \"{}\"", quote_raw_str(val)));
            }
            residual = rem;
        }
        b'$' => {
            let (len_str, after_len) = split_crlf_line(&payload[1..])?;
            if len_str == "-1" {
                tokens.push_str(" replytype \"bulk\"");
                residual = after_len;
            } else {
                let len: usize = len_str.parse().ok()?;
                if after_len.len() < len + 2 || &after_len[len..len + 2] != b"\r\n" {
                    return None;
                }
                let val = core::str::from_utf8(&after_len[..len]).ok()?;
                if !is_printable_redis_str(val) {
                    return None;
                }
                tokens.push_str(&format!(" replytype \"bulk\" value \"{}\"", quote_raw_str(val)));
                residual = &after_len[len + 2..];
            }
        }
        b'*' => {
            let (count_str, mut cur) = split_crlf_line(&payload[1..])?;
            let count: usize = count_str.parse().ok()?;
            if count == 0 || count > 64 {
                return None;
            }
            let mut parts = Vec::with_capacity(count);
            for _ in 0..count {
                if cur.first() != Some(&b'$') {
                    return None;
                }
                let (blen_str, after_blen) = split_crlf_line(&cur[1..])?;
                let blen: usize = blen_str.parse().ok()?;
                if after_blen.len() < blen + 2 || &after_blen[blen..blen + 2] != b"\r\n" {
                    return None;
                }
                let s = core::str::from_utf8(&after_blen[..blen]).ok()?;
                if !is_printable_redis_str(s) {
                    return None;
                }
                parts.push(s);
                cur = &after_blen[blen + 2..];
            }
            if !(parts.len() == 1 && parts[0] == "PING") {
                if parts[0] == "GET" {
                    tokens.push_str(" get");
                } else if parts[0] == "SET" {
                    tokens.push_str(" set");
                } else if is_valid_raw_str(parts[0]) {
                    tokens.push_str(&format!(" cmd \"{}\"", parts[0]));
                } else {
                    return None;
                }
            }
            for arg in &parts[1..] {
                tokens.push_str(&format!(" args \"{}\"", quote_raw_str(arg)));
            }
            residual = cur;
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Redis,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
