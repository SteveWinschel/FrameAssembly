//! Memcached Binary (`0x80`) and ASCII Protocol Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `MEMCACHED` binary protocol frames
//! (24-byte `0x80` request header with `opcode`, `flags`, `exptime`, `key`, `value`, `opaque`, and
//! `cas`) and CRLF-delimited ASCII commands (`get`, `set`, `add`, `replace`, `append`, `prepend`,
//! `delete`) over TCP and UDP transports on ports `11211`, `11212`, or custom ports carrying the
//! 24-byte `0x80` binary header.

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

/// Reads a big-endian `u32` from `b[off..off + 4]`.
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Dissects a `MEMCACHED` binary (`0x80`) or ASCII command frame over TCP or UDP.
pub(crate) fn dissect_memcached(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty() || !matches!(transport, TransportProto::Tcp | TransportProto::Udp) {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);
    let explicit_transport = if !is_tcp {
        Some(TransportProto::Udp)
    } else {
        None
    };

    if payload.len() >= 24 && payload[0] == 0x80 {
        let opcode = payload[1];
        let key_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        let extras_len = payload[4] as usize;
        let total_body = be_u32(payload, 8) as usize;
        let opaque = be_u32(payload, 12);
        let cas = u64::from_be_bytes([
            payload[16],
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
        ]);

        if total_body < extras_len + key_len || payload.len() < 24 + total_body {
            return None;
        }

        let mut tokens = format!("memcached opcode 0x{opcode:02x}");
        if extras_len == 8 {
            let flags = be_u32(payload, 24);
            let exptime = be_u32(payload, 28);
            if flags != 0 || !matches!(opcode, 0x01..=0x03) {
                tokens.push_str(&format!(" flags {flags}"));
            }
            if exptime != 0 {
                tokens.push_str(&format!(" exptime {exptime}"));
            }
        } else if extras_len != 0 {
            return None;
        }

        let key_start = 24 + extras_len;
        let key_end = key_start + key_len;
        let val_end = 24 + total_body;
        let key_str = core::str::from_utf8(&payload[key_start..key_end]).ok()?;
        let val_str = core::str::from_utf8(&payload[key_end..val_end]).ok()?;
        if !is_valid_raw_str(key_str) || !is_valid_raw_str(val_str) {
            return None;
        }
        let default_bin_key = if matches!(opcode, 0x07 | 0x08 | 0x0A | 0x0B | 0x10) {
            ""
        } else {
            "key"
        };
        if key_str != default_bin_key {
            tokens.push_str(&format!(" key \"{key_str}\""));
        }
        if !val_str.is_empty() {
            tokens.push_str(&format!(" value \"{val_str}\""));
        }
        if opaque != 0 {
            tokens.push_str(&format!(" opaque 0x{opaque:08x}"));
        }
        if cas != 0 {
            tokens.push_str(&format!(" cas 0x{cas:x}"));
        }

        return Some(ProtocolDissection {
            protocol: Protocol::Memcached,
            tokens,
            residual_payload: payload[val_end..].to_vec(),
            explicit_transport,
        });
    }

    if !(matches!(dst_port, 11211 | 11212) || matches!(src_port, 11211 | 11212)) {
        return None;
    }

    let (line, rem) = split_crlf_line(payload)?;
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.is_empty() || parts[0].is_empty() || !is_valid_raw_str(parts[0]) {
        return None;
    }
    let cmd = parts[0];
    let mut tokens = String::from("memcached");

    if matches!(cmd, "set" | "add" | "replace" | "append" | "prepend") && parts.len() == 5 {
        let key = parts[1];
        let flags: u32 = parts[2].parse().ok()?;
        let exptime: u32 = parts[3].parse().ok()?;
        let vlen: usize = parts[4].parse().ok()?;
        if rem.len() < vlen + 2 || &rem[vlen..vlen + 2] != b"\r\n" {
            return None;
        }
        let val = core::str::from_utf8(&rem[..vlen]).ok()?;
        if !is_valid_raw_str(key) || !is_valid_raw_str(val) {
            return None;
        }
        if cmd == "set" {
            tokens.push_str(" set");
        } else {
            tokens.push_str(&format!(" cmd \"{cmd}\""));
        }
        if key != "key" {
            tokens.push_str(&format!(" key \"{key}\""));
        }
        if flags != 0 {
            tokens.push_str(&format!(" flags {flags}"));
        }
        if exptime != 0 {
            tokens.push_str(&format!(" exptime {exptime}"));
        }
        if !val.is_empty() {
            tokens.push_str(&format!(" value \"{val}\""));
        }
        return Some(ProtocolDissection {
            protocol: Protocol::Memcached,
            tokens,
            residual_payload: rem[vlen + 2..].to_vec(),
            explicit_transport,
        });
    }

    if parts.len() == 1 {
        if cmd == "get" {
            tokens.push_str(" key \"\"");
        } else {
            tokens.push_str(&format!(" cmd \"{cmd}\""));
        }
    } else if parts.len() == 2 {
        let key = parts[1];
        if !is_valid_raw_str(key) {
            return None;
        }
        if cmd != "get" {
            tokens.push_str(&format!(" cmd \"{cmd}\""));
        }
        if key != "key" {
            tokens.push_str(&format!(" key \"{key}\""));
        }
    } else {
        return None;
    }

    Some(ProtocolDissection {
        protocol: Protocol::Memcached,
        tokens,
        residual_payload: rem.to_vec(),
        explicit_transport,
    })
}
