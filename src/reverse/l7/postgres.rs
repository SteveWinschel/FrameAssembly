//! PostgreSQL Frontend/Backend Wire Protocol v3.0 Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `POSTGRES` v3.0 messages over TCP
//! ports `5432`, `6432` (PgBouncer), and `9999` (Pgpool-II), as well as custom-port `StartupMessage`
//! frames identified by protocol version `0x0003_0000`. It decodes `StartupMessage` (`startup`,
//! `user`, `db`), `Query` (`'Q'`, `sql`), `AuthenticationOk` (`'R'`, `auth_ok`), `CommandComplete`
//! (`'C'`, `command_complete`), `ReadyForQuery` (`'Z'`, `ready_for_query`), and `ErrorResponse`
//! (`'E'`, `error_response`).

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

/// Reads a big-endian `u32` from `b[off..off + 4]`.
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Dissects a `POSTGRES` v3 wire message (`StartupMessage`, `'Q'`, `'R'`, `'C'`, `'Z'`, `'E'`).
pub(crate) fn dissect_postgres(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty() || !matches!(transport, TransportProto::Tcp) {
        return None;
    }

    if payload.len() >= 8 && be_u32(payload, 4) == 0x0003_0000 {
        let total_len = be_u32(payload, 0) as usize;
        if total_len < 9 || payload.len() < total_len {
            return None;
        }
        let params = &payload[8..total_len - 1];
        let parts: Vec<&[u8]> = params.split(|&b| b == 0).collect();
        if parts.len() < 4 || parts[0] != b"user" || parts[2] != b"database" {
            return None;
        }
        let user = core::str::from_utf8(parts[1]).ok()?;
        let db = core::str::from_utf8(parts[3]).ok()?;
        if !is_valid_raw_str(user) || !is_valid_raw_str(db) {
            return None;
        }
        let mut tokens = String::from("postgres startup");
        if user != "postgres" {
            tokens.push_str(&format!(" user \"{user}\""));
        }
        if db != "postgres" {
            tokens.push_str(&format!(" db \"{db}\""));
        }
        return Some(ProtocolDissection {
            protocol: Protocol::Postgres,
            tokens,
            residual_payload: payload[total_len..].to_vec(),
            explicit_transport: None,
        });
    }

    if !(matches!(dst_port, 5432 | 6432 | 9999) || matches!(src_port, 5432 | 6432 | 9999))
        || payload.len() < 5
    {
        return None;
    }
    let tag = payload[0];
    let len = be_u32(payload, 1) as usize;
    if len < 4 || payload.len() < 1 + len {
        return None;
    }
    let body = &payload[5..1 + len];
    let residual = &payload[1 + len..];
    let mut tokens = String::from("postgres");

    match tag {
        b'Z' if body == b"I" => {
            tokens.push_str(" ready_for_query");
        }
        b'R' if body == [0, 0, 0, 0] => {
            tokens.push_str(" auth_ok");
        }
        b'C' if body.ends_with(&[0]) => {
            let s = core::str::from_utf8(&body[..body.len() - 1]).ok()?;
            if !is_valid_raw_str(s) {
                return None;
            }
            tokens.push_str(" command_complete");
            if s != "SELECT 1" {
                tokens.push_str(&format!(" sql \"{s}\""));
            }
        }
        b'E' if body.starts_with(b"SERROR\0C28P01\0M") && body.ends_with(b"\0\0") => {
            let msg_bytes = &body[15..body.len() - 2];
            let s = core::str::from_utf8(msg_bytes).ok()?;
            if !is_valid_raw_str(s) {
                return None;
            }
            tokens.push_str(" error_response");
            if s != "authentication failed" {
                tokens.push_str(&format!(" sql \"{s}\""));
            }
        }
        b'Q' if body.ends_with(&[0]) => {
            let s = core::str::from_utf8(&body[..body.len() - 1]).ok()?;
            if !is_valid_raw_str(s) {
                return None;
            }
            if s != "SELECT version()" {
                tokens.push_str(&format!(" sql \"{s}\""));
            }
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Postgres,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
