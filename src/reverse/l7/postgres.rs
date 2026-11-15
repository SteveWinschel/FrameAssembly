//! PostgreSQL Frontend/Backend Wire Protocol v3.0 Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `postgres` v3.0 messages over TCP
//! ports `5432`, `6432` (PgBouncer), and `9999` (Pgpool-II), as well as custom-port `StartupMessage`
//! frames identified by protocol version `0x0003_0000`. It decodes `StartupMessage` (`startup`,
//! `user`, `db`), `Query` (`'Q'`, `sql`), `AuthenticationOk` (`'R'`, `authok`), `CommandComplete`
//! (`'C'`, `commandcomplete`), `ReadyForQuery` (`'Z'`, `readyforquery`), and `ErrorResponse`
//! (`'E'`, `errorresponse`).

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

/// Reads a big-endian `u32` from `b[off..off + 4]`.
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Dissects a `postgres` v3 wire message (`StartupMessage`, `'Q'`, `'R'`, `'C'`, `'Z'`, `'E'`).
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
        if total_len < 9 || payload.len() != total_len {
            return None;
        }
        let after_uk = payload[8..total_len].strip_prefix(b"user\0")?;
        let u_end = after_uk.iter().position(|&b| b == 0)?;
        let user = core::str::from_utf8(&after_uk[..u_end]).ok()?;
        let after_dk = after_uk[u_end + 1..].strip_prefix(b"database\0")?;
        let d_end = after_dk.iter().position(|&b| b == 0)?;
        let db = core::str::from_utf8(&after_dk[..d_end]).ok()?;
        if after_dk.get(d_end + 1) != Some(&0) || !is_valid_raw_str(user) || !is_valid_raw_str(db) {
            return None;
        }
        let residual = &after_dk[d_end + 2..];
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
            residual_payload: residual.to_vec(),
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
    let msg_end = 1usize.checked_add(len)?;
    if len < 4 || payload.len() != msg_end {
        return None;
    }
    let body = &payload[5..msg_end];
    let mut tokens = String::from("postgres");
    let residual: &[u8] = match tag {
        b'Z' if body.starts_with(b"I") => {
            tokens.push_str(" readyforquery");
            &body[1..]
        }
        b'R' if body.starts_with(&[0, 0, 0, 0]) => {
            tokens.push_str(" authok");
            &body[4..]
        }
        b'C' => {
            let nul = body.iter().position(|&b| b == 0)?;
            let s = core::str::from_utf8(&body[..nul]).ok()?;
            if !is_valid_raw_str(s) {
                return None;
            }
            tokens.push_str(" commandcomplete");
            if s != "SELECT 1" {
                tokens.push_str(&format!(" sql \"{s}\""));
            }
            &body[nul + 1..]
        }
        b'E' => {
            let after_hdr = body.strip_prefix(b"SERROR\0C28P01\0M")?;
            let nul = after_hdr.iter().position(|&b| b == 0)?;
            if after_hdr.get(nul + 1) != Some(&0) {
                return None;
            }
            let s = core::str::from_utf8(&after_hdr[..nul]).ok()?;
            if !is_valid_raw_str(s) {
                return None;
            }
            tokens.push_str(" errorresponse");
            if s != "authentication failed" {
                tokens.push_str(&format!(" sql \"{s}\""));
            }
            &after_hdr[nul + 2..]
        }
        b'Q' => {
            let nul = body.iter().position(|&b| b == 0)?;
            let s = core::str::from_utf8(&body[..nul]).ok()?;
            if !is_valid_raw_str(s) {
                return None;
            }
            if s != "SELECT version()" {
                tokens.push_str(&format!(" sql \"{s}\""));
            }
            &body[nul + 1..]
        }
        _ => return None,
    };

    Some(ProtocolDissection {
        protocol: Protocol::Postgres,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
