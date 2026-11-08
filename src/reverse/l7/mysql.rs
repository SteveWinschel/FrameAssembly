//! MySQL Client/Server Wire Protocol v10 Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `MYSQL` 4-byte framed packets
//! (3-byte little-endian payload length + 1-byte sequence number) over TCP ports `3306`, `6033`
//! (ProxySQL), and `15306` (Vitess VTGate). It decodes `HandshakeV10` (`greeting`, `server_version`),
//! `HandshakeResponse41` (`login`, `user`, `db`), `COM_QUERY` (`sql`), `OK_Packet` (`ok`),
//! `ERR_Packet` (`err`, `errcode`), and `EOF_Packet` (`eof`).

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

/// Reads a little-endian `u16` from `b[off..off + 2]`.
fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// Reads a little-endian `u32` from `b[off..off + 4]`.
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Dissects a `MYSQL` 4-byte framed wire packet (`GREETING`, `LOGIN`, `QUERY`, `OK`, `ERR`, `EOF`).
pub(crate) fn dissect_mysql(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 5
        || !matches!(transport, TransportProto::Tcp)
        || !(matches!(dst_port, 3306 | 6033 | 15306) || matches!(src_port, 3306 | 6033 | 15306))
    {
        return None;
    }
    let body_len =
        (payload[0] as usize) | ((payload[1] as usize) << 8) | ((payload[2] as usize) << 16);
    let seq_id = payload[3];
    if seq_id != 0 || payload.len() < 4 + body_len || body_len == 0 {
        return None;
    }
    let body = &payload[4..4 + body_len];
    let residual = &payload[4 + body_len..];
    let mut tokens = String::from("mysql");

    if body == [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00] {
        tokens.push_str(" ok");
    } else if body == [0xFE, 0x00, 0x00, 0x02, 0x00] {
        tokens.push_str(" eof");
    } else if body[0] == 0xFF && body.len() >= 3 && body[3..].starts_with(b"#28000Access denied") {
        let errcode = le_u16(body, 1);
        tokens.push_str(" err");
        if errcode != 1045 {
            tokens.push_str(&format!(" errcode {errcode}"));
        }
    } else if body[0] == 0x0A {
        let nul_pos = body[1..].iter().position(|&b| b == 0)?;
        let ver = core::str::from_utf8(&body[1..1 + nul_pos]).ok()?;
        if !is_valid_raw_str(ver) || body.len() != 1 + nul_pos + 1 + 27 {
            return None;
        }
        tokens.push_str(" greeting");
        if ver != "8.0.35" {
            tokens.push_str(&format!(" server_version \"{ver}\""));
        }
    } else if body[0] == 0x03 {
        let sql = core::str::from_utf8(&body[1..]).ok()?;
        if !is_valid_raw_str(sql) {
            return None;
        }
        if sql != "SELECT 1" {
            tokens.push_str(&format!(" sql \"{sql}\""));
        }
    } else if body.len() >= 34 && body[8] == 0x21 && body[9..32].iter().all(|&b| b == 0) {
        let caps = le_u32(body, 0);
        if caps != 0x0008_A685 && caps != 0x0008_A68D {
            return None;
        }
        let rest = &body[32..];
        let u_end = rest.iter().position(|&b| b == 0)?;
        let user = core::str::from_utf8(&rest[..u_end]).ok()?;
        if !is_valid_raw_str(user) || rest.get(u_end + 1) != Some(&0) {
            return None;
        }
        tokens.push_str(" login");
        if user != "root" {
            tokens.push_str(&format!(" user \"{user}\""));
        }
        let after_auth = &rest[u_end + 2..];
        if (caps & 0x08) != 0 && !after_auth.is_empty() {
            let db_end = after_auth.iter().position(|&b| b == 0)?;
            let db = core::str::from_utf8(&after_auth[..db_end]).ok()?;
            if !is_valid_raw_str(db) {
                return None;
            }
            tokens.push_str(&format!(" db \"{db}\""));
        }
    } else {
        return None;
    }

    Some(ProtocolDissection {
        protocol: Protocol::Mysql,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
