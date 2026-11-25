//! MySQL Client/Server Wire Protocol v10 Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `mysql` 4-byte framed packets
//! (3-byte little-endian payload length + 1-byte sequence number) over TCP and SCTP ports
//! `3306`, `6033` (ProxySQL), and `15306` (Vitess VTGate). It decodes `HandshakeV10` (`greeting`,
//! `serverversion`), `HandshakeResponse41` (`login`, `user`, `db`), `COM_QUERY` (`sql`),
//! `OK_Packet` (`ok`), `ERR_Packet` (`err`, `errcode`), and `EOF_Packet` (`eof`).

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Checks whether `s` contains no control characters so it can safely be emitted as a quoted field.
fn is_printable_mysql_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

/// Reads a little-endian `u16` from `b[off..off + 2]`.
fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// Reads a little-endian `u32` from `b[off..off + 4]`.
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Fixed 66-byte MySQL `HandshakeV10` trailer following the NUL-terminated server version string.
const HANDSHAKE_V10_TRAILER: &[u8; 66] = &[
    0x01, 0x00, 0x00, 0x00, // Thread ID (1)
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', // Auth-plugin-data-part-1
    0x00, // Filler
    0xFF, 0xFF, // Capability flags (lower 2 bytes)
    0x21, // Character set (0x21)
    0x02, 0x00, // Status flags (0x0002)
    0xFF, 0x00, // Capability flags (upper 2 bytes)
    21,   // Auth plugin data length (21)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10 reserved zero bytes
    b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', 0x00,
    b'm', b'y', b's', b'q', b'l', b'_', b'n', b'a', b't', b'i', b'v', b'e', b'_',
    b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 0x00,
];

/// Dissects a `mysql` 4-byte framed wire packet (`greeting`, `login`, `query`, `ok`, `err`, `eof`).
pub(crate) fn dissect_mysql(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 5
        || !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(matches!(dst_port, 3306 | 6033 | 15306) || matches!(src_port, 3306 | 6033 | 15306))
    {
        return None;
    }
    let body_len =
        (payload[0] as usize) | ((payload[1] as usize) << 8) | ((payload[2] as usize) << 16);
    let seq_id = payload[3];
    let pkt_end = 4usize.checked_add(body_len)?;
    if seq_id != 0 || payload.len() != pkt_end || body_len == 0 {
        return None;
    }
    let body = &payload[4..pkt_end];
    let mut tokens = String::from("mysql");
    let residual: &[u8];

    if let Some(rem) = body.strip_prefix(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]) {
        tokens.push_str(" ok");
        residual = rem;
    } else if let Some(rem) = body.strip_prefix(&[0xFE, 0x00, 0x00, 0x02, 0x00]) {
        tokens.push_str(" eof");
        residual = rem;
    } else if body[0] == 0xFF
        && body.len() >= 3
        && let Some(rem) = body[3..].strip_prefix(b"#28000Access denied")
    {
        let errcode = le_u16(body, 1);
        tokens.push_str(" err");
        if errcode != 1045 {
            tokens.push_str(&format!(" errcode {errcode}"));
        }
        residual = rem;
    } else if body[0] == 0x0A {
        let nul_pos = body[1..].iter().position(|&b| b == 0)?;
        let ver = core::str::from_utf8(&body[1..1 + nul_pos]).ok()?;
        if !is_printable_mysql_str(ver) {
            return None;
        }
        let rem = body[2 + nul_pos..].strip_prefix(HANDSHAKE_V10_TRAILER)?;
        tokens.push_str(" greeting");
        if ver != "8.0.35" {
            tokens.push_str(&format!(" serverversion \"{}\"", quote_raw_str(ver)));
        }
        residual = rem;
    } else if body[0] == 0x03 {
        let sql = core::str::from_utf8(&body[1..]).ok()?;
        if !is_printable_mysql_str(sql) {
            return None;
        }
        if sql != "SELECT 1" {
            tokens.push_str(&format!(" sql \"{}\"", quote_raw_str(sql)));
        }
        residual = &[];
    } else if body.len() >= 34 && body[8] == 0x21 && body[9..32].iter().all(|&b| b == 0) {
        let caps = le_u32(body, 0);
        if caps != 0x0008_A685 && caps != 0x0008_A68D {
            return None;
        }
        let rest = &body[32..];
        let u_end = rest.iter().position(|&b| b == 0)?;
        let user = core::str::from_utf8(&rest[..u_end]).ok()?;
        if !is_printable_mysql_str(user) || rest.get(u_end + 1) != Some(&0) {
            return None;
        }
        tokens.push_str(" login");
        if user != "root" {
            tokens.push_str(&format!(" user \"{}\"", quote_raw_str(user)));
        }
        let after_auth = &rest[u_end + 2..];
        if (caps & 0x08) != 0 {
            let db_end = after_auth.iter().position(|&b| b == 0)?;
            let db = core::str::from_utf8(&after_auth[..db_end]).ok()?;
            if !is_printable_mysql_str(db) {
                return None;
            }
            tokens.push_str(&format!(" db \"{}\"", quote_raw_str(db)));
            residual = &after_auth[db_end + 1..];
        } else {
            residual = after_auth;
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
