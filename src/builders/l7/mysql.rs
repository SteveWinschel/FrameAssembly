//! MySQL Client/Server Wire Protocol v10 payload builder.
//!
//! This module implements [`build_mysql_payload`], which serializes a [`MysqlSpec`]
//! AST specification into a MySQL wire packet over TCP port 3306. Every packet is prefixed with a
//! 3-byte little-endian payload length and 1-byte sequence number (splitting bodies above 16 MiB
//! into `0xFFFFFF` chunks with incrementing sequence IDs), encapsulating `HandshakeV10` greetings,
//! `HandshakeResponse41` logins, `OK_Packet` (`0x00`), `EOF_Packet` (`0xFE`), `ERR_Packet`
//! (`0xFF` with 16-bit error code and SQLSTATE `#28000`), or `COM_QUERY` (`0x03`) SQL commands.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Maximum MySQL single-packet payload length (`2^24 - 1`).
const MAX_MYSQL_PKT_LEN: usize = 0xFF_FFFF;

/// Builds a MySQL client/server command packet payload.
pub fn build_mysql_payload(
    _ctx: &WireContext,
    spec: &MysqlSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    let has_other_flag =
        spec.is_login || spec.is_query || spec.is_ok || spec.is_err || spec.is_eof;

    if spec.is_greeting || (spec.server_version.is_some() && !has_other_flag) {
        // Protocol v10 HandshakeV10 initial greeting packet
        let ver = spec.server_version.unwrap_or("8.0.35");
        body.push(0x0A); // Protocol version 10
        body.extend_from_slice(ver.as_bytes());
        body.push(0x00); // Null-terminated server version
        body.extend_from_slice(&1u32.to_le_bytes()); // Thread ID
        body.extend_from_slice(b"12345678"); // Auth-plugin-data-part-1 (8 bytes)
        body.push(0x00); // Filler
        body.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Capability flags (lower 2 bytes)
        body.push(0x21); // Character set: utf8mb4_0900_ai_ci / utf8 (0x21)
        body.extend_from_slice(&0x0002u16.to_le_bytes()); // Status flags: SERVER_STATUS_AUTOCOMMIT
        body.extend_from_slice(&0x00FFu16.to_le_bytes()); // Capability flags (upper 2 bytes)
        body.push(21); // Auth plugin data length (8 + 13)
        body.extend_from_slice(&[0u8; 10]); // Reserved (10 zero bytes)
        body.extend_from_slice(b"901234567890\0"); // Auth-plugin-data-part-2 (13 bytes, NUL-terminated)
        body.extend_from_slice(b"mysql_native_password\0"); // Auth plugin name
    } else if spec.is_login
        || ((spec.user.is_some() || spec.db.is_some())
            && !spec.is_query
            && !spec.is_ok
            && !spec.is_err
            && !spec.is_eof
            && spec.sql.is_none())
    {
        // HandshakeResponse41 client login packet
        let caps: u32 = if spec.db.is_some() {
            0x0008_A68D
        } else {
            0x0008_A685
        };
        body.extend_from_slice(&caps.to_le_bytes()); // Client capability flags
        body.extend_from_slice(&0x0100_0000u32.to_le_bytes()); // Max packet size (16MB)
        body.push(0x21); // Character set: utf8 (33)
        body.extend_from_slice(&[0u8; 23]); // Reserved (23 zero bytes)
        body.extend_from_slice(spec.user.unwrap_or("root").as_bytes());
        body.push(0x00); // Null-terminated username
        body.push(0x00); // Empty auth response length
        if let Some(db) = spec.db {
            body.extend_from_slice(db.as_bytes());
            body.push(0x00); // Null-terminated database name
        }
    } else if spec.is_ok {
        // OK_Packet (0x00)
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
    } else if spec.is_err || spec.errcode.is_some() {
        // ERR_Packet (0xFF)
        body.push(0xFF);
        body.extend_from_slice(&spec.errcode.unwrap_or(1045).to_le_bytes());
        body.extend_from_slice(b"#28000Access denied");
    } else if spec.is_eof {
        // EOF_Packet (0xFE)
        body.extend_from_slice(&[0xFE, 0x00, 0x00, 0x02, 0x00]);
    } else {
        // COM_QUERY (0x03)
        let sql = spec.sql.unwrap_or("SELECT 1");
        let _ = spec.is_query;
        body.push(0x03); // COM_QUERY
        body.extend_from_slice(sql.as_bytes());
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let mut pkt = Vec::with_capacity(4 + body.len());
    let mut seq_id = 0u8;
    let mut offset = 0usize;
    loop {
        let rem = body.len() - offset;
        let chunk_len = rem.min(MAX_MYSQL_PKT_LEN);
        let len_u32 = chunk_len as u32;
        pkt.push(len_u32 as u8);
        pkt.push((len_u32 >> 8) as u8);
        pkt.push((len_u32 >> 16) as u8);
        pkt.push(seq_id);
        pkt.extend_from_slice(&body[offset..offset + chunk_len]);
        offset += chunk_len;
        seq_id = seq_id.wrapping_add(1);
        if chunk_len < MAX_MYSQL_PKT_LEN {
            break;
        }
    }
    pkt
}
