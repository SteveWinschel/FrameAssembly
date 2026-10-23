//! MYSQL protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a MySQL client/server command packet payload.
pub fn build_mysql_payload(
    _ctx: &WireContext,
    spec: &MysqlSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let sql = spec.sql.unwrap_or("SELECT 1");
    let mut body = Vec::new();
    body.push(0x03); // COM_QUERY
    body.extend_from_slice(sql.as_bytes());

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let length = body.len() as u32;
    let mut pkt = Vec::with_capacity(4 + body.len());
    // 3-byte Packet Length (Little Endian)
    pkt.push(length as u8);
    pkt.push((length >> 8) as u8);
    pkt.push((length >> 16) as u8);
    pkt.push(0); // Sequence ID: 0
    pkt.extend_from_slice(&body);
    pkt
}
