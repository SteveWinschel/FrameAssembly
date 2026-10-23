//! POSTGRES protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a PostgreSQL 3.0 frontend/backend protocol message payload.
pub fn build_postgres_payload(
    _ctx: &WireContext,
    spec: &PostgresSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let sql = spec.sql.unwrap_or("SELECT version()");
    let sql_bytes = sql.as_bytes();
    let length = (4 + sql_bytes.len() + 1) as u32;

    let mut pkt = Vec::with_capacity(1 + length as usize);
    pkt.push(b'Q'); // 'Q' for Simple Query
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(sql_bytes);
    pkt.push(0); // Null-terminated query string

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
