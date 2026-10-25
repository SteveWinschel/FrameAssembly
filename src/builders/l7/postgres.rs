//! PostgreSQL Frontend/Backend Protocol v3.0 wire payload builder.
//!
//! This module implements [`build_postgres_payload`], which serializes a [`PostgresSpec`]
//! AST node into a PostgreSQL v3.0 (`0x00030000`) frontend or backend wire message over TCP port
//! 5432. It supports unprefixed `StartupMessage` frames (32-bit length, version `196608`, and
//! NUL-terminated `user`/`database` key-value pairs) as well as type-prefixed messages:
//! `AuthenticationOk` (`'R'`), `ReadyForQuery` (`'Z'`), `CommandComplete` (`'C'`), `ErrorResponse`
//! (`'E'`), and simple SQL `Query` (`'Q'`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a PostgreSQL 3.0 frontend/backend protocol message payload.
pub fn build_postgres_payload(
    _ctx: &WireContext,
    spec: &PostgresSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();

    if spec.is_startup
        || ((spec.user.is_some() || spec.db.is_some()) && !spec.is_query && spec.sql.is_none())
    {
        // StartupMessage: 4B length (including self) + 0x00030000 (v3.0) + key/value pairs + 0x00
        let user = spec.user.unwrap_or("postgres").as_bytes();
        let db = spec.db.unwrap_or("postgres").as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&0x0003_0000u32.to_be_bytes());
        body.extend_from_slice(b"user\0");
        body.extend_from_slice(user);
        body.push(0);
        body.extend_from_slice(b"database\0");
        body.extend_from_slice(db);
        body.push(0);
        body.push(0); // Terminating null byte

        let length = (4 + body.len()) as u32;
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(&body);
    } else if spec.is_ready_for_query {
        // ReadyForQuery ('Z', length 5, status 'I' Idle)
        pkt.push(b'Z');
        pkt.extend_from_slice(&5u32.to_be_bytes());
        pkt.push(b'I');
    } else if spec.is_command_complete {
        // CommandComplete ('C', length, command tag + NUL)
        let tag = spec.sql.unwrap_or("SELECT 1").as_bytes();
        let length = (4 + tag.len() + 1) as u32;
        pkt.push(b'C');
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(tag);
        pkt.push(0);
    } else if spec.is_error_response {
        // ErrorResponse ('E', length, severity + SQLSTATE + message + NUL)
        let msg = spec.sql.unwrap_or("authentication failed").as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(b"SERROR\0C28P01\0M");
        body.extend_from_slice(msg);
        body.push(0);
        body.push(0);
        let length = (4 + body.len()) as u32;
        pkt.push(b'E');
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(&body);
    } else if spec.is_auth_ok {
        // AuthenticationOk ('R', length 8, auth code 0)
        pkt.push(b'R');
        pkt.extend_from_slice(&8u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
    } else {
        // Simple Query ('Q', length, query + NUL)
        let _ = spec.is_query;
        let sql = spec.sql.unwrap_or("SELECT version()");
        let sql_bytes = sql.as_bytes();
        let length = (4 + sql_bytes.len() + 1) as u32;
        pkt.push(b'Q');
        pkt.extend_from_slice(&length.to_be_bytes());
        pkt.extend_from_slice(sql_bytes);
        pkt.push(0);
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
