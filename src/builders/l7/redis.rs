//! REDIS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a Redis Serialization Protocol (RESP) command or reply.
pub fn build_redis_payload(
    _ctx: &WireContext,
    spec: &RedisSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut out = String::new();
    if let Some(cmd) = spec.cmd {
        let mut parts = Vec::new();
        parts.push(cmd);
        for arg in &spec.args {
            parts.push(arg);
        }
        out.push_str(&format!("*{}\r\n", parts.len()));
        for part in parts {
            out.push_str(&format!("${}\r\n{}\r\n", part.len(), part));
        }
    } else {
        out.push_str("*1\r\n$4\r\nPING\r\n");
    }

    let mut bytes = out.into_bytes();
    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
