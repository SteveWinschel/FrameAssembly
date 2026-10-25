//! Redis Serialization Protocol (RESP2/RESP3) wire payload builder.
//!
//! This module implements [`build_redis_payload`], which serializes a [`RedisSpec`]
//! AST node into a Redis Serialization Protocol (RESP) byte stream over TCP port 6379 (or 26379 for
//! Redis Sentinel). When `REPLY_TYPE` is set, it formats server replies as Simple Strings
//! (`+<val>\r\n`), Errors (`-ERR <val>\r\n`), Integers (`:<n>\r\n`), or Bulk Strings
//! (`$<len>\r\n<val>\r\n`); otherwise it encodes client commands and whitespace-separated `ARGS`
//! as a RESP Array of Bulk Strings (`*<argc>\r\n$<len>\r\n...`).

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
    if let Some(rt) = spec.reply_type {
        let rt_upper = rt.trim().to_ascii_uppercase();
        match rt_upper.as_str() {
            "+" | "SIMPLE" | "STATUS" | "OK" => {
                let val = spec.value.unwrap_or("OK");
                out.push_str(&format!("+{}\r\n", val));
            }
            "-" | "ERROR" | "ERR" => {
                let val = spec.value.unwrap_or("ERR unknown command");
                if val.starts_with("ERR") {
                    out.push_str(&format!("-{}\r\n", val));
                } else {
                    out.push_str(&format!("-ERR {}\r\n", val));
                }
            }
            ":" | "INT" | "INTEGER" => {
                let val = spec.value.unwrap_or("1");
                out.push_str(&format!(":{}\r\n", val));
            }
            "$" | "BULK" => {
                let val = spec.value.unwrap_or("");
                out.push_str(&format!("${}\r\n{}\r\n", val.len(), val));
            }
            _ => {
                let val = spec.value.unwrap_or("OK");
                out.push_str(&format!("+{}\r\n", val));
            }
        }
    } else if spec.cmd.is_some() || !spec.args.is_empty() || spec.value.is_some() {
        let mut parts = Vec::new();
        parts.push(spec.cmd.unwrap_or("SET"));
        for arg in &spec.args {
            parts.push(arg);
        }
        if let Some(val) = spec.value {
            parts.push(val);
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
