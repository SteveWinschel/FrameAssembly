//! Memcached Binary and ASCII Caching Protocol wire payload builder.
//!
//! This module implements [`build_memcached_payload`], which serializes a [`MemcachedSpec`]
//! AST node into a Memcached wire frame over TCP or UDP port 11211. When `OPAQUE` or `CAS` is
//! specified, it emits a 24-byte Memcached Binary Protocol request header (`0x80` magic, opcode,
//! key length, extras length, total body length, opaque token, and 64-bit CAS) followed by extras,
//! key, and value bytes; otherwise it formats a human-readable ASCII storage or retrieval command
//! (`set`, `add`, `replace`, `get`, `gets`, `delete`) terminated by `\r\n`.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a Memcached text or binary protocol packet payload.
pub fn build_memcached_payload(
    _ctx: &WireContext,
    spec: &MemcachedSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    if spec.opcode.is_some() || spec.opaque.is_some() || spec.cas.is_some() {
        let cmd_upper = spec.cmd.unwrap_or("GET").to_ascii_uppercase();
        let opcode = spec.opcode.unwrap_or(match cmd_upper.as_str() {
            "GET" => 0x00,
            "SET" => 0x01,
            "ADD" => 0x02,
            "REPLACE" => 0x03,
            "DELETE" => 0x04,
            "INCREMENT" | "INCR" => 0x05,
            "DECREMENT" | "DECR" => 0x06,
            "QUIT" => 0x07,
            "FLUSH" | "FLUSH_ALL" => 0x08,
            "NOOP" => 0x0A,
            "VERSION" => 0x0B,
            "APPEND" => 0x0E,
            "PREPEND" => 0x0F,
            "STAT" | "STATS" => 0x10,
            _ => 0x00,
        });

        let key_bytes = spec
            .key
            .unwrap_or(if matches!(opcode, 0x07 | 0x08 | 0x0A | 0x0B | 0x10) {
                ""
            } else {
                "key"
            })
            .as_bytes();

        let val_bytes: &[u8] = if let Some(v) = spec.value {
            v.as_bytes()
        } else {
            payload_bytes
        };

        let mut extras = Vec::new();
        if matches!(opcode, 0x01..=0x03) || spec.flags.is_some() || spec.exptime.is_some() {
            extras.extend_from_slice(&spec.flags.unwrap_or(0).to_be_bytes());
            extras.extend_from_slice(&spec.exptime.unwrap_or(0).to_be_bytes());
        }

        let total_body_len = (extras.len() + key_bytes.len() + val_bytes.len()) as u32;
        let mut pkt = Vec::with_capacity(24 + total_body_len as usize);
        pkt.push(0x80); // Request magic
        pkt.push(opcode);
        pkt.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        pkt.push(extras.len() as u8);
        pkt.push(0x00); // Data type: raw bytes
        pkt.extend_from_slice(&0u16.to_be_bytes()); // vbucket id
        pkt.extend_from_slice(&total_body_len.to_be_bytes());
        pkt.extend_from_slice(&spec.opaque.unwrap_or(0).to_be_bytes());
        pkt.extend_from_slice(&spec.cas.unwrap_or(0).to_be_bytes());
        pkt.extend_from_slice(&extras);
        pkt.extend_from_slice(key_bytes);
        pkt.extend_from_slice(val_bytes);
        if spec.value.is_some() && !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
        return pkt;
    }

    let is_storage_fields =
        spec.flags.is_some() || spec.exptime.is_some() || spec.value.is_some();
    let cmd_lower = spec
        .cmd
        .unwrap_or(if is_storage_fields { "set" } else { "get" })
        .to_ascii_lowercase();

    if matches!(
        cmd_lower.as_str(),
        "set" | "add" | "replace" | "append" | "prepend"
    ) || is_storage_fields
    {
        let key = spec.key.unwrap_or("key");
        let flags = spec.flags.unwrap_or(0);
        let exptime = spec.exptime.unwrap_or(0);
        let val_bytes: &[u8] = if let Some(v) = spec.value {
            v.as_bytes()
        } else {
            payload_bytes
        };
        let mut bytes = format!(
            "{} {} {} {} {}\r\n",
            cmd_lower,
            key,
            flags,
            exptime,
            val_bytes.len()
        )
        .into_bytes();
        bytes.extend_from_slice(val_bytes);
        bytes.extend_from_slice(b"\r\n");
        if spec.value.is_some() && !payload_bytes.is_empty() {
            bytes.extend_from_slice(payload_bytes);
        }
        return bytes;
    }

    let mut bytes = if matches!(
        cmd_lower.as_str(),
        "stats" | "version" | "flush_all" | "quit"
    ) && spec.key.is_none()
    {
        format!("{}\r\n", cmd_lower).into_bytes()
    } else {
        let key = spec.key.unwrap_or("key");
        format!("{} {}\r\n", cmd_lower, key).into_bytes()
    };

    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
