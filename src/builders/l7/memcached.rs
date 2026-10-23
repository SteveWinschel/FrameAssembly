//! MEMCACHED protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a Memcached text or binary protocol packet payload.
pub fn build_memcached_payload(
    _ctx: &WireContext,
    spec: &MemcachedSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut bytes = if let Some(cmd) = spec.cmd {
        let key = spec.key.unwrap_or("key");
        format!("{} {}\r\n", cmd.to_ascii_lowercase(), key).into_bytes()
    } else if let Some(key) = spec.key {
        format!("get {}\r\n", key).into_bytes()
    } else {
        b"get key\r\n".to_vec()
    };

    if !payload_bytes.is_empty() {
        bytes.extend_from_slice(payload_bytes);
    }
    bytes
}
