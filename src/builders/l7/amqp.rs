//! AMQP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an AMQP 0-9-1 protocol header or frame payload.
pub fn build_amqp_payload(
    _ctx: &WireContext,
    _spec: &AmqpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = b"AMQP\x00\x00\x09\x01".to_vec();
    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
