//! GRPC protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a length-prefixed gRPC message payload.
pub fn build_grpc_payload(
    _ctx: &WireContext,
    spec: &GrpcSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    if let Some(service) = spec.service {
        data.extend_from_slice(service.as_bytes());
        data.push(b'/');
    }
    if let Some(method) = spec.method {
        data.extend_from_slice(method.as_bytes());
    }
    if !payload_bytes.is_empty() {
        data.extend_from_slice(payload_bytes);
    }

    let length = data.len() as u32;
    let mut pkt = Vec::with_capacity(5 + data.len());
    pkt.push(0); // Compressed flag = 0 (uncompressed)
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.extend_from_slice(&data);
    pkt
}
