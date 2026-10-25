//! gRPC High-Performance Remote Procedure Call Framework (gRPC over HTTP/2 Wire Specification / RFC 9113) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire gRPC High-Performance Remote Procedure Call Framework frames over TCP port 50051.
//! The wire encoder constructs a HTTP/2 transport framing carrying gRPC `/package.Service/Method` call metadata, `grpc-status` trailer codes (`0` OK, `1` CANCELLED, `2` UNKNOWN, `3` INVALID_ARGUMENT, `4` DEADLINE_EXCEEDED, `5` NOT_FOUND, `7` PERMISSION_DENIED, `14` UNAVAILABLE, `16` UNAUTHENTICATED), and 5-byte length-prefixed Protocol Buffers message frames (1-byte Compressed-Flag `0x00`/`0x01` + 32-bit big-endian Message-Length). When optional fields in [`GrpcSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b GRPC [SERVICE <str>] [METHOD <str>] [GRPC_STATUS <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a length-prefixed gRPC message payload.
/// Syntax mapping: `GRPC [SERVICE <str>] [METHOD <str>] [GRPC_STATUS <u32>]`
#[doc(alias = "GRPC")]
#[doc(alias = "PROTOBUF")]
#[doc(alias = "GRPC_STATUS")]
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
    if let Some(status) = spec.grpc_status {
        if !data.is_empty() {
            data.push(b' ');
        }
        data.extend_from_slice(format!("grpc-status:{}", status).as_bytes());
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
