//! gRPC High-Performance Remote Procedure Call Framework (gRPC over HTTP/2 Wire Specification / RFC 9113) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire gRPC High-Performance Remote Procedure Call Framework frames over TCP port 50051.
//! The wire encoder constructs a HTTP/2 transport framing carrying gRPC `/package.Service/Method` call metadata, `grpc-status` trailer codes (`0` OK, `1` CANCELLED, `2` UNKNOWN, `3` INVALID_ARGUMENT, `4` DEADLINE_EXCEEDED, `5` NOT_FOUND, `7` PERMISSION_DENIED, `14` UNAVAILABLE, `16` UNAUTHENTICATED), and 5-byte length-prefixed Protocol Buffers message frames (1-byte Compressed-Flag `0x00`/`0x01` + 32-bit big-endian Message-Length). When optional fields in [`GrpcSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b grpc [service <str>] [method <str>] [grpcstatus <u32>]`

use super::http2::{encode_hpack_headers, format_authority, push_http2_frame};
use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Returns `true` when the gRPC frame originates from the server side of the connection.
fn is_grpc_server_src(ctx: &WireContext) -> bool {
    let grpc_port = |p: u16| matches!(p, 50051 | 443 | 80 | 8080 | 8443);
    (grpc_port(ctx.src_port) && !grpc_port(ctx.dst_port))
        || (ctx.src_port < 1024 && ctx.dst_port >= 1024)
}

/// Builds a gRPC message payload framed inside RFC 9113 HTTP/2 `HEADERS` and `DATA` frames.
/// Syntax mapping: `grpc [service <str>] [method <str>] [grpcstatus <u32>]`
#[doc(alias = "GRPC")]
#[doc(alias = "PROTOBUF")]
#[doc(alias = "GRPC_STATUS")]
pub fn build_grpc_payload(
    ctx: &WireContext,
    spec: &GrpcSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let stream_id = 1u32;
    let send_response_headers =
        is_grpc_server_src(ctx) && spec.service.is_none() && spec.method.is_none();

    let opening_hpack = if send_response_headers {
        encode_hpack_headers(&[(":status", "200"), ("content-type", "application/grpc")])
    } else {
        let is_tls = ctx.dst_port == 443 || ctx.src_port == 443 || ctx.dst_port == 8443;
        let scheme = if is_tls { "https" } else { "http" };
        let svc = spec.service.unwrap_or("grpc.Service").trim_matches('/');
        let meth = spec.method.unwrap_or("Call").trim_matches('/');
        let path = format!("/{}/{}", svc, meth);
        let authority = format_authority(ctx.dst_ip, ctx.dst_port, is_tls);
        encode_hpack_headers(&[
            (":method", "POST"),
            (":scheme", scheme),
            (":path", &path),
            (":authority", &authority),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ])
    };

    let mut pkt = Vec::new();
    push_http2_frame(&mut pkt, 1, 0x04, stream_id, &opening_hpack);

    let msg_len = payload_bytes.len() as u32;
    let mut lpm = Vec::with_capacity(5 + payload_bytes.len());
    lpm.push(0x00); // Compressed-Flag = 0 (uncompressed)
    lpm.extend_from_slice(&msg_len.to_be_bytes());
    lpm.extend_from_slice(payload_bytes);

    let data_flags = if spec.grpc_status.is_some() { 0x00 } else { 0x01 };
    push_http2_frame(&mut pkt, 0, data_flags, stream_id, &lpm);

    if let Some(status) = spec.grpc_status {
        let status_str = status.to_string();
        let trailer_hpack = encode_hpack_headers(&[("grpc-status", &status_str)]);
        push_http2_frame(&mut pkt, 1, 0x05, stream_id, &trailer_hpack);
    }

    pkt
}
