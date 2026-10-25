//! gRPC High-Performance Remote Procedure Call Framework (gRPC over HTTP/2 Wire Specification / RFC 9113) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! gRPC High-Performance Remote Procedure Call Framework packets over TCP port 50051. On the wire, the protocol uses a HTTP/2 transport framing carrying gRPC `/package.Service/Method` call metadata, `grpc-status` trailer codes (`0` OK, `1` CANCELLED, `2` UNKNOWN, `3` INVALID_ARGUMENT, `4` DEADLINE_EXCEEDED, `5` NOT_FOUND, `7` PERMISSION_DENIED, `14` UNAVAILABLE, `16` UNAUTHENTICATED), and 5-byte length-prefixed Protocol Buffers message frames (1-byte Compressed-Flag `0x00`/`0x01` + 32-bit big-endian Message-Length).
//! Every field in [`GrpcSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b GRPC [SERVICE <str>] [METHOD <str>] [GRPC_STATUS <u32>]`

/// gRPC remote procedure call framing specification.
///
/// Syntax mapping: `GRPC [SERVICE <str>] [METHOD <str>] [GRPC_STATUS <u32>]`
#[doc(alias = "GRPC")]
#[doc(alias = "gRPC")]
#[doc(alias = "RFC 9113")]
#[doc(alias = "RFC9113")]
#[doc(alias = "PROTOBUF")]
#[doc(alias = "SERVICE")]
#[doc(alias = "METHOD")]
#[doc(alias = "GRPC_STATUS")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrpcSpec<'a> {
    /// Service name string (`SERVICE <str>`).
    pub service: Option<&'a str>,
    /// Method name string (`METHOD <str>`).
    pub method: Option<&'a str>,
    /// Status code (`GRPC_STATUS <u32>`).
    pub grpc_status: Option<u32>,
}
