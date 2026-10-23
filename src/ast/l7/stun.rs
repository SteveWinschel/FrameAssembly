//! STUN protocol AST definitions.

use core::net::IpAddr;
/// RFC 8489 Session Traversal Utilities for NAT specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StunSpec<'a> {
    /// Binding Request flag.
    pub is_binding_request: bool,
    /// Binding Response flag.
    pub is_binding_response: bool,
    /// Binding Error Response flag.
    pub is_binding_error: bool,
    /// Transaction ID.
    pub txid: Option<u32>,
    /// XOR-MAPPED-ADDRESS attribute IP.
    pub xor_mapped_addr: Option<IpAddr>,
    /// Software description string.
    pub software: Option<&'a str>,
}
