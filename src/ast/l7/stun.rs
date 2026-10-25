//! Session Traversal Utilities for NAT (STUN) (RFC 8489 / RFC 5389 / RFC 8445 (ICE) / RFC 8656 (TURN)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Session Traversal Utilities for NAT (STUN) packets over UDP port 3478 (and WebRTC port 19302). On the wire, the protocol uses a 20-byte fixed STUN message header containing 16-bit STUN Message Type (`0x0001` Binding Request, `0x0101` Binding Success Response, `0x0111` Binding Error Response), 16-bit Message Length (excluding 20-byte header), 32-bit Magic Cookie `0x2112A442`, and 96-bit Transaction ID, followed by 4-byte-aligned TLV attributes (`0x0020` XOR-MAPPED-ADDRESS and `0x8022` SOFTWARE).
//! Every field in [`StunSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b STUN [BINDING_REQUEST | BINDING_RESPONSE | BINDING_ERROR] [TXID <u32>] [XOR_MAPPED_ADDR <ip>] [SOFTWARE <str>]`

use core::net::IpAddr;
/// RFC 8489 Session Traversal Utilities for NAT specification.
///
/// Syntax mapping: `STUN [BINDING_REQUEST | BINDING_RESPONSE | BINDING_ERROR] [TXID <u32>] [XOR_MAPPED_ADDR <ip>] [SOFTWARE <str>]`
#[doc(alias = "STUN")]
#[doc(alias = "TURN")]
#[doc(alias = "ICE")]
#[doc(alias = "RFC 8489")]
#[doc(alias = "RFC8489")]
#[doc(alias = "RFC 5389")]
#[doc(alias = "RFC5389")]
#[doc(alias = "BINDING_REQUEST")]
#[doc(alias = "BINDING_RESPONSE")]
#[doc(alias = "BINDING_ERROR")]
#[doc(alias = "TXID")]
#[doc(alias = "XOR_MAPPED_ADDR")]
#[doc(alias = "SOFTWARE")]
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
