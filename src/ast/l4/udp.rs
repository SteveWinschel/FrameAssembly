//! User Datagram Protocol (UDP, RFC 768) AST definitions.
//!
//! Defines the abstract syntax tree marker for RFC 768 User Datagram Protocol connectionless
//! datagrams encapsulated over IPv4 or IPv6 using IP Protocol number `17` (`0x11`). The 8-byte
//! UDP header consists of a 16-bit Source Port (`SRCPORT`), 16-bit Destination Port (`DSTPORT`),
//! 16-bit Total Length (8-byte header plus payload length in bytes), and a 16-bit one's
//! complement Checksum computed over the IP pseudo-header, UDP header, and payload.
//!
//! Canonical `.fasm` syntax:
//! `a -> b UDP [SRCPORT <u16>] [DSTPORT <u16>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

/// User Datagram Protocol (RFC 768) specification.
///
/// Syntax mapping: `UDP [SRCPORT <u16>] [DSTPORT <u16>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`
#[doc(alias = "UDP")]
#[doc(alias = "RFC 768")]
#[doc(alias = "RFC768")]
#[doc(alias = "proto 17")]
#[doc(alias = "SRCPORT")]
#[doc(alias = "DSTPORT")]
#[doc(alias = "PAYLOAD")]
#[doc(alias = "HEXPAYLOAD")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UdpSpec;
