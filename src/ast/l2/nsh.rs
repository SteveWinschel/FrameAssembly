//! Network Service Header (NSH, RFC 8300) Layer 2 AST definitions.
//!
//! Defines the abstract syntax tree specification for RFC 8300 Service Function Chaining (SFC)
//! Network Service Header frames carried directly over Ethernet II using EtherType `0x894F`.
//! An NSH header consists of a 4-byte Base Header encoding the 2-bit protocol version, `O` OAM
//! flag, 6-bit service hop `TTL` (default `63`), 6-bit length in 4-byte words, 4-bit Metadata
//! Type (`MD Type 1` fixed 16-byte context or `MD Type 2` variable TLVs), and 8-bit Next
//! Protocol (`0x03` Ethernet, `0x01` IPv4, `0x02` IPv6, `0x04` NSH, `0x05` MPLS), followed by a
//! 4-byte Service Path Header (`spi` 24-bit Service Path Identifier and `si` 8-bit Service Index)
//! and optional context headers.
//!
//! Canonical `.frasm` syntax:
//! `a -> b nsh [version <0..3>] [oam] [ttl <0..63>] [mdtype <1|2>] [nextproto <u8|ethernet|ipv4|ipv6|nsh|mpls>] [spi <u24>] [si <u8>] [context <hex>]`

use alloc::vec::Vec;

/// Network Service Header (RFC 8300, EtherType `0x894F`) frame specification.
///
/// Syntax mapping: `nsh [version <0..3>] [oam] [ttl <0..63>] [mdtype <1|2>] [nextproto <u8|ethernet|ipv4|ipv6|nsh|mpls>] [spi <u24>] [si <u8>] [context <hex>]`
#[doc(alias = "nsh")]
#[doc(alias = "RFC 8300")]
#[doc(alias = "RFC8300")]
#[doc(alias = "SFC")]
#[doc(alias = "0x894F")]
#[doc(alias = "oam")]
#[doc(alias = "mdtype")]
#[doc(alias = "nextproto")]
#[doc(alias = "spi")]
#[doc(alias = "si")]
#[doc(alias = "context")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NshSpec {
    /// 2-bit NSH protocol version (`version <0..3>`, default `0`).
    pub version: Option<u8>,
    /// OAM packet indicator bit in the NSH Base Header (`oam`, default `false`).
    pub oam: bool,
    /// 6-bit NSH service hop Time-to-Live (`ttl <0..63>`, default `63` per RFC 8300).
    pub ttl: Option<u8>,
    /// 4-bit Metadata Type (`mdtype <1|2>`: `1` fixed 16-byte context, `2` variable TLV context).
    pub md_type: Option<u8>,
    /// 8-bit encapsulated inner Next Protocol (`nextproto <u8>`, default `0x03` Ethernet).
    pub next_proto: Option<u8>,
    /// 24-bit Service Path Identifier (`spi <0..16777215>`, default `1`).
    pub spi: Option<u32>,
    /// 8-bit Service Index (`si <0..255>`, default `255` per RFC 8300).
    pub si: Option<u8>,
    /// Fixed 16-byte (`mdtype 1`) or 4-byte-aligned variable (`mdtype 2`) metadata context (`context <hex>`).
    pub context: Option<Vec<u8>>,
}
