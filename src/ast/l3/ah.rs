//! IPsec Authentication Header (AH, RFC 4302) AST definitions.
//!
//! Defines the connectionless integrity, data origin authentication, and anti-replay protection
//! header specified in RFC 4302 (obsoleting RFC 2402) over IP protocol `51` (`0x33`). The variable-length
//! AH wire header consists of an 8-bit `Next Header` selector (`nextheader`, default `59` No Next Header),
//! an 8-bit `Payload Len` in 32-bit words minus 2 (`4` for a 24-byte header), a 16-bit zeroed `Reserved`
//! field, a 32-bit Security Parameters Index (`spi`, default `0x2000`), a 32-bit monotonically increasing
//! Sequence Number (`seq`, default `1`), and a variable-length Integrity Check Value (`icv`, default 96-bit
//! HMAC digest) followed by the authenticated upper-layer payload.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ah [spi <u32>] [seq <u32>] [icv "<hex>"] [nextheader <u8>] [payload "<str>" | hexpayload "<hex>"]`

use alloc::vec::Vec;
use core::marker::PhantomData;

/// IPsec Authentication Header (RFC 4302) specification over IP protocol `51`.
///
/// Syntax mapping: `ah [spi <u32>] [seq <u32>] [icv "<hex>"] [nextheader <u8>]`
#[doc(alias = "ah")]
#[doc(alias = "RFC 4302")]
#[doc(alias = "RFC4302")]
#[doc(alias = "IPsec")]
#[doc(alias = "spi")]
#[doc(alias = "seq")]
#[doc(alias = "icv")]
#[doc(alias = "nextheader")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AhSpec<'a> {
    /// 32-bit Security Parameters Index identifying the Security Association (`spi <u32>`, default `0x2000`).
    pub spi: Option<u32>,
    /// 32-bit anti-replay Sequence Number counter (`seq <u32>`, default `1`).
    pub seq: Option<u32>,
    /// Variable-length Integrity Check Value digest bytes (`icv "<hex>"`, default 12 zeroed octets).
    pub icv: Option<Vec<u8>>,
    /// 8-bit Next Header protocol number (`nextheader <u8>`, default `59` IPv6-NoNxt).
    pub next_header: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
