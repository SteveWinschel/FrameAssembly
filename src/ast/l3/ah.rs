//! IPsec Authentication Header (AH, RFC 4302) AST definitions.
//!
//! Defines the connectionless integrity, data origin authentication, and anti-replay protection
//! header specified in RFC 4302 (obsoleting RFC 2402) over IP protocol `51` (`0x33`). The variable-length
//! AH wire header consists of an 8-bit `Next Header` selector (`NEXT_HEADER`, default `59` No Next Header),
//! an 8-bit `Payload Len` in 32-bit words minus 2 (`4` for a 24-byte header), a 16-bit zeroed `Reserved`
//! field, a 32-bit Security Parameters Index (`SPI`, default `0x2000`), a 32-bit monotonically increasing
//! Sequence Number (`SEQ`, default `1`), and a variable-length Integrity Check Value (`ICV`, default 96-bit
//! HMAC digest) followed by the authenticated upper-layer payload.
//!
//! Canonical `.fasm` syntax:
//! `a -> b AH [SPI <u32>] [SEQ <u32>] [ICV "<hex>"] [NEXT_HEADER <u8>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use alloc::vec::Vec;
use core::marker::PhantomData;

/// IPsec Authentication Header (RFC 4302) specification over IP protocol `51`.
///
/// Syntax mapping: `AH [SPI <u32>] [SEQ <u32>] [ICV "<hex>"] [NEXT_HEADER <u8>]`
#[doc(alias = "AH")]
#[doc(alias = "RFC 4302")]
#[doc(alias = "RFC4302")]
#[doc(alias = "IPsec")]
#[doc(alias = "SPI")]
#[doc(alias = "SEQ")]
#[doc(alias = "ICV")]
#[doc(alias = "NEXT_HEADER")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AhSpec<'a> {
    /// 32-bit Security Parameters Index identifying the Security Association (`SPI <u32>`, default `0x2000`).
    pub spi: Option<u32>,
    /// 32-bit anti-replay Sequence Number counter (`SEQ <u32>`, default `1`).
    pub seq: Option<u32>,
    /// Variable-length Integrity Check Value digest bytes (`ICV "<hex>"`, default 12 zeroed octets).
    pub icv: Option<Vec<u8>>,
    /// 8-bit Next Header protocol number (`NEXT_HEADER <u8>`, default `59` IPv6-NoNxt).
    pub next_header: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
