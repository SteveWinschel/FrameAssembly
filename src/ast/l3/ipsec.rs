//! IPsec Encapsulating Security Payload (ESP, RFC 4303) AST definitions.
//!
//! Defines the confidentiality, data origin authentication, connectionless integrity, and anti-replay
//! encapsulation specified in RFC 4303 over IP protocol `50` (`0x32`). An ESP wire packet starts with
//! a 32-bit Security Parameters Index (`spi`, default `0x1000`) and a 32-bit Sequence Number (`seq`,
//! default `1`), followed by an explicit Initialization Vector (`iv`, default 8 zeroed bytes), the
//! encrypted payload data, padding bytes, an 8-bit `Pad Length` (`0`), an 8-bit `Next Header` protocol
//! identifier (`nextheader`, default `59` No Next Header), and a trailing Integrity Check Value (`icv`,
//! default 12-byte HMAC-SHA1-96 digest). Both `ipsec` and `esp` keywords map to [`IpsecSpec`].
//!
//! Canonical `.frasm` syntax:
//! `a -> b [ipsec | esp] [spi <u32>] [seq <u32>] [iv "<hex>"] [icv "<hex>"] [nextheader <u8>] [payload "<str>" | hexpayload "<hex>"]`

use alloc::vec::Vec;
use core::marker::PhantomData;

/// IPsec Encapsulating Security Payload (RFC 4303) specification over IP protocol `50`.
///
/// Syntax mapping: `ipsec [spi <u32>] [seq <u32>] [iv "<hex>"] [icv "<hex>"] [nextheader <u8>]`
#[doc(alias = "ipsec")]
#[doc(alias = "esp")]
#[doc(alias = "IPsec")]
#[doc(alias = "RFC 4303")]
#[doc(alias = "RFC4303")]
#[doc(alias = "spi")]
#[doc(alias = "seq")]
#[doc(alias = "iv")]
#[doc(alias = "icv")]
#[doc(alias = "nextheader")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpsecSpec<'a> {
    /// 32-bit Security Parameters Index identifying the target SA (`spi <u32>`, default `0x1000`).
    pub spi: Option<u32>,
    /// 32-bit anti-replay Sequence Number (`seq <u32>`, default `1`).
    pub seq: Option<u32>,
    /// Explicit Initialization Vector octets (`iv "<hex>"`, default 8 zeroed bytes).
    pub iv: Option<Vec<u8>>,
    /// Trailing Integrity Check Value / AEAD authentication tag octets (`icv "<hex>"`, default 12 zeroed bytes).
    pub icv: Option<Vec<u8>>,
    /// 8-bit encapsulated Next Header protocol number (`nextheader <u8>`, default `59` No Next Header).
    pub next_header: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}

/// Type alias for RFC 4303 Encapsulating Security Payload (`esp`) specification.
///
/// Syntax mapping: `esp [spi <u32>] [seq <u32>] [iv "<hex>"] [icv "<hex>"] [nextheader <u8>]`
#[doc(alias = "esp")]
#[doc(alias = "ipsec")]
#[doc(alias = "RFC 4303")]
#[doc(alias = "RFC4303")]
#[doc(alias = "spi")]
#[doc(alias = "seq")]
#[doc(alias = "iv")]
#[doc(alias = "icv")]
#[doc(alias = "nextheader")]
pub type EspSpec<'a> = IpsecSpec<'a>;
