//! IPsec Encapsulating Security Payload (ESP, RFC 4303) AST definitions.
//!
//! Defines the confidentiality, data origin authentication, connectionless integrity, and anti-replay
//! encapsulation specified in RFC 4303 over IP protocol `50` (`0x32`). An ESP wire packet starts with
//! a 32-bit Security Parameters Index (`SPI`, default `0x1000`) and a 32-bit Sequence Number (`SEQ`,
//! default `1`), followed by an explicit Initialization Vector (`IV`, default 8 zeroed bytes), the
//! encrypted payload data, padding bytes, an 8-bit `Pad Length` (`0`), an 8-bit `Next Header` protocol
//! identifier (`NEXT_HEADER`, default `59` No Next Header), and a trailing Integrity Check Value (`ICV`,
//! default 12-byte HMAC-SHA1-96 digest). Both `IPSEC` and `ESP` keywords map to [`IpsecSpec`].
//!
//! Canonical `.fasm` syntax:
//! `a -> b [IPSEC | ESP] [SPI <u32>] [SEQ <u32>] [IV "<hex>"] [ICV "<hex>"] [NEXT_HEADER <u8>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use alloc::vec::Vec;
use core::marker::PhantomData;

/// IPsec Encapsulating Security Payload (RFC 4303) specification over IP protocol `50`.
///
/// Syntax mapping: `IPSEC [SPI <u32>] [SEQ <u32>] [IV "<hex>"] [ICV "<hex>"] [NEXT_HEADER <u8>]`
#[doc(alias = "IPSEC")]
#[doc(alias = "ESP")]
#[doc(alias = "IPsec")]
#[doc(alias = "RFC 4303")]
#[doc(alias = "RFC4303")]
#[doc(alias = "SPI")]
#[doc(alias = "SEQ")]
#[doc(alias = "IV")]
#[doc(alias = "ICV")]
#[doc(alias = "NEXT_HEADER")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpsecSpec<'a> {
    /// 32-bit Security Parameters Index identifying the target SA (`SPI <u32>`, default `0x1000`).
    pub spi: Option<u32>,
    /// 32-bit anti-replay Sequence Number (`SEQ <u32>`, default `1`).
    pub seq: Option<u32>,
    /// Explicit Initialization Vector octets (`IV "<hex>"`, default 8 zeroed bytes).
    pub iv: Option<Vec<u8>>,
    /// Trailing Integrity Check Value / AEAD authentication tag octets (`ICV "<hex>"`, default 12 zeroed bytes).
    pub icv: Option<Vec<u8>>,
    /// 8-bit encapsulated Next Header protocol number (`NEXT_HEADER <u8>`, default `59` No Next Header).
    pub next_header: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}

/// Type alias for RFC 4303 Encapsulating Security Payload (`ESP`) specification.
///
/// Syntax mapping: `ESP [SPI <u32>] [SEQ <u32>] [IV "<hex>"] [ICV "<hex>"] [NEXT_HEADER <u8>]`
#[doc(alias = "ESP")]
#[doc(alias = "IPSEC")]
#[doc(alias = "RFC 4303")]
#[doc(alias = "RFC4303")]
#[doc(alias = "SPI")]
#[doc(alias = "SEQ")]
#[doc(alias = "IV")]
#[doc(alias = "ICV")]
#[doc(alias = "NEXT_HEADER")]
pub type EspSpec<'a> = IpsecSpec<'a>;
