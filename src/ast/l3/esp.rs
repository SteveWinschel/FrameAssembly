//! IPsec Encapsulating Security Payload (ESP, RFC 4303) protocol alias AST definitions.
//!
//! Re-exports the [`EspSpec`] (an alias of [`super::ipsec::IpsecSpec`]) representing RFC 4303 IPsec
//! Encapsulating Security Payload packets transmitted over IP protocol `50` (`0x32`). ESP provides
//! confidentiality, data origin authentication, connectionless integrity, anti-replay service, and
//! limited traffic flow confidentiality in both transport mode and tunnel mode. Wire frames contain
//! a 32-bit Security Parameters Index (`SPI`), a 32-bit Sequence Number (`SEQ`), an Initialization
//! Vector (`IV`), encrypted payload octets, padding, an 8-bit `Pad Length`, an 8-bit `Next Header`
//! (`NEXT_HEADER`), and a trailing Integrity Check Value (`ICV`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b ESP [SPI <u32>] [SEQ <u32>] [IV "<hex>"] [ICV "<hex>"] [NEXT_HEADER <u8>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

#[doc(inline)]
pub use super::ipsec::EspSpec;
