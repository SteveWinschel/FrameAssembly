//! IPsec Encapsulating Security Payload (ESP, RFC 4303) protocol alias AST definitions.
//!
//! Re-exports the [`EspSpec`] (an alias of [`super::ipsec::IpsecSpec`]) representing RFC 4303 IPsec
//! Encapsulating Security Payload packets transmitted over IP protocol `50` (`0x32`). ESP provides
//! confidentiality, data origin authentication, connectionless integrity, anti-replay service, and
//! limited traffic flow confidentiality in both transport mode and tunnel mode. Wire frames contain
//! a 32-bit Security Parameters Index (`spi`), a 32-bit Sequence Number (`seq`), an Initialization
//! Vector (`iv`), encrypted payload octets, padding, an 8-bit `Pad Length`, an 8-bit `Next Header`
//! (`nextheader`), and a trailing Integrity Check Value (`icv`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b esp [spi <u32>] [seq <u32>] [iv "<hex>"] [icv "<hex>"] [nextheader <u8>] [payload "<str>" | hexpayload "<hex>"]`

#[doc(inline)]
pub use super::ipsec::EspSpec;
