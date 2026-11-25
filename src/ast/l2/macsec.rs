//! IEEE 802.1AE MAC Security (MACsec) Abstract Syntax Tree (AST) definitions.
//!
//! Defines the AST specification for IEEE 802.1AE Media Access Control Security (`macsec`) frames
//! encapsulated in Ethernet II (`EtherType = 0x88E5`). On the wire, each frame prepends an
//! 8-byte or 16-byte Security Tag (`SecTAG`) immediately after the outer Ethernet header—packing
//! Tag Control Information (`tci`), 2-bit Association Number (`an`), 6-bit Short Length (`sl`),
//! 32-bit Packet Number (`pn`), and an optional 64-bit Secure Channel Identifier (`sci`)—ahead
//! of the protected user data and a trailing 16-byte Integrity Check Value (`icv`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b macsec [tci <u8>] [an <0..=3>] [sl <0..=63>] [pn <u32>] [sci <u64>] [icv "<hex>"] [payload "<str>" | hexpayload "<hex>"]`

use alloc::vec::Vec;

/// IEEE 802.1AE MAC Security (`macsec`, EtherType `0x88E5`) frame specification.
///
/// Syntax mapping: `macsec [tci <u8>] [an <0..=3>] [sl <0..=63>] [pn <u32>] [sci <u64>] [icv "<hex>"]`
#[doc(alias = "macsec")]
#[doc(alias = "802.1AE")]
#[doc(alias = "SecTAG")]
#[doc(alias = "0x88E5")]
#[doc(alias = "tci")]
#[doc(alias = "an")]
#[doc(alias = "sl")]
#[doc(alias = "pn")]
#[doc(alias = "sci")]
#[doc(alias = "icv")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacsecSpec {
    /// Upper 6 bits of SecTAG byte 0 (`V | ES | SC | SCB | E | C`, `tci <u8>`, default `0x2C`).
    pub tci: Option<u8>,
    /// 2-bit Association Number (`an <0..=3>`, default `0`).
    pub an: Option<u8>,
    /// 6-bit Short Length for protected frames under 48 octets (`sl <0..=63>`, default `0`).
    pub sl: Option<u8>,
    /// 32-bit replay-protection Packet Number (`pn <u32>`, default `1`).
    pub pn: Option<u32>,
    /// Optional 64-bit Secure Channel Identifier (`sci <u64>`, default `src_mac || 0x0001` when `SC` is set).
    pub sci: Option<u64>,
    /// 16-byte Integrity Check Value tag (`icv "<hex>"`, zero-padded or truncated to 16 bytes, default all-zero).
    pub icv: Option<Vec<u8>>,
}
