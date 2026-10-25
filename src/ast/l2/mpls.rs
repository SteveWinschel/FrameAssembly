//! Multi-Protocol Label Switching (MPLS, RFC 3032 / RFC 5462) AST definitions.
//!
//! Defines the 32-bit MPLS label stack entry structure used both as a Layer 2.5 shim modifier
//! on IP/transport frames and as a standalone Layer 2 protocol over EtherType `0x8847` (MPLS
//! unicast). Per RFC 3032 §2.1, the 4-byte label stack entry packs a 20-bit Label value
//! (bits 0..19), a 3-bit Traffic Class / Experimental field (`TC` / `EXP`, bits 20..22,
//! RFC 5462), a 1-bit Bottom of Stack indicator (`S` / `BOS`, bit 23), and an 8-bit
//! Time To Live field (`TTL`, bits 24..31).
//!
//! Canonical `.fasm` syntax:
//! `a -> b MPLS <label> [EXP <0..7>] [BOS <0|1>] [MPLS_TTL <u8>] [<inner_protocol>...]`

/// RFC 3032 / RFC 5462 32-bit MPLS label stack entry specification.
///
/// Syntax mapping: `MPLS <label> [EXP <0..7>] [BOS <0|1>] [MPLS_TTL <u8>]`
#[doc(alias = "MPLS")]
#[doc(alias = "RFC 3032")]
#[doc(alias = "RFC 5462")]
#[doc(alias = "0x8847")]
#[doc(alias = "EXP")]
#[doc(alias = "BOS")]
#[doc(alias = "MPLS_TTL")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsSpec {
    /// 20-bit MPLS label value (`0..=1_048_575`, where `0..=15` are reserved special-purpose labels).
    pub label: u32,
    /// 3-bit Traffic Class / Experimental bits (`EXP <0..7>`, default `0`).
    pub exp: Option<u8>,
    /// 1-bit Bottom-of-Stack flag (`BOS <0|1>`, default `1` indicating the innermost label).
    pub bos: Option<u8>,
    /// 8-bit MPLS Time-to-Live (`MPLS_TTL <u8>`, default `64`).
    pub ttl: Option<u8>,
}
