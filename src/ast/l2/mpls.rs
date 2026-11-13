//! Multi-Protocol Label Switching (MPLS, RFC 3032 / RFC 5462) AST definitions.
//!
//! Defines the 32-bit MPLS label stack entry structure used both as a Layer 2.5 shim modifier
//! on IP/transport frames and as a standalone Layer 2 protocol over EtherType `0x8847` (MPLS
//! unicast). Per RFC 3032 §2.1, the 4-byte label stack entry packs a 20-bit Label value
//! (bits 0..19), a 3-bit Traffic Class / Experimental field (`tc` / `exp`, bits 20..22,
//! RFC 5462), a 1-bit Bottom of Stack indicator (`S` / `bos`, bit 23), and an 8-bit
//! Time To Live field (`ttl`, bits 24..31).
//!
//! Canonical `.frasm` syntax:
//! `a -> b mpls <label> [exp <0..7>] [bos <0|1>] [mplsttl <u8>] [<inner_protocol>...]`

/// RFC 3032 / RFC 5462 32-bit MPLS label stack entry specification.
///
/// Syntax mapping: `mpls <label> [exp <0..7>] [bos <0|1>] [mplsttl <u8>]`
#[doc(alias = "mpls")]
#[doc(alias = "RFC 3032")]
#[doc(alias = "RFC 5462")]
#[doc(alias = "0x8847")]
#[doc(alias = "exp")]
#[doc(alias = "bos")]
#[doc(alias = "mplsttl")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsSpec {
    /// 20-bit MPLS label value (`0..=1_048_575`, where `0..=15` are reserved special-purpose labels).
    pub label: u32,
    /// 3-bit Traffic Class / Experimental bits (`exp <0..7>`, default `0`).
    pub exp: Option<u8>,
    /// 1-bit Bottom-of-Stack flag (`bos <0|1>`, default `1` indicating the innermost label).
    pub bos: Option<u8>,
    /// 8-bit MPLS Time-to-Live (`mplsttl <u8>`, default `64`).
    pub ttl: Option<u8>,
}
