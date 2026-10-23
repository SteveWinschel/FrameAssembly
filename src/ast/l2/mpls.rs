//! Multi-Protocol Label Switching (MPLS) AST definitions.

/// RFC 3032 MPLS label stack entry specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MplsSpec {
    /// 20-bit MPLS label value.
    pub label: u32,
    /// 3-bit Experimental / Traffic Class bits (0..=7).
    pub exp: Option<u8>,
    /// 1-bit Bottom-of-Stack flag.
    pub bos: Option<u8>,
    /// 8-bit MPLS Time-to-Live.
    pub ttl: Option<u8>,
}
