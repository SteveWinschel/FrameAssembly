//! Generic Routing Encapsulation (GRE) AST definitions.

use core::marker::PhantomData;

/// Generic Routing Encapsulation (RFC 2784 / 2890) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GreSpec<'a> {
    /// Optional 32-bit GRE Key.
    pub key: Option<u32>,
    /// Optional 32-bit Sequence Number.
    pub seq: Option<u32>,
    /// Protocol type of encapsulated payload.
    pub proto: Option<u16>,
    /// Checksum present flag.
    pub checksum: bool,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
