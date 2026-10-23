//! IPsec Authentication Header (AH) AST definitions.

use alloc::vec::Vec;
use core::marker::PhantomData;

/// IPsec Authentication Header (RFC 4302) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AhSpec<'a> {
    /// Security Parameters Index.
    pub spi: Option<u32>,
    /// Sequence Number.
    pub seq: Option<u32>,
    /// Integrity Check Value bytes.
    pub icv: Option<Vec<u8>>,
    /// Next Header protocol number.
    pub next_header: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
