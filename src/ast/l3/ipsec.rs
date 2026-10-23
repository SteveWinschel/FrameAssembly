//! IPsec Encapsulating Security Payload (ESP) AST definitions.

use alloc::vec::Vec;
use core::marker::PhantomData;

/// IPsec ESP (RFC 4303) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpsecSpec<'a> {
    /// Security Parameters Index.
    pub spi: Option<u32>,
    /// Sequence Number.
    pub seq: Option<u32>,
    /// Initialization Vector bytes.
    pub iv: Option<Vec<u8>>,
    /// Integrity Check Value bytes.
    pub icv: Option<Vec<u8>>,
    /// Next Header protocol number.
    pub next_header: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}

/// Type alias for RFC 4303 ESP specification.
pub type EspSpec<'a> = IpsecSpec<'a>;
