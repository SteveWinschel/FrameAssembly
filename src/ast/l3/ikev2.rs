//! Internet Key Exchange Protocol Version 2 (IKEv2) AST definitions.

use core::marker::PhantomData;

/// IKEv2 Exchange Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeExchange {
    /// IKE_SA_INIT (34)
    SaInit,
    /// IKE_AUTH (35)
    Auth,
    /// CREATE_CHILD_SA (36)
    CreateChildSa,
    /// INFORMATIONAL (37)
    Informational,
}

/// Internet Key Exchange v2 (RFC 7296) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ikev2Spec<'a> {
    /// Initiator SPI (8 bytes).
    pub initiator_spi: Option<u64>,
    /// Responder SPI (8 bytes).
    pub responder_spi: Option<u64>,
    /// Exchange Type.
    pub exchange: Option<IkeExchange>,
    /// Message ID.
    pub msgid: Option<u32>,
    /// Flags.
    pub flags: Option<u8>,
    /// Next Payload.
    pub next_payload: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
