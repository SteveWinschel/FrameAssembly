//! Internet Key Exchange Protocol Version 2 (IKEv2, RFC 7296) AST definitions.
//!
//! Defines the control-plane key management and Security Association negotiation header specified
//! in RFC 7296 over UDP port `500` (or UDP `4500` for NAT-Traversal). The 28-byte fixed IKEv2 header
//! begins with a 64-bit `IKE SA Initiator's SPI` (`INITIATOR_SPI`), a 64-bit `IKE SA Responder's SPI`
//! (`RESPONDER_SPI`), an 8-bit `Next Payload` type (`NEXT_HEADER`), an 8-bit Version byte (`0x20` for
//! Major 2, Minor 0), an 8-bit `Exchange Type` (`EXCHANGE`: `34` `SA_INIT`, `35` `AUTH`, `36`
//! `CREATE_CHILD_SA`, `37` `INFORMATIONAL`), an 8-bit `Flags` bitmask (`FLAGS`, default `0x08`
//! Initiator bit), a 32-bit `Message ID` (`MSGID`), and a 32-bit total `Length`.
//!
//! Canonical `.fasm` syntax:
//! `a -> b IKEV2 [EXCHANGE <SA_INIT|AUTH|CREATE_CHILD_SA|INFORMATIONAL>] [INITIATOR_SPI <u64>] [RESPONDER_SPI <u64>] [MSGID <u32>] [FLAGS <u8>] [NEXT_HEADER <u8>]`

use core::marker::PhantomData;

/// RFC 7296 IKEv2 Exchange Type code.
#[doc(alias = "Ikev2ExchangeType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeExchange {
    /// `IKE_SA_INIT` (`34`): Negotiates cryptographic algorithms, exchanges nonces, and performs Diffie-Hellman.
    SaInit,
    /// `IKE_AUTH` (`35`): Authenticates identities and establishes the initial Child SA.
    Auth,
    /// `CREATE_CHILD_SA` (`36`): Creates new IPsec Child SAs or rekeys existing IKE/Child SAs.
    CreateChildSa,
    /// `INFORMATIONAL` (`37`): Deletes SAs, reports error notifications, or performs liveness (DPD) checks.
    Informational,
}

/// Internet Key Exchange v2 (RFC 7296) specification over UDP port `500`.
///
/// Syntax mapping: `IKEV2 [EXCHANGE <SA_INIT|AUTH|CREATE_CHILD_SA|INFORMATIONAL>] [INITIATOR_SPI <u64>] [RESPONDER_SPI <u64>] [MSGID <u32>] [FLAGS <u8>] [NEXT_HEADER <u8>]`
#[doc(alias = "IKEV2")]
#[doc(alias = "IKEv2")]
#[doc(alias = "RFC 7296")]
#[doc(alias = "RFC7296")]
#[doc(alias = "ISAKMP")]
#[doc(alias = "500")]
#[doc(alias = "EXCHANGE")]
#[doc(alias = "SA_INIT")]
#[doc(alias = "AUTH")]
#[doc(alias = "CREATE_CHILD_SA")]
#[doc(alias = "INFORMATIONAL")]
#[doc(alias = "INITIATOR_SPI")]
#[doc(alias = "RESPONDER_SPI")]
#[doc(alias = "MSGID")]
#[doc(alias = "FLAGS")]
#[doc(alias = "NEXT_HEADER")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ikev2Spec<'a> {
    /// 64-bit IKE SA Initiator Security Parameters Index (`INITIATOR_SPI <u64>`, default `0x0102030405060708`).
    pub initiator_spi: Option<u64>,
    /// 64-bit IKE SA Responder Security Parameters Index (`RESPONDER_SPI <u64>`, default `0`).
    pub responder_spi: Option<u64>,
    /// 8-bit Exchange Type (`SA_INIT`, `AUTH`, `CREATE_CHILD_SA`, `INFORMATIONAL`; default `SA_INIT`).
    pub exchange: Option<IkeExchange>,
    /// 32-bit monotonically increasing Message ID (`MSGID <u32>`, default `0`).
    pub msgid: Option<u32>,
    /// 8-bit IKEv2 header Flags bitmask (`FLAGS <u8>`: `0x08` Initiator, `0x20` Response; default `0x08`).
    pub flags: Option<u8>,
    /// 8-bit Next Payload type identifier (`NEXT_HEADER <u8>`, default `0` No Next Payload).
    pub next_payload: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
