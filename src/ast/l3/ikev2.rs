//! Internet Key Exchange Protocol Version 2 (IKEv2, RFC 7296) AST definitions.
//!
//! Defines the control-plane key management and Security Association negotiation header specified
//! in RFC 7296 over UDP port `500` (or UDP `4500` for NAT-Traversal). The 28-byte fixed IKEv2 header
//! begins with a 64-bit `IKE SA Initiator's SPI` (`initiatorspi`), a 64-bit `IKE SA Responder's SPI`
//! (`responderspi`), an 8-bit `Next Payload` type (`nextheader`), an 8-bit Version byte (`0x20` for
//! Major 2, Minor 0), an 8-bit `Exchange Type` (`exchange`: `34` `sainit`, `35` `auth`, `36`
//! `createchildsa`, `37` `informational`), an 8-bit `Flags` bitmask (`flags`, default `0x08`
//! Initiator bit), a 32-bit `Message ID` (`msgid`), and a 32-bit total `Length`.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ikev2 [exchange <sainit|auth|createchildsa|informational>] [initiatorspi <u64>] [responderspi <u64>] [msgid <u32>] [flags <u8>] [nextheader <u8>]`

use core::marker::PhantomData;

/// RFC 7296 IKEv2 Exchange Type code.
#[doc(alias = "Ikev2ExchangeType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeExchange {
    /// `IKE_SA_INIT` (`34`): Negotiates cryptographic algorithms, exchanges nonces, and performs Diffie-Hellman.
    SaInit,
    /// `IKE_AUTH` (`35`): Authenticates identities and establishes the initial Child SA.
    Auth,
    /// `createchildsa` (`36`): Creates new IPsec Child SAs or rekeys existing IKE/Child SAs.
    CreateChildSa,
    /// `informational` (`37`): Deletes SAs, reports error notifications, or performs liveness (DPD) checks.
    Informational,
}

/// Internet Key Exchange v2 (RFC 7296) specification over UDP port `500`.
///
/// Syntax mapping: `ikev2 [exchange <sainit|auth|createchildsa|informational>] [initiatorspi <u64>] [responderspi <u64>] [msgid <u32>] [flags <u8>] [nextheader <u8>]`
#[doc(alias = "ikev2")]
#[doc(alias = "IKEv2")]
#[doc(alias = "RFC 7296")]
#[doc(alias = "RFC7296")]
#[doc(alias = "ISAKMP")]
#[doc(alias = "500")]
#[doc(alias = "exchange")]
#[doc(alias = "sainit")]
#[doc(alias = "auth")]
#[doc(alias = "createchildsa")]
#[doc(alias = "informational")]
#[doc(alias = "initiatorspi")]
#[doc(alias = "responderspi")]
#[doc(alias = "msgid")]
#[doc(alias = "flags")]
#[doc(alias = "nextheader")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ikev2Spec<'a> {
    /// 64-bit IKE SA Initiator Security Parameters Index (`initiatorspi <u64>`, default `0x0102030405060708`).
    pub initiator_spi: Option<u64>,
    /// 64-bit IKE SA Responder Security Parameters Index (`responderspi <u64>`, default `0`).
    pub responder_spi: Option<u64>,
    /// 8-bit Exchange Type (`sainit`, `auth`, `createchildsa`, `informational`; default `sainit`).
    pub exchange: Option<IkeExchange>,
    /// 32-bit monotonically increasing Message ID (`msgid <u32>`, default `0`).
    pub msgid: Option<u32>,
    /// 8-bit IKEv2 header Flags bitmask (`flags <u8>`: `0x08` Initiator, `0x20` Response; default `0x08`).
    pub flags: Option<u8>,
    /// 8-bit Next Payload type identifier (`nextheader <u8>`, default `0` No Next Payload).
    pub next_payload: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
