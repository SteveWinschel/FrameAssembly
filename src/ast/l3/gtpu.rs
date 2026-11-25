//! GPRS Tunneling Protocol User Plane (GTPv1-U, 3GPP TS 29.281) AST definitions.
//!
//! Defines the mobile core user-plane tunneling protocol specified in 3GPP TS 29.281 over UDP
//! destination port `2152` across 4G S1-U/S5/S8 and 5G N3/N9 interfaces. Every GTPv1-U packet
//! opens with an 8-byte mandatory header (`Flags` `0x30`, `Message Type`, 16-bit `Length`, and
//! 32-bit Tunnel Endpoint Identifier `teid`), optionally followed by `Sequence Number` (`seqnum`),
//! `N-PDU Number` (`npdu`), and a 5G NR PDU Session Container extension header (`0x85`) encoding the
//! QoS Flow Identifier (`qfi`). Supports `gpdu` (`255`), `echorequest` (`1`), `echoreply` (`2`),
//! `errorindication` (`26`), and `endmarker` (`254`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b gtpu [gpdu | echorequest | echoreply | errorindication | endmarker] [teid <u32>] [flags <u8>] [seqnum <u16>] [npdu <u8>] [qfi <0..63>]`

use core::marker::PhantomData;

/// 3GPP TS 29.281 GTPv1-U message type discriminator.
#[doc(alias = "GtpuMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuType {
    /// Type `1` (`echorequest`): Path management keepalive probe (`teid` default `0`, `S=1`).
    EchoRequest,
    /// Type `2` (`echoreply`): Path management keepalive reply with Recovery IE (`teid` default `0`, `S=1`).
    EchoReply,
    /// Type `26` (`errorindication`): Tunnel context missing notification carrying TEID Data I and Peer Address IEs.
    ErrorIndication,
    /// Type `254` (`endmarker`): Handover path-switch completion marker (`teid` default `1`).
    EndMarker,
    /// Type `255` (`gpdu`): User-plane G-PDU encapsulating an inner IPv4/IPv6 T-PDU (`teid` default `1`).
    Gpdu,
}

/// GPRS Tunneling Protocol User Plane (3GPP TS 29.281) specification over UDP port `2152`.
///
/// Syntax mapping: `gtpu [gpdu | echorequest | echoreply | errorindication | endmarker] [teid <u32>] [flags <u8>] [seqnum <u16>] [npdu <u8>] [qfi <0..63>]`
#[doc(alias = "gtpu")]
#[doc(alias = "GTP-U")]
#[doc(alias = "TS 29.281")]
#[doc(alias = "2152")]
#[doc(alias = "gpdu")]
#[doc(alias = "echorequest")]
#[doc(alias = "echoreply")]
#[doc(alias = "errorindication")]
#[doc(alias = "endmarker")]
#[doc(alias = "teid")]
#[doc(alias = "seqnum")]
#[doc(alias = "npdu")]
#[doc(alias = "qfi")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GtpuSpec<'a> {
    /// GTPv1-U message type (`gpdu`, `echorequest`, `echoreply`, `errorindication`, `endmarker`; default `gpdu`).
    pub msg_type: Option<GtpuType>,
    /// 32-bit Tunnel Endpoint Identifier (`teid <u32>`, default `1` for G-PDU/EndMarker, `0` for Echo).
    pub teid: Option<u32>,
    /// GTP-U header flags octet (`flags <u8>`, default `0x30` or `0x32` on Echo).
    pub flags: Option<u8>,
    /// Optional 16-bit GTP-U sequence number setting the `S` flag (`seqnum <u16>`).
    pub seqnum: Option<u16>,
    /// Optional 8-bit N-PDU number setting the `PN` flag (`npdu <u8>`).
    pub npdu: Option<u8>,
    /// Optional 6-bit 5G QoS Flow Identifier (`qfi <0..=63>`) emitting Extension Header `0x85`.
    pub qfi: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
