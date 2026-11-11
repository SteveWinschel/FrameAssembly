//! Link Aggregation Control Protocol (LACP, IEEE 802.3ad / IEEE 802.1AX) AST definitions.
//!
//! Defines the abstract syntax tree node for IEEE 802.1AX Link Aggregation Control Protocol
//! Data Units (LACPDUs) transmitted over Ethernet Slow Protocols EtherType `0x8809` to the
//! link-constrained multicast address `01:80:C2:00:00:02`. Each 110-byte LACPDU begins with
//! Subtype `0x01` and Version `0x01`, followed by the 20-byte Actor Information TLV (`0x01`),
//! 20-byte Partner Information TLV (`0x02`), 16-byte Collector Information TLV (`0x03`),
//! Terminator TLV (`0x00`), and 50 bytes of zero padding.
//!
//! Canonical `.fasm` syntax:
//! `a -> b lacp [actorsys <mac>] [actorkey <u16>] [actorport <u16>] [actorstate <u8>] [partnersys <mac>] [partnerkey <u16>] [partnerport <u16>] [partnerstate <u8>]`

use core::marker::PhantomData;

/// Link Aggregation Control Protocol (IEEE 802.3ad / IEEE 802.1AX) frame specification.
///
/// Syntax mapping: `lacp [actorsys <mac>] [actorkey <u16>] [actorport <u16>] [actorstate <u8>] [partnersys <mac>] [partnerkey <u16>] [partnerport <u16>] [partnerstate <u8>]`
#[doc(alias = "lacp")]
#[doc(alias = "802.3ad")]
#[doc(alias = "802.1AX")]
#[doc(alias = "0x8809")]
#[doc(alias = "actorsys")]
#[doc(alias = "actorkey")]
#[doc(alias = "actorport")]
#[doc(alias = "actorstate")]
#[doc(alias = "partnersys")]
#[doc(alias = "partnerkey")]
#[doc(alias = "partnerport")]
#[doc(alias = "partnerstate")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LacpSpec<'a> {
    /// Actor System 48-bit MAC identifier (`actorsys <mac>`).
    pub actor_sys: Option<[u8; 6]>,
    /// Actor 16-bit operational administrative key (`actorkey <u16>`).
    pub actor_key: Option<u16>,
    /// Actor 16-bit port number (`actorport <u16>`).
    pub actor_port: Option<u16>,
    /// Partner System 48-bit MAC identifier (`partnersys <mac>`).
    pub partner_sys: Option<[u8; 6]>,
    /// Partner 16-bit operational administrative key (`partnerkey <u16>`).
    pub partner_key: Option<u16>,
    /// Partner 16-bit port number (`partnerport <u16>`).
    pub partner_port: Option<u16>,
    /// Actor 8-bit state bitmask (`actorstate <u8>`: Activity, Timeout, Aggregation, Sync, Collecting, Distributing, Defaulted, Expired).
    pub actor_state: Option<u8>,
    /// Partner 8-bit state bitmask (`partnerstate <u8>`).
    pub partner_state: Option<u8>,
    /// Optional lifetime marker for zero-copy AST borrowing.
    pub _marker: PhantomData<&'a ()>,
}
