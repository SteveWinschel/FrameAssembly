//! Protocol Independent Multicast - Sparse Mode (PIM-SM, RFC 7761) AST definitions.
//!
//! Defines multicast distribution tree control messages specified in RFC 7761 (obsoleting RFC 4601)
//! and transmitted directly over IP protocol `103` (`0x67`) to the All-PIM-Routers link-local
//! multicast address (`224.0.0.13` for IPv4, `ff02::d` for IPv6) or unicast to a Rendezvous Point
//! (`RP`). The 4-byte PIMv2 header encodes a 4-bit `PIM Ver` (`2`), a 4-bit `Type` (`0` `HELLO`,
//! `1` `REGISTER`, `3` `JOIN_PRUNE`), an 8-bit `Reserved` byte, and a 16-bit ones'-complement
//! `Checksum`, followed by TLV options (`Option 1` `HOLDTIME` default `105`s, `Option 19` `DR_PRIORITY`
//! default `1`) and multicast tree `(S, G)` or `(*, G)` state (`SOURCE`, `GROUP`, `RP`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b PIM [HELLO | JOIN_PRUNE | REGISTER] [HOLDTIME <u16>] [DR_PRIORITY <u32>] [GROUP <ip>] [SOURCE <ip>] [RP <ip>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// Protocol Independent Multicast Sparse Mode (RFC 7761) specification over IP protocol `103`.
///
/// Syntax mapping: `PIM [HELLO | JOIN_PRUNE | REGISTER] [HOLDTIME <u16>] [DR_PRIORITY <u32>] [GROUP <ip>] [SOURCE <ip>] [RP <ip>]`
#[doc(alias = "PIM")]
#[doc(alias = "PIM-SM")]
#[doc(alias = "RFC 7761")]
#[doc(alias = "RFC7761")]
#[doc(alias = "103")]
#[doc(alias = "HELLO")]
#[doc(alias = "JOIN_PRUNE")]
#[doc(alias = "REGISTER")]
#[doc(alias = "HOLDTIME")]
#[doc(alias = "DR_PRIORITY")]
#[doc(alias = "GROUP")]
#[doc(alias = "SOURCE")]
#[doc(alias = "RP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PimSpec<'a> {
    /// Indicates a PIMv2 `HELLO` neighbor discovery and DR election message (`HELLO`).
    pub is_hello: bool,
    /// Indicates a PIMv2 `JOIN_PRUNE` shared-tree `(*,G)` or shortest-path-tree `(S,G)` control message (`JOIN_PRUNE`).
    pub is_join_prune: bool,
    /// Indicates a PIMv2 `REGISTER` unicast first-hop DR-to-RP multicast data encapsulation message (`REGISTER`).
    pub is_register: bool,
    /// Multicast Group IPv4 or IPv6 address (`GROUP <ip>`).
    pub group: Option<IpAddr>,
    /// Multicast Source IPv4 or IPv6 address for `(S,G)` SPT state (`SOURCE <ip>`).
    pub source: Option<IpAddr>,
    /// Rendezvous Point IPv4 or IPv6 address for `(*,G)` shared tree state (`RP <ip>`).
    pub rp: Option<IpAddr>,
    /// 16-bit PIM Hello Option 1 Holdtime in seconds (`HOLDTIME <u16>`, default `105`).
    pub holdtime: Option<u16>,
    /// 32-bit PIM Hello Option 19 Designated Router Priority (`DR_PRIORITY <u32>`, default `1`).
    pub dr_priority: Option<u32>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
