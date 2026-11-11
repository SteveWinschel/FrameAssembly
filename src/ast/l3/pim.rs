//! Protocol Independent Multicast - Sparse Mode (PIM-SM, RFC 7761) AST definitions.
//!
//! Defines multicast distribution tree control messages specified in RFC 7761 (obsoleting RFC 4601)
//! and transmitted directly over IP protocol `103` (`0x67`) to the All-PIM-Routers link-local
//! multicast address (`224.0.0.13` for IPv4, `ff02::d` for IPv6) or unicast to a Rendezvous Point
//! (`rp`). The 4-byte PIMv2 header encodes a 4-bit `PIM Ver` (`2`), a 4-bit `Type` (`0` `hello`,
//! `1` `register`, `3` `joinprune`), an 8-bit `Reserved` byte, and a 16-bit ones'-complement
//! `Checksum`, followed by TLV options (`Option 1` `holdtime` default `105`s, `Option 19` `drpriority`
//! default `1`) and multicast tree `(S, G)` or `(*, G)` state (`source`, `group`, `rp`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b pim [hello | joinprune | register] [holdtime <u16>] [drpriority <u32>] [group <ip>] [source <ip>] [rp <ip>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// Protocol Independent Multicast Sparse Mode (RFC 7761) specification over IP protocol `103`.
///
/// Syntax mapping: `pim [hello | joinprune | register] [holdtime <u16>] [drpriority <u32>] [group <ip>] [source <ip>] [rp <ip>]`
#[doc(alias = "pim")]
#[doc(alias = "PIM-SM")]
#[doc(alias = "RFC 7761")]
#[doc(alias = "RFC7761")]
#[doc(alias = "103")]
#[doc(alias = "hello")]
#[doc(alias = "joinprune")]
#[doc(alias = "register")]
#[doc(alias = "holdtime")]
#[doc(alias = "drpriority")]
#[doc(alias = "group")]
#[doc(alias = "source")]
#[doc(alias = "rp")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PimSpec<'a> {
    /// Indicates a PIMv2 `hello` neighbor discovery and DR election message (`hello`).
    pub is_hello: bool,
    /// Indicates a PIMv2 `joinprune` shared-tree `(*,G)` or shortest-path-tree `(S,G)` control message (`joinprune`).
    pub is_join_prune: bool,
    /// Indicates a PIMv2 `register` unicast first-hop DR-to-RP multicast data encapsulation message (`register`).
    pub is_register: bool,
    /// Multicast Group IPv4 or IPv6 address (`group <ip>`).
    pub group: Option<IpAddr>,
    /// Multicast Source IPv4 or IPv6 address for `(S,G)` SPT state (`source <ip>`).
    pub source: Option<IpAddr>,
    /// Rendezvous Point IPv4 or IPv6 address for `(*,G)` shared tree state (`rp <ip>`).
    pub rp: Option<IpAddr>,
    /// 16-bit PIM Hello Option 1 Holdtime in seconds (`holdtime <u16>`, default `105`).
    pub holdtime: Option<u16>,
    /// 32-bit PIM Hello Option 19 Designated Router Priority (`drpriority <u32>`, default `1`).
    pub dr_priority: Option<u32>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
