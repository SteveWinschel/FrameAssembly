//! Internet Group Management Protocol (IGMP, RFC 1112 / RFC 2236 / RFC 3376) AST definitions.
//!
//! Defines IPv4 host-to-router multicast group membership signaling carried directly over IPv4
//! protocol `2` (`0x02`). The 8-byte IGMPv2 (RFC 2236) message header consists of an 8-bit `Type`
//! (`0x11` Membership `query`, `0x16` v2 Membership `report`, `0x17` `leave` Group), an 8-bit
//! `Max Resp Time` in tenths of a second (`maxresp`, default `100` = 10.0s for Queries, `0` for
//! Reports and Leaves), a 16-bit ones'-complement `Checksum`, and a 32-bit `Group Address` (`group`,
//! default `224.0.0.1` for General Queries, `239.1.1.1` for Reports, and `224.0.0.2` for Leaves).
//!
//! Canonical `.fasm` syntax:
//! `a -> b igmp [query | report | leave] [group <ipv4>] [maxresp <u8>] [v1 | v2 | v3]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2236 / RFC 3376 IGMP message type code.
#[doc(alias = "IgmpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpType {
    /// Membership Query (`query`, Type `0x11`, addressed to `224.0.0.1` for General Queries).
    Query,
    /// Membership Report (`report`, IGMPv1 Type `0x12`, IGMPv2 Type `0x16`).
    Report,
    /// Leave Group (`leave`, IGMPv2 Type `0x17`, addressed to all-routers `224.0.0.2`).
    Leave,
}

/// Internet Group Management Protocol (RFC 2236 / RFC 3376) specification over IPv4 protocol `2`.
///
/// Syntax mapping: `igmp [query | report | leave] [group <ipv4>] [maxresp <u8>] [v1 | v2 | v3]`
#[doc(alias = "igmp")]
#[doc(alias = "IGMPv2")]
#[doc(alias = "IGMPv3")]
#[doc(alias = "RFC 2236")]
#[doc(alias = "RFC2236")]
#[doc(alias = "RFC 3376")]
#[doc(alias = "RFC3376")]
#[doc(alias = "query")]
#[doc(alias = "report")]
#[doc(alias = "leave")]
#[doc(alias = "group")]
#[doc(alias = "maxresp")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IgmpSpec<'a> {
    /// IGMP message type (`query`, `report`, or `leave`; default `report`).
    pub igmp_type: Option<IgmpType>,
    /// 32-bit IPv4 Multicast Group address (`group <ipv4>`).
    pub group: Option<IpAddr>,
    /// 8-bit Max Response Time in 100ms units (`maxresp <u8>`, default `100` for Queries).
    pub max_resp: Option<u8>,
    /// IGMP protocol version selector (`v1`, `v2`, or `v3`).
    pub version: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
