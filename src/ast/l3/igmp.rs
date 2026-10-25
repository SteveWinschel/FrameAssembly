//! Internet Group Management Protocol (IGMP, RFC 1112 / RFC 2236 / RFC 3376) AST definitions.
//!
//! Defines IPv4 host-to-router multicast group membership signaling carried directly over IPv4
//! protocol `2` (`0x02`). The 8-byte IGMPv2 (RFC 2236) message header consists of an 8-bit `Type`
//! (`0x11` Membership `QUERY`, `0x16` v2 Membership `REPORT`, `0x17` `LEAVE` Group), an 8-bit
//! `Max Resp Time` in tenths of a second (`MAX_RESP`, default `100` = 10.0s for Queries, `0` for
//! Reports and Leaves), a 16-bit ones'-complement `Checksum`, and a 32-bit `Group Address` (`GROUP`,
//! default `224.0.0.1` for General Queries, `239.1.1.1` for Reports, and `224.0.0.2` for Leaves).
//!
//! Canonical `.fasm` syntax:
//! `a -> b IGMP [QUERY | REPORT | LEAVE] [GROUP <ipv4>] [MAX_RESP <u8>] [V1 | V2 | V3]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2236 / RFC 3376 IGMP message type code.
#[doc(alias = "IgmpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpType {
    /// Membership Query (`QUERY`, Type `0x11`, addressed to `224.0.0.1` for General Queries).
    Query,
    /// Membership Report (`REPORT`, IGMPv1 Type `0x12`, IGMPv2 Type `0x16`).
    Report,
    /// Leave Group (`LEAVE`, IGMPv2 Type `0x17`, addressed to all-routers `224.0.0.2`).
    Leave,
}

/// Internet Group Management Protocol (RFC 2236 / RFC 3376) specification over IPv4 protocol `2`.
///
/// Syntax mapping: `IGMP [QUERY | REPORT | LEAVE] [GROUP <ipv4>] [MAX_RESP <u8>] [V1 | V2 | V3]`
#[doc(alias = "IGMP")]
#[doc(alias = "IGMPv2")]
#[doc(alias = "IGMPv3")]
#[doc(alias = "RFC 2236")]
#[doc(alias = "RFC2236")]
#[doc(alias = "RFC 3376")]
#[doc(alias = "RFC3376")]
#[doc(alias = "QUERY")]
#[doc(alias = "REPORT")]
#[doc(alias = "LEAVE")]
#[doc(alias = "GROUP")]
#[doc(alias = "MAX_RESP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IgmpSpec<'a> {
    /// IGMP message type (`QUERY`, `REPORT`, or `LEAVE`; default `REPORT`).
    pub igmp_type: Option<IgmpType>,
    /// 32-bit IPv4 Multicast Group address (`GROUP <ipv4>`).
    pub group: Option<IpAddr>,
    /// 8-bit Max Response Time in 100ms units (`MAX_RESP <u8>`, default `100` for Queries).
    pub max_resp: Option<u8>,
    /// IGMP protocol version selector (`V1`, `V2`, or `V3`).
    pub version: Option<u8>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
