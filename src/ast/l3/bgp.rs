//! Border Gateway Protocol Version 4 (BGP-4, RFC 4271 / RFC 4760) AST definitions.
//!
//! Defines inter-domain Autonomous System routing messages specified in RFC 4271 and carried over TCP
//! port `179`. Every BGP-4 PDU begins with a 19-byte fixed header comprising a 16-byte all-ones
//! synchronization `Marker` (`0xFF..0xFF`), a 16-bit total `Length` (`19..=4096`), and an 8-bit `Type`
//! code (`1` `OPEN`, `2` `UPDATE`, `3` `NOTIFICATION`, `4` `KEEPALIVE`). `OPEN` messages negotiate the
//! protocol version (`4`), 16-bit My Autonomous System (`ASN`), 16-bit `Hold Time` (`HOLDTIME`), and
//! 32-bit IPv4 `BGP Identifier` (`BGPID`), while `UPDATE` messages advertise Network Layer Reachability
//! Information (`PREFIX`) and `NEXT_HOP` (`NEXTHOP`) path attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b BGP [OPEN | UPDATE | NOTIFICATION | KEEPALIVE] [ASN <u32>] [HOLDTIME <u16>] [BGPID <ipv4>] [PREFIX "<cidr>"] [NEXTHOP <ip>]`

use core::net::IpAddr;

/// RFC 4271 BGP-4 message type code.
#[doc(alias = "BgpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpType {
    /// Type `1` (`OPEN`): Establishes a BGP peering session and negotiates ASN, Hold Time, and BGP Identifier.
    Open,
    /// Type `2` (`UPDATE`): Advertises feasible routes (`PREFIX`, `NEXTHOP`) or withdraws unreachable prefixes.
    Update,
    /// Type `3` (`NOTIFICATION`): Signals a fatal protocol or hold-timer error and terminates the BGP connection.
    Notification,
    /// Type `4` (`KEEPALIVE`): 19-byte header-only heartbeat confirming session liveness within the Hold Time window.
    Keepalive,
}

/// Border Gateway Protocol v4 (RFC 4271) specification over TCP port `179`.
///
/// Syntax mapping: `BGP [OPEN | UPDATE | NOTIFICATION | KEEPALIVE] [ASN <u32>] [HOLDTIME <u16>] [BGPID <ipv4>] [PREFIX "<cidr>"] [NEXTHOP <ip>]`
#[doc(alias = "BGP")]
#[doc(alias = "BGP4")]
#[doc(alias = "RFC 4271")]
#[doc(alias = "RFC4271")]
#[doc(alias = "179")]
#[doc(alias = "OPEN")]
#[doc(alias = "UPDATE")]
#[doc(alias = "NOTIFICATION")]
#[doc(alias = "KEEPALIVE")]
#[doc(alias = "ASN")]
#[doc(alias = "HOLDTIME")]
#[doc(alias = "BGPID")]
#[doc(alias = "PREFIX")]
#[doc(alias = "NEXTHOP")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgpSpec<'a> {
    /// BGP message type (`OPEN`, `UPDATE`, `NOTIFICATION`, or `KEEPALIVE`; default `KEEPALIVE`).
    pub bgp_type: Option<BgpType>,
    /// Autonomous System Number of the sender (`ASN <u32>`, default `65001`).
    pub asn: Option<u32>,
    /// Proposed Hold Time interval in seconds (`HOLDTIME <u16>`, default `180`).
    pub holdtime: Option<u16>,
    /// 32-bit BGP Router Identifier formatted as an IPv4 address (`BGPID <ipv4>`).
    pub bgpid: Option<IpAddr>,
    /// Network Layer Reachability Information CIDR prefix string (`PREFIX "<cidr>"`).
    pub prefix: Option<&'a str>,
    /// Next-Hop router IP address path attribute (`NEXTHOP <ip>`).
    pub nexthop: Option<IpAddr>,
}
