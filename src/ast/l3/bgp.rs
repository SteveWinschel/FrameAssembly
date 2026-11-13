//! Border Gateway Protocol Version 4 (BGP-4, RFC 4271 / RFC 4760) AST definitions.
//!
//! Defines inter-domain Autonomous System routing messages specified in RFC 4271 and carried over TCP
//! port `179`. Every BGP-4 PDU begins with a 19-byte fixed header comprising a 16-byte all-ones
//! synchronization `Marker` (`0xFF..0xFF`), a 16-bit total `Length` (`19..=4096`), and an 8-bit `Type`
//! code (`1` `open`, `2` `update`, `3` `notification`, `4` `keepalive`). `open` messages negotiate the
//! protocol version (`4`), 16-bit My Autonomous System (`asn`), 16-bit `Hold Time` (`holdtime`), and
//! 32-bit IPv4 `BGP Identifier` (`bgpid`), while `update` messages advertise Network Layer Reachability
//! Information (`prefix`) and `nexthop` (`nexthop`) path attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b bgp [open | update | notification | keepalive] [asn <u32>] [holdtime <u16>] [bgpid <ipv4>] [prefix "<cidr>"] [nexthop <ip>]`

use core::net::IpAddr;

/// RFC 4271 BGP-4 message type code.
#[doc(alias = "BgpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpType {
    /// Type `1` (`open`): Establishes a BGP peering session and negotiates ASN, Hold Time, and BGP Identifier.
    Open,
    /// Type `2` (`update`): Advertises feasible routes (`prefix`, `nexthop`) or withdraws unreachable prefixes.
    Update,
    /// Type `3` (`notification`): Signals a fatal protocol or hold-timer error and terminates the BGP connection.
    Notification,
    /// Type `4` (`keepalive`): 19-byte header-only heartbeat confirming session liveness within the Hold Time window.
    Keepalive,
}

/// Border Gateway Protocol v4 (RFC 4271) specification over TCP port `179`.
///
/// Syntax mapping: `bgp [open | update | notification | keepalive] [asn <u32>] [holdtime <u16>] [bgpid <ipv4>] [prefix "<cidr>"] [nexthop <ip>]`
#[doc(alias = "bgp")]
#[doc(alias = "BGP4")]
#[doc(alias = "RFC 4271")]
#[doc(alias = "RFC4271")]
#[doc(alias = "179")]
#[doc(alias = "open")]
#[doc(alias = "update")]
#[doc(alias = "notification")]
#[doc(alias = "keepalive")]
#[doc(alias = "asn")]
#[doc(alias = "holdtime")]
#[doc(alias = "bgpid")]
#[doc(alias = "prefix")]
#[doc(alias = "nexthop")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgpSpec<'a> {
    /// BGP message type (`open`, `update`, `notification`, or `keepalive`; default `keepalive`).
    pub bgp_type: Option<BgpType>,
    /// Autonomous System Number of the sender (`asn <u32>`, default `65001`).
    pub asn: Option<u32>,
    /// Proposed Hold Time interval in seconds (`holdtime <u16>`, default `180`).
    pub holdtime: Option<u16>,
    /// 32-bit BGP Router Identifier formatted as an IPv4 address (`bgpid <ipv4>`).
    pub bgpid: Option<IpAddr>,
    /// Network Layer Reachability Information CIDR prefix string (`prefix "<cidr>"`).
    pub prefix: Option<&'a str>,
    /// Next-Hop router IP address path attribute (`nexthop <ip>`).
    pub nexthop: Option<IpAddr>,
}
