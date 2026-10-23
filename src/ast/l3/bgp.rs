//! Border Gateway Protocol (BGP) AST definitions.

use core::net::IpAddr;

/// BGP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpType {
    /// OPEN (1)
    Open,
    /// UPDATE (2)
    Update,
    /// NOTIFICATION (3)
    Notification,
    /// KEEPALIVE (4)
    Keepalive,
}

/// Border Gateway Protocol (RFC 4271) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgpSpec<'a> {
    /// BGP message type.
    pub bgp_type: Option<BgpType>,
    /// Autonomous System Number.
    pub asn: Option<u32>,
    /// Hold Time in seconds.
    pub holdtime: Option<u16>,
    /// BGP Identifier.
    pub bgpid: Option<IpAddr>,
    /// NLRI IP prefix.
    pub prefix: Option<&'a str>,
    /// Next Hop IP address.
    pub nexthop: Option<IpAddr>,
}
