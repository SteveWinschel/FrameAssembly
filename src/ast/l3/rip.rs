//! Routing Information Protocol (RIPv2 RFC 2453 / RIPng RFC 2080) AST definitions.
//!
//! Defines distance-vector Interior Gateway Protocol route table request and advertisement messages
//! specified in RFC 2453 (RIPv2 over UDP port `520` to multicast `224.0.0.9`) and RFC 2080 (RIPng
//! for IPv6 over UDP port `521` to multicast `ff02::9`). A 24-byte RIPv2 packet consists of a 4-byte
//! header (`Command`: `1` `request` or `2` `response`, `Version`: `2`, 16-bit `Must Be Zero`) followed
//! by one or more 20-byte Route Table Entries (RTEs) encoding `Address Family Identifier` (`2`), 16-bit
//! `Route Tag` (`tag`), 32-bit `IP Address` (`prefix`), 32-bit `Subnet Mask` (`255.255.255.0`), 32-bit
//! `Next Hop` (`nexthop`), and 32-bit hop-count `Metric` (`metric`, `1..=16` where `16` = infinity).
//!
//! Canonical `.fasm` syntax:
//! `a -> b rip [request | response] [prefix <ip>] [metric <1..16>] [nexthop <ip>] [tag <u16>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 2453 / RFC 2080 RIP message command code.
#[doc(alias = "RipCommandType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RipCommand {
    /// Command `1` (`request`): Queries a neighboring router for all or part of its RIP routing table.
    Request,
    /// Command `2` (`response`): Periodic, solicited, or triggered advertisement containing Route Table Entries.
    Response,
}

/// Routing Information Protocol (RFC 2453 RIPv2 / RFC 2080 RIPng) specification over UDP `520` / `521`.
///
/// Syntax mapping: `rip [request | response] [prefix <ip>] [metric <1..16>] [nexthop <ip>] [tag <u16>]`
#[doc(alias = "rip")]
#[doc(alias = "RIPv2")]
#[doc(alias = "RIPng")]
#[doc(alias = "RFC 2453")]
#[doc(alias = "RFC2453")]
#[doc(alias = "RFC 2080")]
#[doc(alias = "RFC2080")]
#[doc(alias = "request")]
#[doc(alias = "response")]
#[doc(alias = "prefix")]
#[doc(alias = "metric")]
#[doc(alias = "nexthop")]
#[doc(alias = "tag")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RipSpec<'a> {
    /// RIP Command code (`request` `1` or `response` `2`; default `response`).
    pub command: Option<RipCommand>,
    /// Advertised destination network prefix IP address (`prefix <ip>`, default `10.0.0.0`).
    pub prefix: Option<IpAddr>,
    /// 32-bit Bellmann-Ford hop count metric (`metric <1..=16>`, default `1`; `16` indicates unreachable / poison reverse).
    pub metric: Option<u32>,
    /// Immediate Next-Hop router IP address (`nexthop <ip>`, default `0.0.0.0` meaning the advertising router).
    pub nexthop: Option<IpAddr>,
    /// 16-bit external route redistribution Tag (`tag <u16>`, default `0`, often carrying an external BGP/OSPF ASN).
    pub tag: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
