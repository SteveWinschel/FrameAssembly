//! IPv6 Neighbor Discovery Protocol (NDP, RFC 4861) AST definitions.
//!
//! Defines link-local IPv6 address resolution, Neighbor Unreachability Detection (NUD), Duplicate
//! Address Detection (DAD), and Stateless Address Autoconfiguration (SLAAC) router discovery messages
//! specified in RFC 4861 over ICMPv6 (Next Header `58`, Hop Limit `255`). Supports `routersolicit`
//! (Type `133`), `routeradvert` (Type `134`, carrying `routerlifetime`), `neighborsolicit` (Type
//! `135`, automatically computing the Solicited-Node Multicast destination `ff02::1:ffXX:XXXX` and
//! attaching Option 1 Source Link-Layer Address `slla`), `neighboradvert` (Type `136`, setting
//! Solicited + Override flags `0x60` and Option 2 Target Link-Layer Address `tlla`), and `redirect` (`137`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b ndp [routersolicit | routeradvert | neighborsolicit | neighboradvert | redirect] [target <ipv6>] [slla <mac>] [tlla <mac>] [routerlifetime <u16>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 4861 IPv6 Neighbor Discovery ICMPv6 message type code.
#[doc(alias = "NdpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpType {
    /// Router Solicitation (`routersolicit`, ICMPv6 Type `133`, sent to all-routers `ff02::2`).
    RouterSolicit,
    /// Router Advertisement (`routeradvert`, ICMPv6 Type `134`, periodic or solicited SLAAC beacon).
    RouterAdvert,
    /// Neighbor Solicitation (`neighborsolicit`, ICMPv6 Type `135`, resolves link-layer address or performs DAD).
    NeighborSolicit,
    /// Neighbor Advertisement (`neighboradvert`, ICMPv6 Type `136`, supplies Target Link-Layer Address).
    NeighborAdvert,
    /// Redirect (`redirect`, ICMPv6 Type `137`, informs host of a better first-hop router).
    Redirect,
}

/// IPv6 Neighbor Discovery Protocol (RFC 4861) specification over ICMPv6 (`58`).
///
/// Syntax mapping: `ndp [routersolicit | routeradvert | neighborsolicit | neighboradvert | redirect] [target <ipv6>] [slla <mac>] [tlla <mac>] [routerlifetime <u16>]`
#[doc(alias = "ndp")]
#[doc(alias = "RFC 4861")]
#[doc(alias = "RFC4861")]
#[doc(alias = "SLAAC")]
#[doc(alias = "ICMPv6")]
#[doc(alias = "routersolicit")]
#[doc(alias = "routeradvert")]
#[doc(alias = "neighborsolicit")]
#[doc(alias = "neighboradvert")]
#[doc(alias = "redirect")]
#[doc(alias = "target")]
#[doc(alias = "slla")]
#[doc(alias = "tlla")]
#[doc(alias = "routerlifetime")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdpSpec<'a> {
    /// NDP message type (`neighborsolicit`, `neighboradvert`, `routersolicit`, `routeradvert`, `redirect`; default `neighborsolicit`).
    pub ndp_type: Option<NdpType>,
    /// 128-bit Target IPv6 address for Neighbor Solicitation, Neighbor Advertisement, or Redirect (`target <ipv6>`).
    pub target: Option<IpAddr>,
    /// 48-bit Source Link-Layer Address NDP Option 1 override (`slla <mac>`).
    pub slla: Option<[u8; 6]>,
    /// 48-bit Target Link-Layer Address NDP Option 2 override (`tlla <mac>`).
    pub tlla: Option<[u8; 6]>,
    /// 16-bit Router Lifetime in seconds for Router Advertisements (`routerlifetime <u16>`, default `1800`).
    pub router_lifetime: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
