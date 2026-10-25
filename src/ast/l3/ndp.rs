//! IPv6 Neighbor Discovery Protocol (NDP, RFC 4861) AST definitions.
//!
//! Defines link-local IPv6 address resolution, Neighbor Unreachability Detection (NUD), Duplicate
//! Address Detection (DAD), and Stateless Address Autoconfiguration (SLAAC) router discovery messages
//! specified in RFC 4861 over ICMPv6 (Next Header `58`, Hop Limit `255`). Supports `ROUTER_SOLICIT`
//! (Type `133`), `ROUTER_ADVERT` (Type `134`, carrying `ROUTER_LIFETIME`), `NEIGHBOR_SOLICIT` (Type
//! `135`, automatically computing the Solicited-Node Multicast destination `ff02::1:ffXX:XXXX` and
//! attaching Option 1 Source Link-Layer Address `SLLA`), `NEIGHBOR_ADVERT` (Type `136`, setting
//! Solicited + Override flags `0x60` and Option 2 Target Link-Layer Address `TLLA`), and `REDIRECT` (`137`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b NDP [ROUTER_SOLICIT | ROUTER_ADVERT | NEIGHBOR_SOLICIT | NEIGHBOR_ADVERT | REDIRECT] [TARGET <ipv6>] [SLLA <mac>] [TLLA <mac>] [ROUTER_LIFETIME <u16>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 4861 IPv6 Neighbor Discovery ICMPv6 message type code.
#[doc(alias = "NdpMessageType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpType {
    /// Router Solicitation (`ROUTER_SOLICIT`, ICMPv6 Type `133`, sent to all-routers `ff02::2`).
    RouterSolicit,
    /// Router Advertisement (`ROUTER_ADVERT`, ICMPv6 Type `134`, periodic or solicited SLAAC beacon).
    RouterAdvert,
    /// Neighbor Solicitation (`NEIGHBOR_SOLICIT`, ICMPv6 Type `135`, resolves link-layer address or performs DAD).
    NeighborSolicit,
    /// Neighbor Advertisement (`NEIGHBOR_ADVERT`, ICMPv6 Type `136`, supplies Target Link-Layer Address).
    NeighborAdvert,
    /// Redirect (`REDIRECT`, ICMPv6 Type `137`, informs host of a better first-hop router).
    Redirect,
}

/// IPv6 Neighbor Discovery Protocol (RFC 4861) specification over ICMPv6 (`58`).
///
/// Syntax mapping: `NDP [ROUTER_SOLICIT | ROUTER_ADVERT | NEIGHBOR_SOLICIT | NEIGHBOR_ADVERT | REDIRECT] [TARGET <ipv6>] [SLLA <mac>] [TLLA <mac>] [ROUTER_LIFETIME <u16>]`
#[doc(alias = "NDP")]
#[doc(alias = "RFC 4861")]
#[doc(alias = "RFC4861")]
#[doc(alias = "SLAAC")]
#[doc(alias = "ICMPv6")]
#[doc(alias = "ROUTER_SOLICIT")]
#[doc(alias = "ROUTER_ADVERT")]
#[doc(alias = "NEIGHBOR_SOLICIT")]
#[doc(alias = "NEIGHBOR_ADVERT")]
#[doc(alias = "REDIRECT")]
#[doc(alias = "TARGET")]
#[doc(alias = "SLLA")]
#[doc(alias = "TLLA")]
#[doc(alias = "ROUTER_LIFETIME")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdpSpec<'a> {
    /// NDP message type (`NEIGHBOR_SOLICIT`, `NEIGHBOR_ADVERT`, `ROUTER_SOLICIT`, `ROUTER_ADVERT`, `REDIRECT`; default `NEIGHBOR_SOLICIT`).
    pub ndp_type: Option<NdpType>,
    /// 128-bit Target IPv6 address for Neighbor Solicitation, Neighbor Advertisement, or Redirect (`TARGET <ipv6>`).
    pub target: Option<IpAddr>,
    /// 48-bit Source Link-Layer Address NDP Option 1 override (`SLLA <mac>`).
    pub slla: Option<[u8; 6]>,
    /// 48-bit Target Link-Layer Address NDP Option 2 override (`TLLA <mac>`).
    pub tlla: Option<[u8; 6]>,
    /// 16-bit Router Lifetime in seconds for Router Advertisements (`ROUTER_LIFETIME <u16>`, default `1800`).
    pub router_lifetime: Option<u16>,
    /// Optional lifetime phantom marker for AST uniformity.
    pub _marker: PhantomData<&'a ()>,
}
