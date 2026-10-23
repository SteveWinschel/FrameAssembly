//! IPv6 Neighbor Discovery Protocol (NDP) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// NDP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpType {
    /// Router Solicitation (133)
    RouterSolicit,
    /// Router Advertisement (134)
    RouterAdvert,
    /// Neighbor Solicitation (135)
    NeighborSolicit,
    /// Neighbor Advertisement (136)
    NeighborAdvert,
    /// Redirect (137)
    Redirect,
}

/// Neighbor Discovery Protocol (RFC 4861) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdpSpec<'a> {
    /// NDP Message type.
    pub ndp_type: Option<NdpType>,
    /// Target IPv6 address.
    pub target: Option<IpAddr>,
    /// Source Link-Layer Address option.
    pub slla: Option<[u8; 6]>,
    /// Target Link-Layer Address option.
    pub tlla: Option<[u8; 6]>,
    /// Router Lifetime in seconds.
    pub router_lifetime: Option<u16>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
