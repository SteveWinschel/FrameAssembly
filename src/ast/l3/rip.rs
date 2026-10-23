//! Routing Information Protocol (RIP) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// RIP command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RipCommand {
    /// Request (1)
    Request,
    /// Response (2)
    Response,
}

/// Routing Information Protocol (RFC 2453 / 2080) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RipSpec<'a> {
    /// Command (Request or Response).
    pub command: Option<RipCommand>,
    /// Route prefix IP.
    pub prefix: Option<IpAddr>,
    /// Metric (hop count).
    pub metric: Option<u32>,
    /// Next Hop IP.
    pub nexthop: Option<IpAddr>,
    /// Route Tag.
    pub tag: Option<u16>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
