//! Multicast Listener Discovery (MLD) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// MLD message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MldType {
    /// Multicast Listener Query (130)
    Query,
    /// Multicast Listener Report (131)
    Report,
    /// Multicast Listener Done (132)
    Done,
}

/// Multicast Listener Discovery (RFC 2710 / 3810) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MldSpec<'a> {
    /// MLD message type.
    pub mld_type: Option<MldType>,
    /// Multicast IPv6 address.
    pub multicast_addr: Option<IpAddr>,
    /// Maximum Response Delay.
    pub max_resp_delay: Option<u16>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
