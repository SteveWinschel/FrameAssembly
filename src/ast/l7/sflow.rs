//! SFLOW protocol AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;
/// sFlow v5 network monitoring datagram specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SflowSpec<'a> {
    /// Agent IP address.
    pub agent_ip: Option<IpAddr>,
    /// Sub-agent identifier.
    pub sub_agent_id: Option<u32>,
    /// Sequence number.
    pub seq: Option<u32>,
    /// System uptime in milliseconds.
    pub uptime: Option<u32>,
    /// Number of samples.
    pub samples: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
