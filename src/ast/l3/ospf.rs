//! Open Shortest Path First (OSPF) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// OSPF packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfType {
    /// Hello (1)
    Hello,
    /// Database Description (2)
    Dbd,
    /// Link State Request (3)
    Lsr,
    /// Link State Update (4)
    Lsu,
    /// Link State Ack (5)
    LsAck,
}

/// Open Shortest Path First (RFC 2328 / 5340) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OspfSpec<'a> {
    /// Packet type.
    pub ospf_type: Option<OspfType>,
    /// Router ID.
    pub router_id: Option<IpAddr>,
    /// Area ID.
    pub area_id: Option<u32>,
    /// Hello Interval in seconds.
    pub hello_interval: Option<u16>,
    /// Dead Interval in seconds.
    pub dead_interval: Option<u32>,
    /// Router Priority.
    pub priority: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
