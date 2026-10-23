//! Internet Group Management Protocol (IGMP) AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;

/// IGMP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpType {
    /// Membership Query (0x11)
    Query,
    /// Membership Report (v1: 0x12, v2: 0x16)
    Report,
    /// Leave Group (0x17)
    Leave,
}

/// Internet Group Management Protocol (RFC 2236 / 3376) specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IgmpSpec<'a> {
    /// IGMP message type.
    pub igmp_type: Option<IgmpType>,
    /// Multicast group IPv4 address.
    pub group: Option<IpAddr>,
    /// Max Response Time.
    pub max_resp: Option<u8>,
    /// IGMP version (1, 2, or 3).
    pub version: Option<u8>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
