//! IPFIX protocol AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;
/// RFC 7011 IP Flow Information Export specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpfixSpec<'a> {
    /// Source IP address in flow record.
    pub srcip: Option<IpAddr>,
    /// Destination IP address in flow record.
    pub dstip: Option<IpAddr>,
    /// Source port in flow record.
    pub srcport: Option<u16>,
    /// Destination port in flow record.
    pub dstport: Option<u16>,
    /// IP protocol number.
    pub proto: Option<u8>,
    /// Packet count.
    pub packets: Option<u32>,
    /// Octet (byte) count.
    pub octets: Option<u32>,
    /// Observation domain identifier.
    pub domain_id: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
