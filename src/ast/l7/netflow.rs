//! NETFLOW protocol AST definitions.

use core::marker::PhantomData;
use core::net::IpAddr;
/// Cisco NetFlow v5/v9 telemetry export specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetflowSpec<'a> {
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
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
