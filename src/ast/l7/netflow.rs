//! Cisco NetFlow Version 5 Telemetry Export (Cisco NetFlow v5 / RFC 3954 (NetFlow v9)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Cisco NetFlow Version 5 Telemetry Export packets over UDP port 2055. On the wire, the protocol uses a 24-byte NetFlow v5 export header (16-bit version = 5, 16-bit flow count, 32-bit sys_uptime, 32-bit unix_secs, 32-bit unix_nsecs, 32-bit flow_sequence, 8-bit engine_type, 8-bit engine_id, 16-bit sampling_interval) followed by 48-byte fixed flow records containing srcaddr, dstaddr, nexthop, input/output SNMP ifIndex, dPkts, dOctets, first/last timestamps, srcport, dstport, tcp_flags, prot, tos, and src_as/dst_as.
//! Every field in [`NetflowSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b netflow [srcip <ip>] [dstip <ip>] [srcport <u16>] [dstport <u16>] [proto <u8>] [packets <u32>] [octets <u32>]`

use core::marker::PhantomData;
use core::net::IpAddr;
/// Cisco NetFlow v5/v9 telemetry export specification.
///
/// Syntax mapping: `netflow [srcip <ip>] [dstip <ip>] [srcport <u16>] [dstport <u16>] [proto <u8>] [packets <u32>] [octets <u32>]`
#[doc(alias = "netflow")]
#[doc(alias = "RFC 3954")]
#[doc(alias = "RFC3954")]
#[doc(alias = "NETFLOWV5")]
#[doc(alias = "srcip")]
#[doc(alias = "dstip")]
#[doc(alias = "srcport")]
#[doc(alias = "dstport")]
#[doc(alias = "proto")]
#[doc(alias = "packets")]
#[doc(alias = "octets")]
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
