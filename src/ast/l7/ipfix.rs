//! IP Flow Information Export (IPFIX) (RFC 7011 / RFC 7012) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! IP Flow Information Export (IPFIX) packets over UDP port 4739. On the wire, the protocol uses a 16-byte IPFIX message header (16-bit Version = `0x000a`, 16-bit Message Length, 32-bit Export Time in epoch seconds, 32-bit Sequence Number, 32-bit Observation Domain ID) followed by Set Header (16-bit Set ID `>= 256` for Data Sets, 16-bit Set Length) and Information Element flow records (sourceIPv4Address, destinationIPv4Address, sourceTransportPort, destinationTransportPort, protocolIdentifier, packetDeltaCount, octetDeltaCount).
//! Every field in [`IpfixSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b IPFIX [DOMAIN_ID <u32>] [SRCIP <ip>] [DSTIP <ip>] [SRCPORT <u16>] [DSTPORT <u16>] [PROTO <u8>] [PACKETS <u32>] [OCTETS <u32>]`

use core::marker::PhantomData;
use core::net::IpAddr;

/// RFC 7011 IP Flow Information Export specification.
///
/// Syntax mapping: `IPFIX [DOMAIN_ID <u32>] [SRCIP <ip>] [DSTIP <ip>] [SRCPORT <u16>] [DSTPORT <u16>] [PROTO <u8>] [PACKETS <u32>] [OCTETS <u32>]`
#[doc(alias = "IPFIX")]
#[doc(alias = "RFC 7011")]
#[doc(alias = "RFC7011")]
#[doc(alias = "RFC 7012")]
#[doc(alias = "RFC7012")]
#[doc(alias = "DOMAIN_ID")]
#[doc(alias = "SRCIP")]
#[doc(alias = "DSTIP")]
#[doc(alias = "SRCPORT")]
#[doc(alias = "DSTPORT")]
#[doc(alias = "PROTO")]
#[doc(alias = "PACKETS")]
#[doc(alias = "OCTETS")]
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
