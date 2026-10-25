//! IP Flow Information Export (IPFIX) (RFC 7011 / RFC 7012) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire IP Flow Information Export (IPFIX) frames over UDP port 4739.
//! The wire encoder constructs a 16-byte IPFIX message header (16-bit Version = 0x000a, 16-bit Message Length, 32-bit Export Time in epoch seconds, 32-bit Sequence Number, 32-bit Observation Domain ID) followed by Set Header (16-bit Set ID >= 256 for Data Sets, 16-bit Set Length) and Information Element flow records (sourceIPv4Address, destinationIPv4Address, sourceTransportPort, destinationTransportPort, protocolIdentifier, packetDeltaCount, octetDeltaCount). When optional fields in [`IpfixSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b IPFIX [DOMAIN_ID <u32>] [SRCIP <ip>] [DSTIP <ip>] [SRCPORT <u16>] [DSTPORT <u16>] [PROTO <u8>] [PACKETS <u32>] [OCTETS <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 7011 IPFIX export packet payload.
/// Syntax mapping: `IPFIX [DOMAIN_ID <u32>] [SRCIP <ip>] [DSTIP <ip>] [SRCPORT <u16>] [DSTPORT <u16>] [PROTO <u8>] [PACKETS <u32>] [OCTETS <u32>]`
#[doc(alias = "IPFIX")]
#[doc(alias = "RFC7011")]
#[doc(alias = "RFC7012")]
#[doc(alias = "DOMAIN_ID")]
pub fn build_ipfix_payload(
    ctx: &WireContext,
    spec: &IpfixSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut data_record = Vec::new();
    let src_ip = spec.srcip.unwrap_or(ctx.src_ip);
    let dst_ip = spec.dstip.unwrap_or(ctx.dst_ip);
    let src_octets = match src_ip {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => [192, 168, 1, 100],
    };
    let dst_octets = match dst_ip {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => [1, 1, 1, 1],
    };
    data_record.extend_from_slice(&src_octets);
    data_record.extend_from_slice(&dst_octets);
    data_record.extend_from_slice(&spec.srcport.unwrap_or(ctx.src_port).to_be_bytes());
    data_record.extend_from_slice(&spec.dstport.unwrap_or(ctx.dst_port).to_be_bytes());
    data_record.push(spec.proto.unwrap_or(6));
    data_record.extend_from_slice(&(spec.packets.unwrap_or(1) as u64).to_be_bytes());
    data_record.extend_from_slice(&(spec.octets.unwrap_or(64) as u64).to_be_bytes());

    let set_len = (4 + data_record.len() + payload_bytes.len()) as u16;
    let total_len = 16 + set_len;

    let mut pkt = Vec::with_capacity(total_len as usize);
    // IPFIX Header (16 bytes)
    pkt.extend_from_slice(&10u16.to_be_bytes()); // Version 10
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&1700000000u32.to_be_bytes()); // Export Time
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
    pkt.extend_from_slice(&spec.domain_id.unwrap_or(0).to_be_bytes()); // Observation Domain ID

    // Data Set Header
    pkt.extend_from_slice(&256u16.to_be_bytes()); // Set ID 256
    pkt.extend_from_slice(&set_len.to_be_bytes());
    pkt.extend_from_slice(&data_record);

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
