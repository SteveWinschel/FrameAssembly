//! IP Flow Information Export (IPFIX) (RFC 7011 / RFC 7012) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire IP Flow Information Export (IPFIX) frames over UDP port 4739.
//! The wire encoder constructs a 16-byte IPFIX message header (`Version = 0x000a`, `Message Length`, `Export Time`,
//! `Sequence Number`, `Observation Domain ID`) followed by Information Element flow records. For IPv4 flows it emits
//! Data Set `256` with 4-byte IPv4 addresses; for IPv6 flows it emits Template Set `2` (`Template ID 257` with
//! `sourceIPv6Address` / `destinationIPv6Address`) followed by Data Set `257` with 16-byte IPv6 addresses.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ipfix [domainid <u32>] [srcip <ip>] [dstip <ip>] [srcport <u16>] [dstport <u16>] [proto <u8>] [packets <u32>] [octets <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Converts an IPv4 or IPv6 address into 16 network-order bytes for IPv6 Information Elements.
fn to_ipv6_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

/// Builds an RFC 7011 IPFIX IPv6 message carrying Template Set `2` (`257`) and Data Set `257`.
fn build_ipfix_ipv6(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    spec: &IpfixSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut data_record = Vec::with_capacity(53);
    data_record.extend_from_slice(&to_ipv6_octets(src_ip));
    data_record.extend_from_slice(&to_ipv6_octets(dst_ip));
    data_record.extend_from_slice(&spec.srcport.unwrap_or(0).to_be_bytes());
    data_record.extend_from_slice(&spec.dstport.unwrap_or(0).to_be_bytes());
    data_record.push(spec.proto.unwrap_or(6));
    data_record.extend_from_slice(&(spec.packets.unwrap_or(1) as u64).to_be_bytes());
    data_record.extend_from_slice(&(spec.octets.unwrap_or(64) as u64).to_be_bytes());

    let template_set_len = 36u16; // 4B Set Header + 4B Template Header + 7 * 4B IEs
    let max_extra = usize::from(u16::MAX) - 16 - usize::from(template_set_len) - 4 - data_record.len();
    let extra_slice = &payload_bytes[..payload_bytes.len().min(max_extra)];
    let data_set_len = (4 + data_record.len() + extra_slice.len()) as u16;
    let total_len = 16 + template_set_len + data_set_len;

    let mut pkt = Vec::with_capacity(usize::from(total_len));
    // IPFIX Header (16 bytes)
    pkt.extend_from_slice(&10u16.to_be_bytes());
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&1700000000u32.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes());
    pkt.extend_from_slice(&spec.domain_id.unwrap_or(0).to_be_bytes());

    // Template Set (Set ID 2, Template ID 257)
    pkt.extend_from_slice(&2u16.to_be_bytes());
    pkt.extend_from_slice(&template_set_len.to_be_bytes());
    pkt.extend_from_slice(&257u16.to_be_bytes());
    pkt.extend_from_slice(&7u16.to_be_bytes());
    let ies: [(u16, u16); 7] = [
        (27, 16), // sourceIPv6Address
        (28, 16), // destinationIPv6Address
        (7, 2),   // sourceTransportPort
        (11, 2),  // destinationTransportPort
        (4, 1),   // protocolIdentifier
        (2, 8),   // packetDeltaCount
        (1, 8),   // octetDeltaCount
    ];
    for (ie_id, ie_len) in ies {
        pkt.extend_from_slice(&ie_id.to_be_bytes());
        pkt.extend_from_slice(&ie_len.to_be_bytes());
    }

    // Data Set (Set ID 257)
    pkt.extend_from_slice(&257u16.to_be_bytes());
    pkt.extend_from_slice(&data_set_len.to_be_bytes());
    pkt.extend_from_slice(&data_record);
    if !extra_slice.is_empty() {
        pkt.extend_from_slice(extra_slice);
    }
    pkt
}

/// Builds an RFC 7011 IPFIX export packet payload (IPv4 Data Set `256` or IPv6 Template+Data Set `257`).
/// Syntax mapping: `ipfix [domainid <u32>] [srcip <ip>] [dstip <ip>] [srcport <u16>] [dstport <u16>] [proto <u8>] [packets <u32>] [octets <u32>]`
#[doc(alias = "IPFIX")]
#[doc(alias = "RFC7011")]
#[doc(alias = "RFC7012")]
#[doc(alias = "DOMAIN_ID")]
pub fn build_ipfix_payload(
    ctx: &WireContext,
    spec: &IpfixSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let src_ip = spec.srcip.unwrap_or(ctx.src_ip);
    let dst_ip = spec.dstip.unwrap_or(ctx.dst_ip);
    if src_ip.is_ipv6() || dst_ip.is_ipv6() {
        return build_ipfix_ipv6(src_ip, dst_ip, spec, payload_bytes);
    }

    let mut data_record = Vec::new();
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
    data_record.extend_from_slice(&spec.srcport.unwrap_or(0).to_be_bytes());
    data_record.extend_from_slice(&spec.dstport.unwrap_or(0).to_be_bytes());
    data_record.push(spec.proto.unwrap_or(6));
    data_record.extend_from_slice(&(spec.packets.unwrap_or(1) as u64).to_be_bytes());
    data_record.extend_from_slice(&(spec.octets.unwrap_or(64) as u64).to_be_bytes());

    let max_extra = usize::from(u16::MAX) - 16 - 4 - data_record.len();
    let extra_slice = &payload_bytes[..payload_bytes.len().min(max_extra)];
    let set_len = (4 + data_record.len() + extra_slice.len()) as u16;
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

    if !extra_slice.is_empty() {
        pkt.extend_from_slice(extra_slice);
    }
    pkt
}
