//! Cisco NetFlow Version 5 & Version 9 Telemetry Export (Cisco NetFlow v5 / RFC 3954 NetFlow v9) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Cisco NetFlow Telemetry Export frames over UDP port 2055.
//! For IPv4 flows, the wire encoder constructs a 24-byte NetFlow v5 export header followed by a 48-byte fixed flow record.
//! For IPv6 flows (`srcip` or `dstip` or context endpoints are IPv6), it emits an RFC 3954 NetFlow v9 export message
//! containing a 20-byte v9 header, a Template FlowSet (`FlowSet ID 0`, `Template ID 256` with `IPV6_SRC_ADDR`/`IPV6_DST_ADDR`),
//! and a 4-byte-aligned Data FlowSet (`FlowSet ID 256`) carrying 16-byte IPv6 addresses and transport counters.
//!
//! Canonical `.frasm` syntax:
//! `a -> b netflow [srcip <ip>] [dstip <ip>] [srcport <u16>] [dstport <u16>] [proto <u8>] [packets <u32>] [octets <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Converts an IPv4 or IPv6 address into 16 network-order bytes for IPv6 telemetry records.
fn to_ipv6_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

/// Builds a NetFlow v9 (RFC 3954) IPv6 Template + Data FlowSet payload.
fn build_netflow_v9_ipv6(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    spec: &NetflowSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(108 + payload_bytes.len());
    // NetFlow v9 Header (20 bytes)
    pkt.extend_from_slice(&9u16.to_be_bytes()); // Version 9
    pkt.extend_from_slice(&2u16.to_be_bytes()); // Count: 1 template record + 1 data record
    pkt.extend_from_slice(&1000u32.to_be_bytes()); // SysUptime ms
    pkt.extend_from_slice(&1700000000u32.to_be_bytes()); // Unix Secs
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Source ID

    // Template FlowSet (FlowSet ID = 0, Length = 36 bytes = 4 + 4 + 7*4)
    pkt.extend_from_slice(&0u16.to_be_bytes()); // FlowSet ID 0 (Template)
    pkt.extend_from_slice(&36u16.to_be_bytes()); // Length
    pkt.extend_from_slice(&256u16.to_be_bytes()); // Template ID 256
    pkt.extend_from_slice(&7u16.to_be_bytes()); // Field Count: 7
    let template_fields: [(u16, u16); 7] = [
        (27, 16), // IPV6_SRC_ADDR
        (28, 16), // IPV6_DST_ADDR
        (7, 2),   // L4_SRC_PORT
        (11, 2),  // L4_DST_PORT
        (4, 1),   // PROTOCOL
        (2, 4),   // IN_PKTS
        (1, 4),   // IN_BYTES
    ];
    for (field_type, field_len) in template_fields {
        pkt.extend_from_slice(&field_type.to_be_bytes());
        pkt.extend_from_slice(&field_len.to_be_bytes());
    }

    // Data FlowSet (FlowSet ID = 256, 4B header + 45B record + 3B zero padding = 52 bytes)
    pkt.extend_from_slice(&256u16.to_be_bytes()); // FlowSet ID 256
    pkt.extend_from_slice(&52u16.to_be_bytes()); // Length (aligned to 4-byte boundary)
    pkt.extend_from_slice(&to_ipv6_octets(src_ip));
    pkt.extend_from_slice(&to_ipv6_octets(dst_ip));
    pkt.extend_from_slice(&spec.srcport.unwrap_or(0).to_be_bytes());
    pkt.extend_from_slice(&spec.dstport.unwrap_or(0).to_be_bytes());
    pkt.push(spec.proto.unwrap_or(6));
    pkt.extend_from_slice(&spec.packets.unwrap_or(1).to_be_bytes());
    pkt.extend_from_slice(&spec.octets.unwrap_or(64).to_be_bytes());
    pkt.extend_from_slice(&[0u8; 3]); // RFC 3954 32-bit FlowSet alignment padding

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}

/// Builds a Cisco NetFlow v5 (IPv4) or NetFlow v9 (IPv6) export packet payload.
/// Syntax mapping: `netflow [srcip <ip>] [dstip <ip>] [srcport <u16>] [dstport <u16>] [proto <u8>] [packets <u32>] [octets <u32>]`
#[doc(alias = "NETFLOW")]
#[doc(alias = "RFC3954")]
#[doc(alias = "NETFLOWV5")]
#[doc(alias = "NETFLOWV9")]
#[doc(alias = "PACKETS")]
#[doc(alias = "OCTETS")]
pub fn build_netflow_payload(
    ctx: &WireContext,
    spec: &NetflowSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let src_ip = spec.srcip.unwrap_or(ctx.src_ip);
    let dst_ip = spec.dstip.unwrap_or(ctx.dst_ip);
    if src_ip.is_ipv6() || dst_ip.is_ipv6() {
        return build_netflow_v9_ipv6(src_ip, dst_ip, spec, payload_bytes);
    }

    let mut pkt = Vec::with_capacity(72);
    // Header (24 bytes)
    pkt.extend_from_slice(&5u16.to_be_bytes()); // Version 5
    pkt.extend_from_slice(&1u16.to_be_bytes()); // Count: 1 record
    pkt.extend_from_slice(&1000u32.to_be_bytes()); // SysUptime ms
    pkt.extend_from_slice(&1700000000u32.to_be_bytes()); // Unix Secs
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Unix NanoSecs
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Flow Sequence
    pkt.push(0); // Engine Type
    pkt.push(0); // Engine ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Sampling Interval

    // Record (48 bytes)
    let src_octets = match src_ip {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => [192, 168, 1, 100],
    };
    let dst_octets = match dst_ip {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => [8, 8, 8, 8],
    };

    pkt.extend_from_slice(&src_octets); // srcaddr
    pkt.extend_from_slice(&dst_octets); // dstaddr
    pkt.extend_from_slice(&[0, 0, 0, 0]); // nexthop
    pkt.extend_from_slice(&1u16.to_be_bytes()); // input ifIndex
    pkt.extend_from_slice(&2u16.to_be_bytes()); // output ifIndex
    pkt.extend_from_slice(&spec.packets.unwrap_or(1).to_be_bytes()); // dPkts
    pkt.extend_from_slice(&spec.octets.unwrap_or(64).to_be_bytes()); // dOctets
    pkt.extend_from_slice(&900u32.to_be_bytes()); // first uptime ms
    pkt.extend_from_slice(&1000u32.to_be_bytes()); // last uptime ms
    pkt.extend_from_slice(&spec.srcport.unwrap_or(0).to_be_bytes()); // srcport
    pkt.extend_from_slice(&spec.dstport.unwrap_or(0).to_be_bytes()); // dstport
    pkt.push(0); // pad1
    pkt.push(0x10); // tcp_flags: ACK
    pkt.push(spec.proto.unwrap_or(6)); // prot: TCP (6)
    pkt.push(0); // tos
    pkt.extend_from_slice(&0u16.to_be_bytes()); // src_as
    pkt.extend_from_slice(&0u16.to_be_bytes()); // dst_as
    pkt.push(24); // src_mask
    pkt.push(24); // dst_mask
    pkt.extend_from_slice(&0u16.to_be_bytes()); // pad2

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
