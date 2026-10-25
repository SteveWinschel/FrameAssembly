//! Cisco NetFlow Version 5 Telemetry Export (Cisco NetFlow v5 / RFC 3954 (NetFlow v9)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Cisco NetFlow Version 5 Telemetry Export frames over UDP port 2055.
//! The wire encoder constructs a 24-byte NetFlow v5 export header (16-bit version = 5, 16-bit flow count, 32-bit sys_uptime, 32-bit unix_secs, 32-bit unix_nsecs, 32-bit flow_sequence, 8-bit engine_type, 8-bit engine_id, 16-bit sampling_interval) followed by 48-byte fixed flow records containing srcaddr, dstaddr, nexthop, input/output SNMP ifIndex, dPkts, dOctets, first/last timestamps, srcport, dstport, tcp_flags, prot, tos, and src_as/dst_as. When optional fields in [`NetflowSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b NETFLOW [SRCIP <ip>] [DSTIP <ip>] [SRCPORT <u16>] [DSTPORT <u16>] [PROTO <u8>] [PACKETS <u32>] [OCTETS <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds a Cisco NetFlow v5 export packet payload.
/// Syntax mapping: `NETFLOW [SRCIP <ip>] [DSTIP <ip>] [SRCPORT <u16>] [DSTPORT <u16>] [PROTO <u8>] [PACKETS <u32>] [OCTETS <u32>]`
#[doc(alias = "NETFLOW")]
#[doc(alias = "RFC3954")]
#[doc(alias = "NETFLOWV5")]
#[doc(alias = "PACKETS")]
#[doc(alias = "OCTETS")]
pub fn build_netflow_payload(
    ctx: &WireContext,
    spec: &NetflowSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
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
    let src_ip = spec.srcip.unwrap_or(ctx.src_ip);
    let dst_ip = spec.dstip.unwrap_or(ctx.dst_ip);
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
    pkt.extend_from_slice(&spec.srcport.unwrap_or(ctx.src_port).to_be_bytes()); // srcport
    pkt.extend_from_slice(&spec.dstport.unwrap_or(ctx.dst_port).to_be_bytes()); // dstport
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
