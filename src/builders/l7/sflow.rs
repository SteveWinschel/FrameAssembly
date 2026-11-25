//! sFlow Version 5 Sampled Network Telemetry (sFlow.org Version 5 Specification / RFC 3176) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire sFlow Version 5 Sampled Network Telemetry frames over UDP port 6343.
//! The wire encoder constructs a 28-byte (IPv4 agent) or 40-byte (IPv6 agent) sFlow v5 datagram header containing
//! `datagram_version = 5`, `address_type` (`1 = IPv4`, `2 = IPv6`), Agent IP, `sub_agent_id`, `sequence_number`, `sys_uptime`,
//! and `num_samples` followed by XDR Flow Sample headers (`Format 1`). When running over IPv6 or with an IPv6 agent,
//! each flow sample embeds a 64-byte `Sampled IPv6` (`enterprise = 0, format = 4`) XDR flow record.
//!
//! Canonical `.frasm` syntax:
//! `a -> b sflow [agentip <ip>] [subagentid <u32>] [seq <u32>] [uptime <u32>] [samples <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Converts an IPv4 or IPv6 address into 16 network-order bytes for sFlow `sampled_ipv6` records.
fn to_ipv6_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

/// Builds an sFlow v5 network monitoring datagram payload.
/// Syntax mapping: `sflow [agentip <ip>] [subagentid <u32>] [seq <u32>] [uptime <u32>] [samples <u32>]`
#[doc(alias = "SFLOW")]
#[doc(alias = "RFC3176")]
#[doc(alias = "SFLOWV5")]
#[doc(alias = "SUB_AGENT_ID")]
#[doc(alias = "SAMPLES")]
pub fn build_sflow_payload(
    ctx: &WireContext,
    spec: &SflowSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(144);
    pkt.extend_from_slice(&5u32.to_be_bytes()); // sFlow version 5

    let agent_ip = spec.agent_ip.unwrap_or(ctx.src_ip);
    let is_ipv6_flow = agent_ip.is_ipv6() || ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6();
    match agent_ip {
        IpAddr::V4(v4) => {
            pkt.extend_from_slice(&1u32.to_be_bytes()); // Address type 1: IPv4
            pkt.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            pkt.extend_from_slice(&2u32.to_be_bytes()); // Address type 2: IPv6
            pkt.extend_from_slice(&v6.octets());
        }
    }

    pkt.extend_from_slice(&spec.sub_agent_id.unwrap_or(0).to_be_bytes());
    pkt.extend_from_slice(&spec.seq.unwrap_or(1).to_be_bytes());
    pkt.extend_from_slice(&spec.uptime.unwrap_or(1000).to_be_bytes());
    let count = spec.samples.unwrap_or(1).min(64);
    pkt.extend_from_slice(&count.to_be_bytes());

    let flow_record_len: u32 = if is_ipv6_flow { 64 } else { 0 };
    // Flow Sample Records (Format 1: standard flow sample, 32-byte header + optional flow records)
    for sample_seq in 1..=count {
        let extra = if sample_seq == count {
            payload_bytes.len()
        } else {
            0
        };
        let sample_len = 32u32
            .saturating_add(flow_record_len)
            .saturating_add(extra as u32);
        pkt.extend_from_slice(&1u32.to_be_bytes()); // Sample format 1 (enterprise 0, format 1)
        pkt.extend_from_slice(&sample_len.to_be_bytes()); // Sample data length
        pkt.extend_from_slice(&sample_seq.to_be_bytes()); // 1. sequence_number (1..=count)
        pkt.extend_from_slice(&0u32.to_be_bytes()); // 2. source_id
        pkt.extend_from_slice(&100u32.to_be_bytes()); // 3. sampling_rate
        pkt.extend_from_slice(&100u32.to_be_bytes()); // 4. sample_pool
        pkt.extend_from_slice(&0u32.to_be_bytes()); // 5. drops
        pkt.extend_from_slice(&1u32.to_be_bytes()); // 6. input_if (ifIndex 1)
        pkt.extend_from_slice(&2u32.to_be_bytes()); // 7. output_if (ifIndex 2)
        if is_ipv6_flow {
            pkt.extend_from_slice(&1u32.to_be_bytes()); // 8. num_flow_records = 1
            // Flow Record: Sampled IPv6 (enterprise = 0, format = 4, XDR length = 56 bytes)
            pkt.extend_from_slice(&4u32.to_be_bytes()); // flow_data_format = 4 (sampled_ipv6)
            pkt.extend_from_slice(&56u32.to_be_bytes()); // flow_data_length = 56
            pkt.extend_from_slice(&64u32.to_be_bytes()); // ip_length
            pkt.extend_from_slice(&6u32.to_be_bytes()); // protocol = TCP (6)
            pkt.extend_from_slice(&to_ipv6_octets(ctx.src_ip));
            pkt.extend_from_slice(&to_ipv6_octets(ctx.dst_ip));
            pkt.extend_from_slice(&u32::from(ctx.src_port).to_be_bytes());
            pkt.extend_from_slice(&u32::from(ctx.dst_port).to_be_bytes());
            pkt.extend_from_slice(&0x10u32.to_be_bytes()); // tcp_flags = ACK
            pkt.extend_from_slice(&0u32.to_be_bytes()); // priority
        } else {
            pkt.extend_from_slice(&0u32.to_be_bytes()); // 8. num_flow_records
        }
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
