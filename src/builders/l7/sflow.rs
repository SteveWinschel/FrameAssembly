//! SFLOW protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an sFlow v5 network monitoring datagram payload.
pub fn build_sflow_payload(
    ctx: &WireContext,
    spec: &SflowSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&5u32.to_be_bytes()); // sFlow version 5

    let agent_ip = spec.agent_ip.unwrap_or(ctx.src_ip);
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
    pkt.extend_from_slice(&spec.samples.unwrap_or(1).to_be_bytes());

    // Flow Sample Record (Format 1: standard flow sample)
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sample format 1
    pkt.extend_from_slice(&16u32.to_be_bytes()); // Sample data length
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sample sequence
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Source ID
    pkt.extend_from_slice(&100u32.to_be_bytes()); // Sampling rate
    pkt.extend_from_slice(&100u32.to_be_bytes()); // Sample pool

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
