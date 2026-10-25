//! sFlow Version 5 Sampled Network Telemetry (sFlow.org Version 5 Specification / RFC 3176) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire sFlow Version 5 Sampled Network Telemetry frames over UDP port 6343.
//! The wire encoder constructs a 28-byte (IPv4) or 40-byte (IPv6) sFlow v5 datagram header containing 32-bit datagram_version = 5, 32-bit address_type (1 = IPv4, 2 = IPv6), Agent IP address, 32-bit sub_agent_id, 32-bit sequence_number, 32-bit sys_uptime in milliseconds, and 32-bit num_samples count followed by XDR-encoded flow sample and counter sample records. When optional fields in [`SflowSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SFLOW [AGENT_IP <ip>] [SUB_AGENT_ID <u32>] [SEQ <u32>] [UPTIME <u32>] [SAMPLES <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an sFlow v5 network monitoring datagram payload.
/// Syntax mapping: `SFLOW [AGENT_IP <ip>] [SUB_AGENT_ID <u32>] [SEQ <u32>] [UPTIME <u32>] [SAMPLES <u32>]`
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

    // Flow Sample Record (Format 1: standard flow sample, 32-byte 8 x u32 header)
    let sample_len = (32 + payload_bytes.len()) as u32;
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sample format 1 (enterprise 0, format 1)
    pkt.extend_from_slice(&sample_len.to_be_bytes()); // Sample data length (32B header + flow records)
    pkt.extend_from_slice(&spec.seq.unwrap_or(1).to_be_bytes()); // 1. sequence_number
    pkt.extend_from_slice(&0u32.to_be_bytes()); // 2. source_id
    pkt.extend_from_slice(&100u32.to_be_bytes()); // 3. sampling_rate
    pkt.extend_from_slice(&100u32.to_be_bytes()); // 4. sample_pool
    pkt.extend_from_slice(&0u32.to_be_bytes()); // 5. drops
    pkt.extend_from_slice(&1u32.to_be_bytes()); // 6. input_if (ifIndex 1)
    pkt.extend_from_slice(&2u32.to_be_bytes()); // 7. output_if (ifIndex 2)
    pkt.extend_from_slice(&0u32.to_be_bytes()); // 8. num_flow_records

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
