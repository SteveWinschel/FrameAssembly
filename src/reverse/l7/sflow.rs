//! sFlow v5 (`SFLOW`, RFC 3176) Layer 7 sampled network telemetry PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for sFlow Version 5 datagrams carried
//! over UDP ports `6343` and `16343`. It decodes both IPv4 (`address_type == 1`, 28-byte header)
//! and IPv6 (`address_type == 2`, 40-byte header) exporter agent addresses (`agent_ip`), sub-agent
//! identifiers (`sub_agent_id`), sequence numbers (`seq`), switch uptime (`uptime`), and sample
//! counts (`samples`).

use alloc::string::String;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, ipv4_at, ipv6_at, push_if};

use super::ok_dissect;

/// Dissects an sFlow v5 network telemetry datagram over UDP port `6343` or `16343`.
pub(crate) fn dissect_sflow(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 28
        || be_u32(payload, 0) != 5
        || !(sp == 6343 || dp == 6343 || sp == 16343 || dp == 16343)
    {
        return None;
    }
    let (agent_ip, hdr_end) = match be_u32(payload, 4) {
        1 => (IpAddr::V4(ipv4_at(payload, 8)), 28usize),
        2 if payload.len() >= 40 => (IpAddr::V6(ipv6_at(payload, 8)), 40usize),
        _ => return None,
    };

    let base = hdr_end - 16;
    let residual_start = if payload.len() >= hdr_end + 40 {
        hdr_end + 40
    } else {
        hdr_end
    };

    let mut tokens = String::from("sflow");
    let _ = write!(tokens, " agent_ip {agent_ip}");
    push_if(&mut tokens, "sub_agent_id", be_u32(payload, base), 0);
    push_if(&mut tokens, "seq", be_u32(payload, base + 4), 1);
    push_if(&mut tokens, "uptime", be_u32(payload, base + 8), 1000);
    push_if(&mut tokens, "samples", be_u32(payload, base + 12), 1);

    ok_dissect(Protocol::Sflow, tokens, payload[residual_start..].to_vec())
}
