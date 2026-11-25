//! sFlow v5 (`sflow`, RFC 3176) Layer 7 sampled network telemetry PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for sFlow Version 5 datagrams carried
//! over UDP ports `6343` and `16343`. It decodes both IPv4 (`address_type == 1`, 28-byte header)
//! and IPv6 (`address_type == 2`, 40-byte header) exporter agent addresses (`agentip`), sub-agent
//! identifiers (`subagentid`), sequence numbers (`seq`), switch uptime (`uptime`), sample counts
//! (`samples`), and 64-byte `Sampled IPv6` XDR flow records.

use alloc::string::String;
use alloc::vec::Vec;
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
    let samples = be_u32(payload, base + 12);
    if samples > 64 {
        return None;
    }

    let mut pos = hdr_end;
    let mut residual = Vec::new();
    for sample_idx in 0..samples {
        if pos.checked_add(40)? > payload.len() {
            return None;
        }
        let sample_fmt = be_u32(payload, pos);
        let sample_len = usize::try_from(be_u32(payload, pos + 4)).ok()?;
        if sample_fmt != 1 || sample_len < 32 {
            return None;
        }
        let sample_end = pos.checked_add(8)?.checked_add(sample_len)?;
        if sample_end > payload.len() {
            return None;
        }
        let num_flow_records = be_u32(payload, pos + 36);
        let flow_rec_len = match num_flow_records {
            0 => 0usize,
            1 => {
                if sample_len < 96 || be_u32(payload, pos + 40) != 4 || be_u32(payload, pos + 44) != 56
                {
                    return None;
                }
                64usize
            }
            _ => return None,
        };
        let body_end = pos.checked_add(8)?.checked_add(32 + flow_rec_len)?;
        if sample_idx + 1 < samples {
            if body_end != sample_end {
                return None;
            }
        } else {
            if sample_end != payload.len() {
                return None;
            }
            residual = payload[body_end..sample_end].to_vec();
        }
        pos = sample_end;
    }
    if samples == 0 {
        residual = payload[hdr_end..].to_vec();
    }

    let mut tokens = String::from("sflow");
    let _ = write!(tokens, " agentip {agent_ip}");
    push_if(&mut tokens, "subagentid", be_u32(payload, base), 0);
    push_if(&mut tokens, "seq", be_u32(payload, base + 4), 1);
    push_if(&mut tokens, "uptime", be_u32(payload, base + 8), 1000);
    push_if(&mut tokens, "samples", samples, 1);

    ok_dissect(Protocol::Sflow, tokens, residual)
}
