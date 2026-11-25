//! Cisco NetFlow v5 and v9 (`netflow`, RFC 3954) Layer 7 network flow telemetry PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for Cisco `netflow` Version 5 (24-byte
//! header + 48-byte IPv4 flow record) and RFC 3954 Version 9 (20-byte header + Template FlowSet `0`
//! + Data FlowSet `256` carrying 16-byte IPv6 addresses) export datagrams over UDP port `2055`. It
//!   extracts flow source and destination IP addresses (`srcip`, `dstip`), `srcport`, `dstport`,
//!   inner IP `proto`, `packets`, and `octets`.

use alloc::string::String;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if};

use super::{append_flow_record_tokens, ok_dissect};

/// Expected NetFlow v9 IPv6 template fields (`IPV6_SRC_ADDR`, `IPV6_DST_ADDR`, ports, proto, pkts, octets).
const NETFLOW_V9_IPV6_FIELDS: [(u16, u16); 7] = [
    (27, 16),
    (28, 16),
    (7, 2),
    (11, 2),
    (4, 1),
    (2, 4),
    (1, 4),
];

/// Dissects a Cisco `netflow` v5 (IPv4) or RFC 3954 v9 (IPv6) telemetry datagram.
pub(crate) fn dissect_netflow(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 72 {
        return None;
    }
    let version = be_u16(payload, 0);
    if version == 9 {
        return dissect_netflow_v9(payload, sp, dp);
    }
    if version != 5
        || !(sp == 2055
            || dp == 2055
            || (be_u16(payload, 2) == 1
                && be_u32(payload, 4) == 1000
                && be_u32(payload, 8) == 1_700_000_000))
    {
        return None;
    }
    let mut tokens = String::from("netflow");
    append_flow_record_tokens(
        &mut tokens,
        ipv4_at(payload, 24),
        ipv4_at(payload, 28),
        payload[62],
        be_u32(payload, 40),
        be_u32(payload, 44),
    );
    push_if(&mut tokens, "srcport", be_u16(payload, 56), 0);
    push_if(&mut tokens, "dstport", be_u16(payload, 58), 0);
    ok_dissect(Protocol::Netflow, tokens, payload[72..].to_vec())
}

/// Dissects an RFC 3954 NetFlow v9 IPv6 Template (`256`) + Data FlowSet payload.
fn dissect_netflow_v9(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 108
        || !(sp == 2055
            || dp == 2055
            || (be_u16(payload, 2) == 2
                && be_u32(payload, 4) == 1000
                && be_u32(payload, 8) == 1_700_000_000
                && be_u32(payload, 12) == 1
                && be_u32(payload, 16) == 0))
    {
        return None;
    }
    if be_u16(payload, 20) != 0
        || be_u16(payload, 22) != 36
        || be_u16(payload, 24) != 256
        || be_u16(payload, 26) != 7
        || be_u16(payload, 56) != 256
        || be_u16(payload, 58) != 52
    {
        return None;
    }
    for (idx, &(expected_type, expected_len)) in NETFLOW_V9_IPV6_FIELDS.iter().enumerate() {
        let off = 28 + idx * 4;
        if be_u16(payload, off) != expected_type || be_u16(payload, off + 2) != expected_len {
            return None;
        }
    }

    let flow_src = IpAddr::V6(ipv6_at(payload, 60));
    let flow_dst = IpAddr::V6(ipv6_at(payload, 76));
    let flow_sp = be_u16(payload, 92);
    let flow_dp = be_u16(payload, 94);
    let proto = payload[96];
    let packets = be_u32(payload, 97);
    let octets = be_u32(payload, 101);

    let mut tokens = String::from("netflow");
    let _ = write!(tokens, " srcip {flow_src} dstip {flow_dst}");
    push_if(&mut tokens, "proto", proto, 6);
    push_if(&mut tokens, "packets", packets, 1);
    push_if(&mut tokens, "octets", octets, 64);
    push_if(&mut tokens, "srcport", flow_sp, 0);
    push_if(&mut tokens, "dstport", flow_dp, 0);
    ok_dissect(Protocol::Netflow, tokens, payload[108..].to_vec())
}
