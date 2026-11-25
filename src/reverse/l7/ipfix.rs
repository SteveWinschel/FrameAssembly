//! IP Flow Information Export (`ipfix`, RFC 7011 / RFC 7012) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 7011 `ipfix` (Version 10) flow
//! telemetry datagrams over UDP port `4739`. It decodes both IPv4 Data Set `256` (16B header + 4B
//! set header + 29B record) and IPv6 Template Set `2` (`257`) + Data Set `257` (53B record) flows,
//! extracting `domainid`, `srcip`, `dstip`, `srcport`, `dstport`, `proto`, `packets`, and `octets`.

use alloc::string::String;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, be_u64, ipv4_at, ipv6_at, push_if};

use super::{append_flow_record_tokens, ok_dissect};

/// Expected IPFIX IPv6 template Information Elements (`sourceIPv6Address`, `destinationIPv6Address`, ports, proto, pkts, octets).
const IPFIX_IPV6_IES: [(u16, u16); 7] = [
    (27, 16),
    (28, 16),
    (7, 2),
    (11, 2),
    (4, 1),
    (2, 8),
    (1, 8),
];

/// Dissects an RFC 7011 `ipfix` v10 IPv4 or IPv6 telemetry datagram.
pub(crate) fn dissect_ipfix(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 49
        || be_u16(payload, 0) != 10
        || usize::from(be_u16(payload, 2)) != payload.len()
    {
        return None;
    }

    if be_u16(payload, 16) == 2 {
        return dissect_ipfix_ipv6(payload, sp, dp);
    }

    if be_u16(payload, 16) != 256
        || 16usize.checked_add(usize::from(be_u16(payload, 18))) != Some(payload.len())
        || !(sp == 4739
            || dp == 4739
            || (be_u32(payload, 4) == 1_700_000_000
                && be_u32(payload, 8) == 1
                && be_u16(payload, 18) == 33))
    {
        return None;
    }
    let mut tokens = String::from("ipfix");
    push_if(&mut tokens, "domainid", be_u32(payload, 12), 0);
    append_flow_record_tokens(
        &mut tokens,
        ipv4_at(payload, 20),
        ipv4_at(payload, 24),
        payload[32],
        be_u64(payload, 33) as u32,
        be_u64(payload, 41) as u32,
    );
    push_if(&mut tokens, "srcport", be_u16(payload, 28), 0);
    push_if(&mut tokens, "dstport", be_u16(payload, 30), 0);
    ok_dissect(Protocol::Ipfix, tokens, payload[49..].to_vec())
}

/// Dissects an RFC 7011 IPFIX IPv6 message carrying Template Set `2` (`257`) + Data Set `257`.
fn dissect_ipfix_ipv6(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 109
        || be_u16(payload, 18) != 36
        || be_u16(payload, 20) != 257
        || be_u16(payload, 22) != 7
        || be_u16(payload, 52) != 257
    {
        return None;
    }
    for (idx, &(expected_id, expected_len)) in IPFIX_IPV6_IES.iter().enumerate() {
        let off = 24 + idx * 4;
        if be_u16(payload, off) != expected_id || be_u16(payload, off + 2) != expected_len {
            return None;
        }
    }
    let data_set_len = usize::from(be_u16(payload, 54));
    if data_set_len < 57
        || 52usize.checked_add(data_set_len) != Some(payload.len())
        || !(sp == 4739
            || dp == 4739
            || (be_u32(payload, 4) == 1_700_000_000
                && be_u32(payload, 8) == 1
                && data_set_len == 57))
    {
        return None;
    }

    let flow_src = IpAddr::V6(ipv6_at(payload, 56));
    let flow_dst = IpAddr::V6(ipv6_at(payload, 72));
    let flow_sp = be_u16(payload, 88);
    let flow_dp = be_u16(payload, 90);
    let proto = payload[92];
    let packets = be_u64(payload, 93) as u32;
    let octets = be_u64(payload, 101) as u32;

    let mut tokens = String::from("ipfix");
    push_if(&mut tokens, "domainid", be_u32(payload, 12), 0);
    let _ = write!(tokens, " srcip {flow_src} dstip {flow_dst}");
    push_if(&mut tokens, "proto", proto, 6);
    push_if(&mut tokens, "packets", packets, 1);
    push_if(&mut tokens, "octets", octets, 64);
    push_if(&mut tokens, "srcport", flow_sp, 0);
    push_if(&mut tokens, "dstport", flow_dp, 0);
    ok_dissect(Protocol::Ipfix, tokens, payload[109..].to_vec())
}
