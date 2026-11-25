//! Packet Forwarding Control Protocol (`pfcp`, 3GPP TS 29.244) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire 3GPP TS 29.244 PFCP signaling packets over
//! UDP port `8805`. It handles both 8-byte Node-level headers (`S=0` for Heartbeat and
//! Association Setup/Update/Release) and 16-byte Session-level headers (`S=1` carrying a 64-bit
//! `SEID` for Session Establishment, Modification, Deletion, and Report messages) with `Cause`
//! (IE `19`), `Node ID` (IE `60` supporting IPv4, IPv6, and DNS-label FQDN), and `Recovery Time
//! Stamp` (IE `96`) Information Elements.
//!
//! Canonical `.frasm` syntax:
//! `a -> b pfcp [heartbeatrequest | heartbeatresponse | associationsetuprequest | associationsetupresponse | sessionestablishmentrequest | sessionestablishmentresponse | sessionmodificationrequest | sessionmodificationresponse | sessiondeletionrequest | sessiondeletionresponse | msgtype <str>] [seid <u64>] [seqnum <u32>] [cause <u8>] [nodeid <ip|str>] [recovery <u32>]`

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::*;
use crate::builders::WireContext;

/// Appends a 3GPP TS 29.244 PFCP Information Element (`type(u16 BE)`, `len(u16 BE)`, `val`).
fn push_pfcp_ie(out: &mut Vec<u8>, ie_type: u16, val: &[u8]) {
    let clamped = &val[..val.len().min(usize::from(u16::MAX))];
    out.extend_from_slice(&ie_type.to_be_bytes());
    out.extend_from_slice(&(clamped.len() as u16).to_be_bytes());
    out.extend_from_slice(clamped);
}

/// Encodes a `Node ID` IE Type `60` value (Type `0` IPv4, `1` IPv6, or `2` DNS-label FQDN without trailing zero).
fn encode_pfcp_node_id(node_str: &str) -> Vec<u8> {
    if let Ok(ip) = node_str.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let mut out = Vec::with_capacity(5);
                out.push(0x00); // IPv4
                out.extend_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => {
                let mut out = Vec::with_capacity(17);
                out.push(0x01); // IPv6
                out.extend_from_slice(&v6.octets());
                out
            }
        };
    }
    let mut out = Vec::with_capacity(node_str.len() + 3);
    out.push(0x02); // FQDN
    for seg in node_str.split('.').filter(|s| !s.is_empty()) {
        let len = seg.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&seg.as_bytes()[..len]);
    }
    if out.len() == 1 {
        out.push(4);
        out.extend_from_slice(b"node");
    }
    out
}

/// Builds a 3GPP TS 29.244 PFCP control packet payload over UDP port `8805`.
///
/// Syntax mapping: `pfcp [heartbeatrequest | heartbeatresponse | associationsetuprequest | associationsetupresponse | sessionestablishmentrequest | sessionestablishmentresponse | sessionmodificationrequest | sessionmodificationresponse | sessiondeletionrequest | sessiondeletionresponse | msgtype <str>] [seid <u64>] [seqnum <u32>] [cause <u8>] [nodeid <ip|str>] [recovery <u32>]`
#[doc(alias = "PFCP")]
#[doc(alias = "TS29244")]
pub fn build_pfcp_payload(
    ctx: &WireContext,
    spec: &PfcpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let default_msg = if spec.seid.is_some() {
        "sessionestablishmentrequest"
    } else {
        "heartbeatrequest"
    };
    let mtype_norm = spec
        .msg_type
        .unwrap_or(default_msg)
        .to_ascii_uppercase()
        .replace(['_', '-'], "");

    let msg_code: u8 = match mtype_norm.as_str() {
        "HEARTBEATREQUEST" => 1,
        "HEARTBEATRESPONSE" => 2,
        "ASSOCIATIONSETUPREQUEST" => 5,
        "ASSOCIATIONSETUPRESPONSE" => 6,
        "ASSOCIATIONUPDATEREQUEST" => 7,
        "ASSOCIATIONUPDATERESPONSE" => 8,
        "ASSOCIATIONRELEASEREQUEST" => 9,
        "ASSOCIATIONRELEASERESPONSE" => 10,
        "SESSIONESTABLISHMENTREQUEST" => 50,
        "SESSIONESTABLISHMENTRESPONSE" => 51,
        "SESSIONMODIFICATIONREQUEST" => 52,
        "SESSIONMODIFICATIONRESPONSE" => 53,
        "SESSIONDELETIONREQUEST" => 54,
        "SESSIONDELETIONRESPONSE" => 55,
        "SESSIONREPORTREQUEST" => 56,
        "SESSIONREPORTRESPONSE" => 57,
        other => other.parse::<u8>().unwrap_or(1),
    };

    let has_seid = msg_code >= 50;
    let seq = spec.seq_num.unwrap_or(1) & 0x00FF_FFFF;

    let mut ies = Vec::new();
    let is_resp = matches!(msg_code, 6 | 8 | 10 | 51 | 53 | 55 | 57);
    if let Some(cause) = spec.cause {
        push_pfcp_ie(&mut ies, 19, &[cause]);
    } else if is_resp && payload_bytes.is_empty() {
        push_pfcp_ie(&mut ies, 19, &[1]); // Cause 1: Request accepted
    }

    if let Some(node_str) = spec.node_id {
        let encoded = encode_pfcp_node_id(node_str);
        push_pfcp_ie(&mut ies, 60, &encoded);
    } else if matches!(msg_code, 5 | 6 | 50) && payload_bytes.is_empty() {
        let node_val = match ctx.src_ip {
            IpAddr::V4(v4) => {
                let mut v = Vec::with_capacity(5);
                v.push(0x00);
                v.extend_from_slice(&v4.octets());
                v
            }
            IpAddr::V6(v6) => {
                let mut v = Vec::with_capacity(17);
                v.push(0x01);
                v.extend_from_slice(&v6.octets());
                v
            }
        };
        push_pfcp_ie(&mut ies, 60, &node_val);
    }

    if let Some(rec) = spec.recovery {
        push_pfcp_ie(&mut ies, 96, &rec.to_be_bytes());
    } else if matches!(msg_code, 1 | 2 | 5 | 6) && payload_bytes.is_empty() {
        push_pfcp_ie(&mut ies, 96, &0x1122_3344u32.to_be_bytes());
    }

    if !payload_bytes.is_empty() {
        let hdr_after_len = if has_seid { 12 } else { 4 };
        let max_tail = usize::from(u16::MAX).saturating_sub(hdr_after_len + ies.len());
        ies.extend_from_slice(&payload_bytes[..payload_bytes.len().min(max_tail)]);
    }

    let flags = 0x20u8 | u8::from(has_seid);
    let msg_len = ((if has_seid { 12 } else { 4 }) + ies.len()).min(usize::from(u16::MAX)) as u16;
    let mut pkt = Vec::with_capacity(4 + usize::from(msg_len));
    pkt.push(flags);
    pkt.push(msg_code);
    pkt.extend_from_slice(&msg_len.to_be_bytes());
    if has_seid {
        let default_seid = if msg_code == 50 { 0u64 } else { 1u64 };
        pkt.extend_from_slice(&spec.seid.unwrap_or(default_seid).to_be_bytes());
    }
    pkt.push(((seq >> 16) & 0xFF) as u8);
    pkt.push(((seq >> 8) & 0xFF) as u8);
    pkt.push((seq & 0xFF) as u8);
    pkt.push(0x00); // Spare
    pkt.extend_from_slice(&ies);
    pkt
}
