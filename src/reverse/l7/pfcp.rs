//! Packet Forwarding Control Protocol (`pfcp`, 3GPP TS 29.244) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for 3GPP TS 29.244 `pfcp` N4/Sx
//! signaling packets carried over UDP port `8805`. It validates the PFCP version (`1`), `S` SEID
//! flag, message length, optional 64-bit `SEID`, 24-bit sequence number, and core Information
//! Elements (`Cause` Type `19`, `Node ID` Type `60` for IPv4/IPv6/FQDN, and `Recovery Time Stamp`
//! Type `96`), eliding defaults and preserving unknown IEs in `residual_payload`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, be_u64, ipv4_at, ipv6_at};

use super::{ok_dissect, quote_raw_str};

/// Decodes a 3GPP TS 29.244 `Node ID` IE Type `60` into an IP or FQDN string.
fn decode_pfcp_node_id(bytes: &[u8]) -> Option<String> {
    let ntype = *bytes.first()?;
    match ntype {
        0x00 if bytes.len() == 5 => Some(IpAddr::V4(ipv4_at(bytes, 1)).to_string()),
        0x01 if bytes.len() == 17 => Some(IpAddr::V6(ipv6_at(bytes, 1)).to_string()),
        0x02 if bytes.len() > 1 => {
            let mut parts = Vec::new();
            let mut idx = 1usize;
            while idx < bytes.len() {
                let len = usize::from(bytes[idx]);
                let start = idx + 1;
                let end = start.checked_add(len)?;
                if len == 0 || len > 63 || end > bytes.len() {
                    return None;
                }
                let seg = core::str::from_utf8(&bytes[start..end]).ok()?;
                if !seg.bytes().all(|b| (0x21..=0x7E).contains(&b) && b != b'.') {
                    return None;
                }
                parts.push(seg);
                idx = end;
            }
            Some(parts.join("."))
        }
        _ => None,
    }
}

/// Dissects a 3GPP TS 29.244 PFCP signaling packet on UDP port `8805`.
pub(crate) fn dissect_pfcp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 8 {
        return None;
    }
    let flags = payload[0];
    if (flags & 0xE0) != 0x20 || (flags & 0x1E) != 0 {
        return None;
    }
    let has_seid = (flags & 0x01) != 0;
    let msg_code = payload[1];
    let msg_len = usize::from(be_u16(payload, 2));
    if 4usize.checked_add(msg_len) != Some(payload.len()) {
        return None;
    }
    let hdr_len = if has_seid { 16usize } else { 8usize };
    if payload.len() < hdr_len || payload[hdr_len - 1] != 0 {
        return None;
    }

    let seid = if has_seid {
        Some(be_u64(payload, 4))
    } else {
        None
    };
    let seq_off = if has_seid { 12 } else { 4 };
    let seq = (u32::from(payload[seq_off]) << 16)
        | (u32::from(payload[seq_off + 1]) << 8)
        | u32::from(payload[seq_off + 2]);

    if (has_seid && msg_code < 50) || (!has_seid && msg_code >= 50) {
        return None;
    }

    let (mut cause, mut node_id, mut recovery) = (None, None, None);
    let mut residual = Vec::new();
    let mut max_seen_type = 0u16;

    let mut idx = hdr_len;
    while idx < payload.len() {
        let Some(ie_hdr_end) = idx.checked_add(4) else {
            residual.extend_from_slice(&payload[idx..]);
            break;
        };
        if ie_hdr_end > payload.len() {
            residual.extend_from_slice(&payload[idx..]);
            break;
        }
        let ie_type = be_u16(payload, idx);
        let ie_len = usize::from(be_u16(payload, idx + 2));
        let Some(ie_end) = ie_hdr_end.checked_add(ie_len) else {
            residual.extend_from_slice(&payload[idx..]);
            break;
        };
        if ie_end > payload.len() {
            residual.extend_from_slice(&payload[idx..]);
            break;
        }
        let val = &payload[ie_hdr_end..ie_end];
        let raw_ie = &payload[idx..ie_end];

        if ie_type > max_seen_type && residual.is_empty() {
            match ie_type {
                19 if cause.is_none() && val.len() == 1 => {
                    cause = Some(val[0]);
                    max_seen_type = ie_type;
                }
                60 if node_id.is_none() => {
                    if let Some(s) = decode_pfcp_node_id(val) {
                        node_id = Some(s);
                        max_seen_type = ie_type;
                    } else {
                        residual.extend_from_slice(raw_ie);
                    }
                }
                96 if recovery.is_none() && val.len() == 4 => {
                    recovery = Some(be_u32(val, 0));
                    max_seen_type = ie_type;
                }
                _ => residual.extend_from_slice(raw_ie),
            }
        } else {
            residual.extend_from_slice(raw_ie);
        }
        idx = ie_end;
    }

    let mut tokens = String::from("pfcp");
    match msg_code {
        1 => {}
        2 => tokens.push_str(" heartbeatresponse"),
        5 => tokens.push_str(" associationsetuprequest"),
        6 => tokens.push_str(" associationsetupresponse"),
        7 => tokens.push_str(" msgtype \"associationupdaterequest\""),
        8 => tokens.push_str(" msgtype \"associationupdateresponse\""),
        9 => tokens.push_str(" msgtype \"associationreleaserequest\""),
        10 => tokens.push_str(" msgtype \"associationreleaseresponse\""),
        50 => tokens.push_str(" sessionestablishmentrequest"),
        51 => tokens.push_str(" sessionestablishmentresponse"),
        52 => tokens.push_str(" sessionmodificationrequest"),
        53 => tokens.push_str(" sessionmodificationresponse"),
        54 => tokens.push_str(" sessiondeletionrequest"),
        55 => tokens.push_str(" sessiondeletionresponse"),
        56 => tokens.push_str(" msgtype \"sessionreportrequest\""),
        57 => tokens.push_str(" msgtype \"sessionreportresponse\""),
        other => {
            let _ = write!(tokens, " msgtype \"{other}\"");
        }
    }

    if let Some(s) = seid {
        let def_seid = if msg_code == 50 { 0u64 } else { 1u64 };
        if s != def_seid {
            let _ = write!(tokens, " seid 0x{s:016x}");
        }
    }
    if seq != 1 {
        let _ = write!(tokens, " seqnum {seq}");
    }
    let is_resp = matches!(msg_code, 6 | 8 | 10 | 51 | 53 | 55 | 57);
    if let Some(c) = cause
        && !(is_resp && c == 1 && residual.is_empty())
    {
        let _ = write!(tokens, " cause {c}");
    }
    if let Some(nid) = node_id {
        let _ = write!(tokens, " nodeid \"{}\"", quote_raw_str(&nid));
    }
    if let Some(rec) = recovery
        && !(matches!(msg_code, 1 | 2 | 5 | 6) && rec == 0x1122_3344 && residual.is_empty())
    {
        let _ = write!(tokens, " recovery 0x{rec:08x}");
    }

    ok_dissect(Protocol::Pfcp, tokens, residual)
}
