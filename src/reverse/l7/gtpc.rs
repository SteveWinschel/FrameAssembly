//! GPRS Tunneling Protocol Control Plane v2 (`gtpc`, 3GPP TS 29.274) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for 3GPP TS 29.274 `gtpc` GTPv2-C
//! packets carried over UDP port `2123`. It validates the GTPv2-C version (`2`), `T` TEID
//! presence bit, message length, 24-bit sequence number, and Information Elements (`IMSI` Type `1`,
//! `Cause` Type `2`, `Recovery` Type `3`, `APN` Type `71`, `PAA` Type `79`, and `RAT Type` Type `82`),
//! eliding defaults cleanly and preserving unknown or extra IEs in `residual_payload`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at};

use super::{ok_dissect, quote_raw_str};

/// Decodes a 3GPP TS 29.274 TBCD IMSI byte slice into an ASCII digit string.
fn decode_tbcd_imsi(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for (i, &b) in bytes.iter().enumerate() {
        let lo = b & 0x0F;
        let hi = (b >> 4) & 0x0F;
        if lo > 9 {
            return None;
        }
        out.push((b'0' + lo) as char);
        if hi == 0x0F {
            if i + 1 != bytes.len() {
                return None;
            }
            break;
        }
        if hi > 9 {
            return None;
        }
        out.push((b'0' + hi) as char);
    }
    Some(out)
}

/// Decodes a 3GPP TS 23.003 DNS-label-encoded APN without a trailing zero root into a dotted string.
fn decode_apn_labels(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut idx = 0usize;
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

/// Dissects a 3GPP TS 29.274 GTPv2-C message on UDP port `2123`.
pub(crate) fn dissect_gtpc(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 8 {
        return None;
    }
    let flags = payload[0];
    if (flags & 0xE0) != 0x40 || (flags & 0x17) != 0 {
        return None;
    }
    let has_teid = (flags & 0x08) != 0;
    let msg_code = payload[1];
    let msg_len = usize::from(be_u16(payload, 2));
    if 4usize.checked_add(msg_len) != Some(payload.len()) {
        return None;
    }
    let hdr_len = if has_teid { 12usize } else { 8usize };
    if payload.len() < hdr_len || payload[hdr_len - 1] != 0 {
        return None;
    }

    let teid = if has_teid {
        Some(be_u32(payload, 4))
    } else {
        None
    };
    let seq_off = if has_teid { 8 } else { 4 };
    let seq = (u32::from(payload[seq_off]) << 16)
        | (u32::from(payload[seq_off + 1]) << 8)
        | u32::from(payload[seq_off + 2]);

    let (mut imsi, mut cause, mut recovery, mut apn, mut addr, mut rat) =
        (None, None, None, None, None, None);
    let mut residual = Vec::new();
    let mut max_seen_type = 0u8;

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
        let ie_type = payload[idx];
        let ie_len = usize::from(be_u16(payload, idx + 1));
        let ie_cr_inst = payload[idx + 3];
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

        if ie_cr_inst == 0 && ie_type > max_seen_type && residual.is_empty() {
            match ie_type {
                1 if imsi.is_none() => {
                    if let Some(s) = decode_tbcd_imsi(val) {
                        imsi = Some(s);
                        max_seen_type = ie_type;
                    } else {
                        residual.extend_from_slice(raw_ie);
                    }
                }
                2 if cause.is_none() && val.len() == 2 && val[1] == 0 => {
                    cause = Some(val[0]);
                    max_seen_type = ie_type;
                }
                3 if recovery.is_none() && val.len() == 1 => {
                    recovery = Some(val[0]);
                    max_seen_type = ie_type;
                }
                71 if apn.is_none() => {
                    if let Some(s) = decode_apn_labels(val) {
                        apn = Some(s);
                        max_seen_type = ie_type;
                    } else {
                        residual.extend_from_slice(raw_ie);
                    }
                }
                79 if addr.is_none() => {
                    if val.len() == 5 && val[0] == 0x01 {
                        addr = Some(IpAddr::V4(ipv4_at(val, 1)));
                        max_seen_type = ie_type;
                    } else if val.len() == 18 && val[0] == 0x02 && val[1] == 64 {
                        addr = Some(IpAddr::V6(ipv6_at(val, 2)));
                        max_seen_type = ie_type;
                    } else {
                        residual.extend_from_slice(raw_ie);
                    }
                }
                82 if rat.is_none() && val.len() == 1 => {
                    rat = Some(val[0]);
                    max_seen_type = ie_type;
                }
                _ => residual.extend_from_slice(raw_ie),
            }
        } else {
            residual.extend_from_slice(raw_ie);
        }
        idx = ie_end;
    }

    let mut tokens = String::from("gtpc");
    if (has_teid && matches!(msg_code, 1 | 2)) || (!has_teid && matches!(msg_code, 32..=37)) {
        return None;
    }
    match msg_code {
        1 => {}
        2 => tokens.push_str(" echoresponse"),
        32 => tokens.push_str(" createsessionrequest"),
        33 => tokens.push_str(" createsessionresponse"),
        34 => tokens.push_str(" modifybearerrequest"),
        35 => tokens.push_str(" modifybearerresponse"),
        36 => tokens.push_str(" deletesessionrequest"),
        37 => tokens.push_str(" deletesessionresponse"),
        other => {
            let _ = write!(tokens, " msgtype \"{other}\"");
        }
    }

    if let Some(t) = teid {
        let def_teid = if msg_code == 32 { 0 } else { 1 };
        if t != def_teid {
            let _ = write!(tokens, " teid 0x{t:08x}");
        }
    }
    if seq != 1 {
        let _ = write!(tokens, " seqnum {seq}");
    }
    if let Some(c) = cause
        && !(matches!(msg_code, 33 | 35 | 37) && c == 16 && residual.is_empty())
    {
        let _ = write!(tokens, " cause {c}");
    }
    if let Some(i) = imsi {
        let _ = write!(tokens, " imsi \"{}\"", quote_raw_str(&i));
    }
    if let Some(a) = apn {
        let _ = write!(tokens, " apn \"{}\"", quote_raw_str(&a));
    }
    if let Some(r) = rat {
        let _ = write!(tokens, " rat {r}");
    }
    if let Some(rec) = recovery
        && !(matches!(msg_code, 1 | 2) && rec == 1 && residual.is_empty())
    {
        let _ = write!(tokens, " recovery {rec}");
    }
    if let Some(ip) = addr {
        let _ = write!(tokens, " addr {ip}");
    }

    ok_dissect(Protocol::Gtpc, tokens, residual)
}
