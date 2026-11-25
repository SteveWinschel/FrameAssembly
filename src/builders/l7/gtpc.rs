//! GPRS Tunneling Protocol Control Plane v2 (`gtpc`, 3GPP TS 29.274) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire 3GPP TS 29.274 GTPv2-C control signaling
//! packets over UDP port `2123`. It builds 8-byte (`T=0`, Echo Request/Response) and 12-byte
//! (`T=1`, Create/Modify/Delete Session & Bearer) headers with 32-bit Tunnel Endpoint Identifier,
//! 24-bit Sequence Number, and 3GPP Information Elements (`IMSI` Type `1`, `Cause` Type `2`,
//! `Recovery` Type `3`, `APN` Type `71`, `PAA` Type `79`, and `RAT Type` Type `82`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b gtpc [echorequest | echoreply | echoresponse | createsessionrequest | createsessionresponse | modifybearerrequest | modifybearerresponse | deletesessionrequest | deletesessionresponse | msgtype <str>] [teid <u32>] [seqnum <u32>] [cause <u8>] [imsi <str>] [apn <str>] [rat <u8>] [recovery <u8>] [addr <ip>]`

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::*;
use crate::builders::WireContext;

/// Appends a 3GPP TS 29.274 GTPv2-C Information Element (`type`, `len(u16 BE)`, `cr_inst=0`, `val`).
fn push_gtpc_ie(out: &mut Vec<u8>, ie_type: u8, val: &[u8]) {
    let clamped = &val[..val.len().min(usize::from(u16::MAX))];
    out.push(ie_type);
    out.extend_from_slice(&(clamped.len() as u16).to_be_bytes());
    out.push(0x00); // CR=0, Instance=0
    out.extend_from_slice(clamped);
}

/// Encodes an ASCII digit string into 3GPP TS 29.274 TBCD bytes (`0xF` padded on odd lengths).
fn encode_tbcd_imsi(imsi: &str) -> Vec<u8> {
    let digits: Vec<u8> = imsi
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .take(16)
        .map(|b| b - b'0')
        .collect();
    if digits.is_empty() {
        return alloc::vec![0x00, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0];
    }
    let mut out = Vec::with_capacity(digits.len().div_ceil(2));
    let mut idx = 0usize;
    while idx < digits.len() {
        let lo = digits[idx];
        let hi = if idx + 1 < digits.len() {
            digits[idx + 1]
        } else {
            0x0F
        };
        out.push((hi << 4) | lo);
        idx += 2;
    }
    out
}

/// Encodes an Access Point Name into 3GPP TS 23.003 DNS-label format without a trailing zero root.
fn encode_apn_labels(apn: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(apn.len() + 2);
    for seg in apn.split('.').filter(|s| !s.is_empty()) {
        let len = seg.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&seg.as_bytes()[..len]);
    }
    if out.is_empty() {
        out.push(8);
        out.extend_from_slice(b"internet");
    }
    out
}

/// Builds a 3GPP TS 29.274 GTPv2-C control packet payload over UDP port `2123`.
///
/// Syntax mapping: `gtpc [echorequest | echoreply | echoresponse | createsessionrequest | createsessionresponse | modifybearerrequest | modifybearerresponse | deletesessionrequest | deletesessionresponse | msgtype <str>] [teid <u32>] [seqnum <u32>] [cause <u8>] [imsi <str>] [apn <str>] [rat <u8>] [recovery <u8>] [addr <ip>]`
#[doc(alias = "GTPC")]
#[doc(alias = "GTPv2")]
pub fn build_gtpc_payload(
    _ctx: &WireContext,
    spec: &GtpcSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let default_msg = if spec.cause.is_some() || spec.addr.is_some() {
        "createsessionresponse"
    } else if spec.teid.is_some()
        || spec.imsi.is_some()
        || spec.apn.is_some()
        || spec.rat.is_some()
    {
        "createsessionrequest"
    } else {
        "echorequest"
    };

    let mtype_norm = spec
        .msg_type
        .unwrap_or(default_msg)
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let msg_code: u8 = match mtype_norm.as_str() {
        "ECHOREQUEST" => 1,
        "ECHORESPONSE" | "ECHOREPLY" => 2,
        "CREATESESSIONREQUEST" => 32,
        "CREATESESSIONRESPONSE" => 33,
        "MODIFYBEARERREQUEST" => 34,
        "MODIFYBEARERRESPONSE" => 35,
        "DELETESESSIONREQUEST" => 36,
        "DELETESESSIONRESPONSE" => 37,
        other => other.parse::<u8>().unwrap_or(1),
    };

    let has_teid = !matches!(msg_code, 1 | 2);
    let seq = spec.seq_num.unwrap_or(1) & 0x00FF_FFFF;

    let mut ies = Vec::new();
    if let Some(imsi) = spec.imsi {
        let tbcd = encode_tbcd_imsi(imsi);
        push_gtpc_ie(&mut ies, 1, &tbcd);
    }

    let is_session_resp = matches!(msg_code, 33 | 35 | 37);
    if let Some(cause) = spec.cause {
        push_gtpc_ie(&mut ies, 2, &[cause, 0x00]);
    } else if is_session_resp && payload_bytes.is_empty() {
        push_gtpc_ie(&mut ies, 2, &[16, 0x00]); // 16 = Request accepted
    }

    let is_echo = matches!(msg_code, 1 | 2);
    if let Some(recovery) = spec.recovery {
        push_gtpc_ie(&mut ies, 3, &[recovery]);
    } else if is_echo && payload_bytes.is_empty() {
        push_gtpc_ie(&mut ies, 3, &[1]);
    }

    if let Some(apn) = spec.apn {
        let labels = encode_apn_labels(apn);
        push_gtpc_ie(&mut ies, 71, &labels);
    }

    if let Some(addr) = spec.addr {
        match addr {
            IpAddr::V4(v4) => {
                let mut paa = Vec::with_capacity(5);
                paa.push(0x01); // PDN Type IPv4
                paa.extend_from_slice(&v4.octets());
                push_gtpc_ie(&mut ies, 79, &paa);
            }
            IpAddr::V6(v6) => {
                let mut paa = Vec::with_capacity(18);
                paa.push(0x02); // PDN Type IPv6
                paa.push(64); // Prefix Length 64
                paa.extend_from_slice(&v6.octets());
                push_gtpc_ie(&mut ies, 79, &paa);
            }
        }
    }

    if let Some(rat) = spec.rat {
        push_gtpc_ie(&mut ies, 82, &[rat]);
    }

    if !payload_bytes.is_empty() {
        let max_tail = usize::from(u16::MAX).saturating_sub(8 + ies.len());
        ies.extend_from_slice(&payload_bytes[..payload_bytes.len().min(max_tail)]);
    }

    let flags = 0x40u8 | if has_teid { 0x08u8 } else { 0x00u8 };
    let msg_len = ((if has_teid { 8 } else { 4 }) + ies.len()).min(usize::from(u16::MAX)) as u16;
    let mut pkt = Vec::with_capacity(4 + usize::from(msg_len));
    pkt.push(flags);
    pkt.push(msg_code);
    pkt.extend_from_slice(&msg_len.to_be_bytes());
    if has_teid {
        let default_teid = if msg_code == 32 { 0 } else { 1 };
        pkt.extend_from_slice(&spec.teid.unwrap_or(default_teid).to_be_bytes());
    }
    pkt.push(((seq >> 16) & 0xFF) as u8);
    pkt.push(((seq >> 8) & 0xFF) as u8);
    pkt.push((seq & 0xFF) as u8);
    pkt.push(0x00); // Spare
    pkt.extend_from_slice(&ies);
    pkt
}
