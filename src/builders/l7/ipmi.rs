//! Intelligent Platform Management Interface (`ipmi`, RMCP / ASF v2.0 / IPMI v1.5 / RMCP+ v2.0) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Remote Management Control Protocol (`RMCP`),
//! Alert Standard Forum (`ASF`), IPMI v1.5, and IPMI v2.0 (`RMCP+`) management payloads over UDP
//! port `623`. It emits 4-byte RMCP headers (`0x06 0x00 0xFF 0x06` for ASF Presence Ping/Pong,
//! `0x06 0x00 0xFF 0x07` for IPMI/RMCP+), IPMI v1.5 unauthenticated session wrappers with IPMB
//! request/response frames and two's-complement header/body checksums, and IPMI v2.0 RMCP+ session
//! and pre-session (`Open Session`, `RAKP 1..4`) packets.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ipmi [ping | pong | msgtype <str>] [version <u8>] [request | response] [netfn <u8>] [cmd <u8>] [lun <u8>] [rqseq <u8>] [sessionid <u32>] [seqnum <u32>] [status <u8>]`

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Canonical 16-byte ASF v2.0 Presence Pong capability payload (DMTF IANA `4542`, IPMI supported).
const DEFAULT_ASF_PONG_DATA: [u8; 16] = [
    0x00, 0x00, 0x11, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Canonical 32-byte RMCP+ Open Session Request body (`tag`, `max_priv=4`, `console_sid`, and null suites).
fn default_open_session_req(tag: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&[tag, 0x04, 0x00, 0x00]);
    out.extend_from_slice(&0x1122_3344u32.to_le_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]);
    out
}

/// Canonical 36-byte RMCP+ Open Session Response body (`tag`, `status`, `max_priv=4`, `console_sid`, `bmc_sid`, and suites).
fn default_open_session_resp(tag: u8, status: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&[tag, status, 0x04, 0x00]);
    out.extend_from_slice(&0x1122_3344u32.to_le_bytes());
    out.extend_from_slice(&0x5566_7788u32.to_le_bytes());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]);
    out
}

/// Builds a deterministic RMCP+ pre-session handshake body (`0x10..=0x15`) when `payload_bytes` is empty.
fn default_rmcp_plus_body(payload_type: u8, tag: u8, status: u8) -> Vec<u8> {
    let mut out = Vec::new();
    match payload_type {
        0x10 => return default_open_session_req(tag),
        0x11 => return default_open_session_resp(tag, status),
        0x12 => {
            // RAKP Message 1 (28 bytes)
            out.extend_from_slice(&[tag, 0x00, 0x00, 0x00]);
            out.extend_from_slice(&0x5566_7788u32.to_le_bytes());
            out.extend_from_slice(&[0xA1u8; 16]);
            out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        }
        0x13 => {
            // RAKP Message 2 (40 bytes)
            out.extend_from_slice(&[tag, status, 0x00, 0x00]);
            out.extend_from_slice(&0x1122_3344u32.to_le_bytes());
            out.extend_from_slice(&[0xB2u8; 16]);
            out.extend_from_slice(&[0xC3u8; 16]);
        }
        0x14 => {
            // RAKP Message 3 (8 bytes)
            out.extend_from_slice(&[tag, status, 0x00, 0x00]);
            out.extend_from_slice(&0x5566_7788u32.to_le_bytes());
        }
        _ => {
            // RAKP Message 4 (8 bytes)
            out.extend_from_slice(&[tag, status, 0x00, 0x00]);
            out.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        }
    }
    out
}

/// Builds an IPMB message frame with two's-complement header (`chk1`) and body (`chk2`) checksums.
fn build_ipmb_frame(
    is_resp: bool,
    netfn: u8,
    lun: u8,
    rqseq: u8,
    cmd: u8,
    status: u8,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let (rs_addr, rq_addr) = if is_resp { (0x81u8, 0x20u8) } else { (0x20u8, 0x81u8) };
    let netfn_lun = ((netfn & 0x3F) << 2) | (lun & 0x03);
    let chk1 = 0u8.wrapping_sub(rs_addr.wrapping_add(netfn_lun));
    let rqseq_lun = ((rqseq & 0x3F) << 2) | (lun & 0x03);

    let mut body = Vec::with_capacity(4 + usize::from(is_resp) + payload_bytes.len());
    body.push(rq_addr);
    body.push(rqseq_lun);
    body.push(cmd);
    if is_resp {
        body.push(status);
    }
    body.extend_from_slice(payload_bytes);

    let body_sum = body.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    let chk2 = 0u8.wrapping_sub(body_sum);

    let mut ipmb = Vec::with_capacity(4 + body.len());
    ipmb.push(rs_addr);
    ipmb.push(netfn_lun);
    ipmb.push(chk1);
    ipmb.extend_from_slice(&body);
    ipmb.push(chk2);
    ipmb
}

/// Builds an RMCP / ASF / IPMI v1.5 / RMCP+ v2.0 packet payload over UDP port `623`.
///
/// Syntax mapping: `ipmi [ping | pong | msgtype <str>] [version <u8>] [request | response] [netfn <u8>] [cmd <u8>] [lun <u8>] [rqseq <u8>] [sessionid <u32>] [seqnum <u32>] [status <u8>]`
#[doc(alias = "IPMI")]
#[doc(alias = "RMCP")]
#[doc(alias = "ASF")]
pub fn build_ipmi_payload(
    _ctx: &WireContext,
    spec: &IpmiSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mtype = spec
        .msg_type
        .unwrap_or("ipmi")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");

    if mtype == "PING" || mtype == "PONG" {
        let is_pong = mtype == "PONG";
        let msg_tag = (spec.seq_num.unwrap_or(0) & 0xFF) as u8;
        let data: &[u8] = if !payload_bytes.is_empty() {
            &payload_bytes[..payload_bytes.len().min(255)]
        } else if is_pong {
            &DEFAULT_ASF_PONG_DATA
        } else {
            &[]
        };
        let mut pkt = Vec::with_capacity(12 + data.len());
        pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x06]); // RMCP v1.0, class ASF (0x06)
        pkt.extend_from_slice(&[0x00, 0x00, 0x11, 0xBE]); // DMTF IANA 4542
        pkt.push(if is_pong { 0x40 } else { 0x80 });
        pkt.push(msg_tag);
        pkt.push(0x00); // Reserved
        pkt.push(data.len() as u8);
        pkt.extend_from_slice(data);
        return pkt;
    }

    let rmcp_plus_type = match mtype.as_str() {
        "OPENSESSION" => Some(0x10u8),
        "OPENSESSIONRESP" => Some(0x11u8),
        "RAKP1" => Some(0x12u8),
        "RAKP2" => Some(0x13u8),
        "RAKP3" => Some(0x14u8),
        "RAKP4" => Some(0x15u8),
        _ => None,
    };

    let session_id = spec.session_id.unwrap_or(0);
    let seq_num = spec.seq_num.unwrap_or(0);
    let status = spec.status.unwrap_or(0);

    if let Some(ptype) = rmcp_plus_type {
        let tag = spec.rqseq.unwrap_or(0);
        let body = if payload_bytes.is_empty() {
            default_rmcp_plus_body(ptype, tag, status)
        } else {
            payload_bytes[..payload_bytes.len().min(usize::from(u16::MAX))].to_vec()
        };
        let mut pkt = Vec::with_capacity(16 + body.len());
        pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]); // RMCP v1.0, class IPMI (0x07)
        pkt.push(0x06); // Auth Type: RMCP+
        pkt.push(ptype);
        pkt.extend_from_slice(&session_id.to_le_bytes());
        pkt.extend_from_slice(&seq_num.to_le_bytes());
        pkt.extend_from_slice(&(body.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&body);
        return pkt;
    }

    let mut netfn = spec
        .netfn
        .unwrap_or(if spec.is_response { 0x07 } else { 0x06 })
        & 0x3F;
    if spec.is_response && (netfn & 1) == 0 {
        netfn |= 1;
    }
    let is_resp = spec.is_response || (netfn & 1) == 1;
    let cmd = spec.cmd.unwrap_or(0x01);
    let lun = spec.lun.unwrap_or(0) & 0x03;
    let rqseq = spec.rqseq.unwrap_or(1) & 0x3F;
    let version = spec.version.unwrap_or(1);

    let max_ipmb_data = if version == 2 { 65500 } else { 248 };
    let data_slice = &payload_bytes[..payload_bytes.len().min(max_ipmb_data)];
    let ipmb = build_ipmb_frame(is_resp, netfn, lun, rqseq, cmd, status, data_slice);

    if version == 2 {
        let mut pkt = Vec::with_capacity(16 + ipmb.len());
        pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);
        pkt.push(0x06); // RMCP+
        pkt.push(0x00); // Payload Type: IPMI (0x00)
        pkt.extend_from_slice(&session_id.to_le_bytes());
        pkt.extend_from_slice(&seq_num.to_le_bytes());
        pkt.extend_from_slice(&(ipmb.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&ipmb);
        pkt
    } else {
        let mut pkt = Vec::with_capacity(14 + ipmb.len());
        pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);
        pkt.push(0x00); // Auth Type: None
        pkt.extend_from_slice(&seq_num.to_le_bytes());
        pkt.extend_from_slice(&session_id.to_le_bytes());
        pkt.push(ipmb.len() as u8);
        pkt.extend_from_slice(&ipmb);
        pkt
    }
}
