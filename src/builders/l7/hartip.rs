//! HART-IP (HCF Spec 085 Industrial Field Instrumentation) wire payload builder.
//!
//! This module implements [`build_hartip_payload`], which serializes a [`HartipSpec`] AST
//! specification into a FieldComm Group HART-IP packet over UDP or TCP port 5094. It constructs
//! the 8-byte big-endian header (`Version`, `Message Type`, `Message ID`, `Status`, 16-bit
//! `Transaction ID`, and `Message Length`) followed by Session Initiate (`0`: 1-byte master type
//! and 4-byte inactivity close timer), Session Close (`1`), Keep Alive (`2`), Token-Passing
//! pass-through HART PDU (`3` with short polling frame, optional 2-byte response code, and LRC
//! checksum), Direct PDU (`4`), or Discovery (`5`) bodies.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Default HART-IP Session Initiate inactivity close timer (`60000` ms).
pub(crate) const DEFAULT_HARTIP_INACTIVITY_MS: u32 = 60_000;

/// Parses a HART-IP Message Type string or decimal byte into `0..=3` (Request/Response/Publish/NAK).
fn parse_hartip_msg_type(raw: &str) -> u8 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "REQ" | "REQUEST" | "0" => 0,
        "RESP" | "RESPONSE" | "1" => 1,
        "PUB" | "PUBLISH" | "BURST" | "2" => 2,
        "NAK" | "ERROR" | "3" => 3,
        _ => norm.parse::<u8>().unwrap_or(0),
    }
}

/// Builds a FieldComm Group HART-IP packet payload over UDP or TCP port 5094.
pub fn build_hartip_payload(
    _ctx: &WireContext,
    spec: &HartipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let version = spec.version.unwrap_or(1);
    let msg_type = if spec.is_response {
        1
    } else {
        spec.msg_type.map_or(0, parse_hartip_msg_type)
    };
    let msg_id = spec.msg_id.unwrap_or_else(|| {
        if spec.poll_addr.is_some() || spec.hart_cmd.is_some() {
            3
        } else {
            0
        }
    });
    let status = spec.status.unwrap_or(0);
    let txid = spec.txid.unwrap_or(1);

    let mut body = Vec::new();
    match msg_id {
        0 => {
            body.push(spec.master_type.unwrap_or(1));
            body.extend_from_slice(
                &spec
                    .inactivity_timer
                    .unwrap_or(DEFAULT_HARTIP_INACTIVITY_MS)
                    .to_be_bytes(),
            );
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        3 => {
            let delim = if msg_type == 1 { 0x06u8 } else { 0x02u8 };
            let addr = spec.poll_addr.unwrap_or(0) & 0x3F;
            let cmd = spec.hart_cmd.unwrap_or(0);
            if msg_type == 1 {
                let data_chunk = &payload_bytes[..payload_bytes.len().min(253)];
                let byte_count = (2 + data_chunk.len()) as u8;
                body.extend_from_slice(&[delim, addr, cmd, byte_count, 0x00, 0x00]);
                body.extend_from_slice(data_chunk);
            } else {
                let data_chunk = &payload_bytes[..payload_bytes.len().min(255)];
                let byte_count = data_chunk.len() as u8;
                body.extend_from_slice(&[delim, addr, cmd, byte_count]);
                body.extend_from_slice(data_chunk);
            }
            let lrc = body.iter().fold(0u8, |acc, &b| acc ^ b);
            body.push(lrc);
        }
        _ => {
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
    }

    let msg_len = u16::try_from(8usize.saturating_add(body.len())).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(usize::from(msg_len));
    pkt.push(version);
    pkt.push(msg_type);
    pkt.push(msg_id);
    pkt.push(status);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&msg_len.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
