//! Diagnostics over Internet Protocol (DoIP, ISO 13400-2) wire payload builder.
//!
//! This module implements [`build_doip_payload`], which serializes a [`DoipSpec`] AST node into
//! an ISO 13400-2 DoIP frame over TCP or UDP port 13400. Every packet begins with the 8-byte
//! big-endian DoIP generic header (`version`, `inv_version`, 16-bit `payload_type`, and 32-bit
//! `payload_length`) followed by the message-specific payload body for Vehicle Identification
//! (`0x0001..=0x0004`), Routing Activation (`0x0005..=0x0006`), Alive Check (`0x0007..=0x0008`),
//! Generic NACK (`0x0000`), and UDS Diagnostic Messages and acknowledgements (`0x8001..=0x8003`).

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Parses a DoIP payload type mnemonic or hex/decimal code string into a 16-bit payload type.
fn parse_doip_payload_type(raw: &str) -> u16 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "NACK" | "GENERICNACK" => 0x0000,
        "VEHICLEID" | "VEHICLEREQ" => 0x0001,
        "VEHICLEEID" => 0x0002,
        "VEHICLEVIN" => 0x0003,
        "ANNOUNCEMENT" | "VEHICLERESP" => 0x0004,
        "ROUTINGREQ" | "ROUTINGACTIVATIONREQ" => 0x0005,
        "ROUTINGRESP" | "ROUTINGACTIVATIONRESP" => 0x0006,
        "ALIVECHECKREQ" => 0x0007,
        "ALIVECHECKRESP" => 0x0008,
        "ENTITYSTATUSREQ" => 0x4001,
        "ENTITYSTATUSRESP" => 0x4002,
        "POWERMODEREQ" => 0x4003,
        "POWERMODERESP" => 0x4004,
        "DIAGNOSTIC" | "DIAG" => 0x8001,
        "DIAGACK" => 0x8002,
        "DIAGNACK" => 0x8003,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u16::from_str_radix(hex, 16).unwrap_or(0x0005)
            } else {
                norm.parse::<u16>().unwrap_or(0x0005)
            }
        }
    }
}

/// Encodes an ASCII VIN slice padded with `'0'` or truncated to exactly 17 bytes.
fn push_fixed_vin(out: &mut Vec<u8>, raw: Option<&str>) {
    let src = raw.unwrap_or("WBA00000000000001").as_bytes();
    let mut vin = [b'0'; 17];
    let n = src.len().min(17);
    vin[..n].copy_from_slice(&src[..n]);
    out.extend_from_slice(&vin);
}

/// Builds an ISO 13400-2 DoIP TCP or UDP application-layer payload from [`DoipSpec`].
pub fn build_doip_payload(
    _ctx: &WireContext,
    spec: &DoipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let version = spec.version.unwrap_or(0x02);
    let inv_version = spec.inv_version.unwrap_or(!version);
    let default_msg = if spec.dst.is_some() || !payload_bytes.is_empty() {
        "diagnostic"
    } else {
        "routingreq"
    };
    let ptype = parse_doip_payload_type(spec.msg_type.unwrap_or(default_msg));
    let eid = spec.eid.unwrap_or([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let gid = spec.gid.unwrap_or([0x00; 6]);

    let mut body = Vec::new();
    match ptype {
        0x0000 => {
            body.push(spec.code.unwrap_or(0x00));
            body.extend_from_slice(payload_bytes);
        }
        0x0001 => {
            body.extend_from_slice(payload_bytes);
        }
        0x0002 => {
            body.extend_from_slice(&eid);
            body.extend_from_slice(payload_bytes);
        }
        0x0003 => {
            push_fixed_vin(&mut body, spec.vin);
            body.extend_from_slice(payload_bytes);
        }
        0x0004 => {
            push_fixed_vin(&mut body, spec.vin);
            body.extend_from_slice(&spec.src.unwrap_or(0x00E0).to_be_bytes());
            body.extend_from_slice(&eid);
            body.extend_from_slice(&gid);
            body.push(spec.code.unwrap_or(0x00));
            body.extend_from_slice(payload_bytes);
        }
        0x0005 => {
            body.extend_from_slice(&spec.src.unwrap_or(0x0E00).to_be_bytes());
            body.push(spec.code.unwrap_or(0x00));
            body.extend_from_slice(&0u32.to_be_bytes());
            body.extend_from_slice(payload_bytes);
        }
        0x0006 => {
            body.extend_from_slice(&spec.src.unwrap_or(0x0E00).to_be_bytes());
            body.extend_from_slice(&spec.dst.unwrap_or(0x00E0).to_be_bytes());
            body.push(spec.code.unwrap_or(0x10));
            body.extend_from_slice(&0u32.to_be_bytes());
            body.extend_from_slice(payload_bytes);
        }
        0x0007 | 0x4001 | 0x4003 => {
            body.extend_from_slice(payload_bytes);
        }
        0x0008 => {
            body.extend_from_slice(&spec.src.unwrap_or(0x0E00).to_be_bytes());
            body.extend_from_slice(payload_bytes);
        }
        0x4002 => {
            body.extend_from_slice(&[0x00, 0x08, 0x01, 0x00, 0x00, 0x10, 0x00]);
            body.extend_from_slice(payload_bytes);
        }
        0x4004 => {
            body.push(spec.code.unwrap_or(0x01));
            body.extend_from_slice(payload_bytes);
        }
        0x8001 => {
            body.extend_from_slice(&spec.src.unwrap_or(0x0E00).to_be_bytes());
            body.extend_from_slice(&spec.dst.unwrap_or(0x00E0).to_be_bytes());
            if payload_bytes.is_empty() {
                body.extend_from_slice(&[0x3E, 0x00]); // UDS TesterPresent
            } else {
                body.extend_from_slice(payload_bytes);
            }
        }
        0x8002 | 0x8003 => {
            let default_code = if ptype == 0x8002 { 0x00 } else { 0x03 };
            body.extend_from_slice(&spec.src.unwrap_or(0x00E0).to_be_bytes());
            body.extend_from_slice(&spec.dst.unwrap_or(0x0E00).to_be_bytes());
            body.push(spec.code.unwrap_or(default_code));
            body.extend_from_slice(payload_bytes);
        }
        _ => {
            body.extend_from_slice(payload_bytes);
        }
    }

    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut pkt = Vec::with_capacity(8 + body.len());
    pkt.push(version);
    pkt.push(inv_version);
    pkt.extend_from_slice(&ptype.to_be_bytes());
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
