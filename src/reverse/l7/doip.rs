//! Diagnostics over Internet Protocol (DoIP, ISO 13400-2) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for ISO 13400-2 `doip` packets over
//! TCP, UDP, and SCTP transports (port `13400` and custom gateways matching canonical DoIP
//! version/inverse-version headers). It decodes `version`, `invversion`, payload types
//! (`routingreq`, `routingresp`, `diagnostic`, `diagack`, `diagnack`, `vehicleid`, `vehicleeid`,
//! `vehiclevin`, `announcement`, `alivecheckreq`, `alivecheckresp`, `nack`, numeric `msgtype`),
//! logical addresses (`src`, `dst`), `code`, 17-byte ASCII `vin`, and 6-byte `eid`/`gid` fields,
//! emitting `transport udp` on UDP captures.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::l7::quote_raw_str;
use crate::reverse::{ProtocolDissection, mac_at, push_mac_if};

/// Default 17-character ASCII VIN emitted when `vin` is omitted in `.frasm`.
const DEFAULT_DOIP_VIN: &str = "WBA00000000000001";

/// Default 6-byte DoIP Entity Identification (`02:00:00:00:00:01`).
const DEFAULT_DOIP_EID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Decodes a 17-byte ASCII VIN slice, appending `vin "..."` when non-default.
fn push_vin_if(tokens: &mut String, bytes: &[u8]) -> Option<()> {
    if bytes.len() != 17 || !bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    let s = core::str::from_utf8(bytes).ok()?;
    if s != DEFAULT_DOIP_VIN {
        let _ = write!(tokens, " vin \"{}\"", quote_raw_str(s));
    }
    Some(())
}

/// Dissects an ISO 13400-2 `doip` message over TCP, UDP, or SCTP.
pub(crate) fn dissect_doip(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 8
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
    {
        return None;
    }

    let ver = payload[0];
    let inv_ver = payload[1];
    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
    let body_len = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if 8usize.checked_add(body_len) != Some(payload.len()) {
        return None;
    }

    let on_known_port = src_port == 13400 || dst_port == 13400;
    let valid_ver_pair = (ver ^ inv_ver) == 0xFF && matches!(ver, 0x01 | 0x02 | 0xFF);
    if !on_known_port && !valid_ver_pair {
        return None;
    }

    let body = &payload[8..];
    let mut tokens = String::from("doip");
    let explicit_transport = if matches!(transport, TransportProto::Udp) {
        Some(TransportProto::Udp)
    } else {
        None
    };

    let residual: Vec<u8> = match ptype {
        0x0000 => {
            let code = *body.first()?;
            tokens.push_str(" nack");
            if code != 0x00 {
                let _ = write!(tokens, " code 0x{code:02x}");
            }
            body[1..].to_vec()
        }
        0x0001 => {
            tokens.push_str(" vehicleid");
            body.to_vec()
        }
        0x0002 => {
            if body.len() < 6 {
                return None;
            }
            tokens.push_str(" vehicleeid");
            push_mac_if(&mut tokens, "eid", mac_at(body, 0), DEFAULT_DOIP_EID);
            body[6..].to_vec()
        }
        0x0003 => {
            if body.len() < 17 {
                return None;
            }
            tokens.push_str(" vehiclevin");
            push_vin_if(&mut tokens, &body[0..17])?;
            body[17..].to_vec()
        }
        0x0004 => {
            if body.len() < 32 {
                return None;
            }
            tokens.push_str(" announcement");
            push_vin_if(&mut tokens, &body[0..17])?;
            let logical = u16::from_be_bytes([body[17], body[18]]);
            if logical != 0x00E0 {
                let _ = write!(tokens, " src 0x{logical:04x}");
            }
            push_mac_if(&mut tokens, "eid", mac_at(body, 19), DEFAULT_DOIP_EID);
            push_mac_if(&mut tokens, "gid", mac_at(body, 25), [0x00; 6]);
            if body[31] != 0x00 {
                let _ = write!(tokens, " code 0x{:02x}", body[31]);
            }
            body[32..].to_vec()
        }
        0x0005 => {
            if body.len() < 7 || body[3..7] != [0, 0, 0, 0] {
                return None;
            }
            let src = u16::from_be_bytes([body[0], body[1]]);
            if src != 0x0E00 {
                let _ = write!(tokens, " src 0x{src:04x}");
            }
            if body[2] != 0x00 {
                let _ = write!(tokens, " code 0x{:02x}", body[2]);
            }
            body[7..].to_vec()
        }
        0x0006 => {
            if body.len() < 9 || body[5..9] != [0, 0, 0, 0] {
                return None;
            }
            tokens.push_str(" routingresp");
            let src = u16::from_be_bytes([body[0], body[1]]);
            let dst = u16::from_be_bytes([body[2], body[3]]);
            if src != 0x0E00 {
                let _ = write!(tokens, " src 0x{src:04x}");
            }
            if dst != 0x00E0 {
                let _ = write!(tokens, " dst 0x{dst:04x}");
            }
            if body[4] != 0x10 {
                let _ = write!(tokens, " code 0x{:02x}", body[4]);
            }
            body[9..].to_vec()
        }
        0x0007 => {
            tokens.push_str(" alivecheckreq");
            body.to_vec()
        }
        0x0008 => {
            if body.len() < 2 {
                return None;
            }
            tokens.push_str(" alivecheckresp");
            let src = u16::from_be_bytes([body[0], body[1]]);
            if src != 0x0E00 {
                let _ = write!(tokens, " src 0x{src:04x}");
            }
            body[2..].to_vec()
        }
        0x8001 => {
            if body.len() < 5 {
                return None;
            }
            tokens.push_str(" diagnostic");
            let src = u16::from_be_bytes([body[0], body[1]]);
            let dst = u16::from_be_bytes([body[2], body[3]]);
            if src != 0x0E00 {
                let _ = write!(tokens, " src 0x{src:04x}");
            }
            if dst != 0x00E0 {
                let _ = write!(tokens, " dst 0x{dst:04x}");
            }
            let uds = &body[4..];
            if uds == [0x3E, 0x00] {
                Vec::new()
            } else {
                uds.to_vec()
            }
        }
        0x8002 | 0x8003 => {
            if body.len() < 5 {
                return None;
            }
            if ptype == 0x8002 {
                tokens.push_str(" diagack");
            } else {
                tokens.push_str(" diagnack");
            }
            let src = u16::from_be_bytes([body[0], body[1]]);
            let dst = u16::from_be_bytes([body[2], body[3]]);
            let default_code = if ptype == 0x8002 { 0x00 } else { 0x03 };
            if src != 0x00E0 {
                let _ = write!(tokens, " src 0x{src:04x}");
            }
            if dst != 0x0E00 {
                let _ = write!(tokens, " dst 0x{dst:04x}");
            }
            if body[4] != default_code {
                let _ = write!(tokens, " code 0x{:02x}", body[4]);
            }
            body[5..].to_vec()
        }
        0x4001 => {
            tokens.push_str(" msgtype 0x4001");
            body.to_vec()
        }
        0x4002 => {
            let rem = body.strip_prefix(&[0x00, 0x08, 0x01, 0x00, 0x00, 0x10, 0x00])?;
            tokens.push_str(" msgtype 0x4002");
            rem.to_vec()
        }
        0x4003 => {
            tokens.push_str(" msgtype 0x4003");
            body.to_vec()
        }
        0x4004 => {
            let code = *body.first()?;
            tokens.push_str(" msgtype 0x4004");
            if code != 0x01 {
                let _ = write!(tokens, " code 0x{code:02x}");
            }
            body[1..].to_vec()
        }
        other => {
            let _ = write!(tokens, " msgtype 0x{other:04x}");
            body.to_vec()
        }
    };

    if ver != 0x02 {
        let _ = write!(tokens, " version 0x{ver:02x}");
    }
    if inv_ver != !ver {
        let _ = write!(tokens, " invversion 0x{inv_ver:02x}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Doip,
        tokens,
        residual_payload: residual,
        explicit_transport,
    })
}
