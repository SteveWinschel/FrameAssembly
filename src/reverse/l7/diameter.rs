//! Diameter Base Protocol (RFC 6733) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire dissection for RFC 6733 `diameter` packets carried
//! over TCP or SCTP port `3868` (preserving explicit `transport sctp` when decompiling SCTP
//! captures). It validates the 20-byte version-1 Diameter header and 4-byte-padded AVP chain,
//! reconstructs command shorthands and header/AVP modifiers, and retains custom AVPs verbatim.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::{is_valid_raw_string_body, push_str_if};

/// Maps `(cmd_code, is_req)` to `(default_shorthand, default_app_id, default_proxiable)`.
fn lookup_diameter_cmd(cmd_code: u32, is_req: bool) -> Option<(&'static str, u32, bool)> {
    match (cmd_code, is_req) {
        (257, true) => Some(("cer", 0, false)),
        (257, false) => Some(("cea", 0, false)),
        (280, true) => Some(("dwr", 0, false)),
        (280, false) => Some(("dwa", 0, false)),
        (282, true) => Some(("dpr", 0, false)),
        (282, false) => Some(("dpa", 0, false)),
        (272, true) => Some(("ccr", 4, true)),
        (272, false) => Some(("cca", 4, true)),
        (271, true) => Some(("acr", 3, true)),
        (271, false) => Some(("aca", 3, true)),
        (258, true) => Some(("rar", 0, true)),
        (258, false) => Some(("raa", 0, true)),
        (275, true) => Some(("str", 0, true)),
        (275, false) => Some(("sta", 0, true)),
        (274, true) => Some(("asr", 0, true)),
        (274, false) => Some(("asa", 0, true)),
        (316, true) => Some(("ulr", 16_777_251, true)),
        (316, false) => Some(("ula", 16_777_251, true)),
        (318, true) => Some(("air", 16_777_251, true)),
        (318, false) => Some(("aia", 16_777_251, true)),
        (265, true) => Some(("aar", 16_777_236, true)),
        (265, false) => Some(("aaa", 16_777_236, true)),
        _ => None,
    }
}

/// Checks whether a parsed AVP is an exact default tail AVP emitted automatically by the builder.
fn is_default_tail_avp(cmd_code: u32, is_req: bool, code: u32, flags: u8, data: &[u8]) -> bool {
    match (cmd_code, code, flags) {
        (257, 257, 0x40) => data == [0x00, 0x01, 127, 0, 0, 1],
        (257, 266, 0x40) => data == 0u32.to_be_bytes(),
        (257, 269, 0x00) => data == b"FrameAssembly",
        (272, 416, 0x40) => data == 1u32.to_be_bytes(),
        (272, 415, 0x40) => data == 0u32.to_be_bytes(),
        (272, 461, 0x40) if is_req => data == b"32251@3gpp.org",
        _ => false,
    }
}

/// Dissects a Diameter Base Protocol (RFC 6733) packet over TCP or SCTP.
pub(crate) fn dissect_diameter(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp) || payload.len() < 20 {
        return None;
    }
    if payload[0] != 1 {
        return None;
    }
    let msg_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;
    let flags = payload[4];
    if msg_len != payload.len() || msg_len < 20 || !msg_len.is_multiple_of(4) || (flags & 0x0F) != 0 {
        return None;
    }
    let cmd_code = u32::from_be_bytes([0, payload[5], payload[6], payload[7]]);
    let app_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let hop_id = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let end_id = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);

    if !(src_port == 3868 || dst_port == 3868) && cmd_code == 0 {
        return None;
    }

    let is_req = (flags & 0x80) != 0;
    let mut avp_slices: Vec<(u32, u8, &[u8], &[u8])> = Vec::new();
    let mut pos = 20usize;
    while pos < payload.len() {
        let hdr = payload.get(pos..pos.checked_add(8)?)?;
        let code = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let avp_flags = hdr[4];
        let avp_len = u32::from_be_bytes([0, hdr[5], hdr[6], hdr[7]]) as usize;
        let has_v = (avp_flags & 0x80) != 0;
        let data_off = if has_v { 12usize } else { 8usize };
        if (avp_flags & 0x1F) != 0 || avp_len < data_off {
            return None;
        }
        let end_avp = pos.checked_add(avp_len)?;
        let padded = (avp_len.checked_add(3)?) & !3;
        let next_pos = pos.checked_add(padded)?;
        let data = payload.get(pos + data_off..end_avp)?;
        let full_avp = payload.get(pos..next_pos)?;
        avp_slices.push((code, avp_flags, data, full_avp));
        pos = next_pos;
    }
    if !(src_port == 3868 || dst_port == 3868) && avp_slices.is_empty() {
        return None;
    }

    let mut session_id: Option<&str> = None;
    let mut origin_host: Option<&str> = None;
    let mut origin_realm: Option<&str> = None;
    let mut dst_realm: Option<&str> = None;
    let mut dst_host: Option<&str> = None;
    let mut result_code: Option<u32> = None;
    let mut user_name: Option<&str> = None;
    let mut residual = Vec::new();
    let mut non_tail_seen = false;

    for &(code, avp_flags, data, full_avp) in &avp_slices {
        if !non_tail_seen {
            let captured = match (code, avp_flags) {
                (263, 0x40) if session_id.is_none() => core::str::from_utf8(data)
                    .ok()
                    .filter(|s| is_valid_raw_string_body(s))
                    .map(|s| session_id = Some(s))
                    .is_some(),
                (264, 0x40) if origin_host.is_none() => core::str::from_utf8(data)
                    .ok()
                    .filter(|s| is_valid_raw_string_body(s))
                    .map(|s| origin_host = Some(s))
                    .is_some(),
                (296, 0x40) if origin_realm.is_none() => core::str::from_utf8(data)
                    .ok()
                    .filter(|s| is_valid_raw_string_body(s))
                    .map(|s| origin_realm = Some(s))
                    .is_some(),
                (283, 0x40) if dst_realm.is_none() => core::str::from_utf8(data)
                    .ok()
                    .filter(|s| is_valid_raw_string_body(s))
                    .map(|s| dst_realm = Some(s))
                    .is_some(),
                (293, 0x40) if dst_host.is_none() => core::str::from_utf8(data)
                    .ok()
                    .filter(|s| is_valid_raw_string_body(s))
                    .map(|s| dst_host = Some(s))
                    .is_some(),
                (268, 0x40) if result_code.is_none() && data.len() == 4 => {
                    result_code = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    true
                }
                (1, 0x40) if user_name.is_none() => core::str::from_utf8(data)
                    .ok()
                    .filter(|s| is_valid_raw_string_body(s))
                    .map(|s| user_name = Some(s))
                    .is_some(),
                _ => false,
            };
            if captured {
                continue;
            }
            if is_default_tail_avp(cmd_code, is_req, code, avp_flags, data) {
                continue;
            }
            non_tail_seen = true;
        }
        residual.extend_from_slice(full_avp);
    }

    let mut tokens = String::from("diameter");
    let (default_app_id, default_proxiable) = if let Some((mnem, d_app, d_prox)) = lookup_diameter_cmd(cmd_code, is_req) {
        match mnem {
            "cer" => {}
            "cea" | "dwr" | "dwa" | "ccr" | "cca" => {
                let _ = write!(tokens, " {mnem}");
            }
            other => {
                let _ = write!(tokens, " cmd \"{other}\"");
            }
        }
        (d_app, d_prox)
    } else {
        let _ = write!(tokens, " cmd {cmd_code}");
        if !is_req {
            tokens.push_str(" response");
        }
        (0, !matches!(cmd_code, 257 | 280 | 282))
    };

    let expected_flags = {
        let mut f = if is_req { 0x80 } else { 0x00 };
        if default_proxiable {
            f |= 0x40;
        }
        f
    };
    if flags != expected_flags {
        let _ = write!(tokens, " flags {flags}");
    }
    if app_id != default_app_id {
        let _ = write!(tokens, " appid {app_id}");
    }
    if hop_id != 1 {
        let _ = write!(tokens, " hopid {hop_id}");
    }
    if end_id != 1 {
        let _ = write!(tokens, " endid {end_id}");
    }

    let default_origin = if is_req {
        "client.example.com"
    } else {
        "server.example.com"
    };
    if let Some(oh) = origin_host {
        push_str_if(&mut tokens, "originhost", oh, default_origin);
    }
    if let Some(or) = origin_realm {
        push_str_if(&mut tokens, "realm", or, "example.com");
    }
    if let Some(dh) = dst_host {
        let _ = write!(tokens, " dsthost \"{}\"", super::quote_raw_str(dh));
    }
    if let Some(dr) = dst_realm {
        let _ = write!(tokens, " dstrealm \"{}\"", super::quote_raw_str(dr));
    }
    if let Some(sid) = session_id {
        let default_sid = (!matches!(cmd_code, 257 | 280 | 282)).then_some("client.example.com;1;1");
        if Some(sid) != default_sid {
            let _ = write!(tokens, " sessionid \"{}\"", super::quote_raw_str(sid));
        }
    }
    if let Some(rc) = result_code
        && (is_req || rc != 2001)
    {
        let _ = write!(tokens, " resultcode {rc}");
    }
    if let Some(u) = user_name {
        let _ = write!(tokens, " user \"{}\"", super::quote_raw_str(u));
    }

    // If `builder` omitted `Class` (25) wrapping for arbitrary non-AVP residual? Note: when `residual`
    // is a single AVP 25 and was emitted from non-AVP bytes, keep `residual` as valid AVP bytes so
    // `builder` appends it verbatim and passes the forward-compiler byte oracle cleanly!
    let explicit_transport = if matches!(transport, TransportProto::Sctp) {
        Some(TransportProto::Sctp)
    } else {
        None
    };

    Some(ProtocolDissection {
        protocol: Protocol::Diameter,
        tokens,
        residual_payload: residual,
        explicit_transport,
    })
}
