//! Diameter Base Protocol (RFC 6733) Layer 7 zero-heap-style wire builder.
//!
//! This module serializes [`DiameterSpec`] into RFC 6733 Diameter packets over TCP or SCTP
//! (default port `3868`, SCTP PPID `46`). It builds the 20-byte Diameter header (Version `1`,
//! 24-bit Message Length, Command Flags, 24-bit Command Code, Application-ID, Hop-by-Hop ID,
//! End-to-End ID) and 4-byte-padded AVPs, preserving explicit raw AVP streams from `payload_bytes`.

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Resolves a Diameter command mnemonic or decimal string to `(cmd_code, default_is_request, default_app_id, proxiable)`.
fn resolve_diameter_cmd(cmd: Option<&str>) -> (u32, bool, u32, bool) {
    match cmd {
        None | Some("cer") => (257, true, 0, false),
        Some("cea") => (257, false, 0, false),
        Some("dwr") => (280, true, 0, false),
        Some("dwa") => (280, false, 0, false),
        Some("dpr") => (282, true, 0, false),
        Some("dpa") => (282, false, 0, false),
        Some("ccr") => (272, true, 4, true),
        Some("cca") => (272, false, 4, true),
        Some("acr") => (271, true, 3, true),
        Some("aca") => (271, false, 3, true),
        Some("rar") => (258, true, 0, true),
        Some("raa") => (258, false, 0, true),
        Some("str") => (275, true, 0, true),
        Some("sta") => (275, false, 0, true),
        Some("asr") => (274, true, 0, true),
        Some("asa") => (274, false, 0, true),
        Some("ulr") => (316, true, 16_777_251, true),
        Some("ula") => (316, false, 16_777_251, true),
        Some("air") => (318, true, 16_777_251, true),
        Some("aia") => (318, false, 16_777_251, true),
        Some("aar") => (265, true, 16_777_236, true),
        Some("aaa") => (265, false, 16_777_236, true),
        Some(other) => {
            if let Ok(code) = other.parse::<u32>() {
                let proxiable = !matches!(code, 257 | 280 | 282);
                (code & 0x00FF_FFFF, true, 0, proxiable)
            } else {
                (257, true, 0, false)
            }
        }
    }
}

/// Appends one RFC 6733 AVP (`code`, `flags`, `data`) padded to a 4-byte boundary.
fn push_avp(buf: &mut Vec<u8>, code: u32, flags: u8, data: &[u8]) {
    let avp_len = 8usize.saturating_add(data.len());
    let len_be = (avp_len as u32).to_be_bytes();
    buf.extend_from_slice(&code.to_be_bytes());
    buf.push(flags);
    buf.extend_from_slice(&len_be[1..4]);
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Checks if `raw` is a clean sequence of 4-byte-aligned Diameter AVPs and returns whether `target_code` is present.
fn scan_raw_avp_stream(raw: &[u8]) -> Option<Vec<u32>> {
    if raw.is_empty() {
        return None;
    }
    let mut codes = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        if raw.len() - pos < 8 {
            return None;
        }
        let code = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        let flags = raw[pos + 4];
        let avp_len =
            u32::from_be_bytes([0, raw[pos + 5], raw[pos + 6], raw[pos + 7]]) as usize;
        let has_v = (flags & 0x80) != 0;
        let min_len = if has_v { 12 } else { 8 };
        if (flags & 0x1F) != 0 || avp_len < min_len || pos + avp_len > raw.len() {
            return None;
        }
        let padded = (avp_len + 3) & !3;
        if pos + padded > raw.len() {
            return None;
        }
        codes.push(code);
        pos += padded;
    }
    Some(codes)
}

/// Builds an RFC 6733 Diameter payload from `spec` and optional `payload_bytes`.
pub fn build_diameter_payload(
    _ctx: &WireContext,
    spec: &DiameterSpec<'_>,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let (cmd_code, default_req, default_app_id, proxiable) = resolve_diameter_cmd(spec.cmd);
    let is_req = if spec.is_response { false } else { default_req };
    let flags = spec.flags.unwrap_or_else(|| {
        let mut f = if is_req { 0x80 } else { 0x00 };
        if proxiable {
            f |= 0x40;
        }
        f
    });
    let app_id = spec.app_id.unwrap_or(default_app_id);
    let hop_id = spec.hop_id.unwrap_or(1);
    let end_id = spec.end_id.unwrap_or(1);

    let mut avps = Vec::with_capacity(128 + payload_bytes.len());
    let raw_avp_codes = scan_raw_avp_stream(payload_bytes);
    let has_raw_code = |c: u32| -> bool {
        raw_avp_codes
            .as_ref()
            .is_some_and(|codes| codes.contains(&c))
    };

    if let Some(sid) = spec.session_id {
        push_avp(&mut avps, 263, 0x40, sid.as_bytes());
    } else if !matches!(cmd_code, 257 | 280 | 282) && !has_raw_code(263) {
        push_avp(&mut avps, 263, 0x40, b"client.example.com;1;1");
    }

    let default_origin = if is_req {
        "client.example.com"
    } else {
        "server.example.com"
    };
    let origin_host = spec.origin_host.unwrap_or(default_origin);
    if spec.origin_host.is_some() || !has_raw_code(264) {
        push_avp(&mut avps, 264, 0x40, origin_host.as_bytes());
    }

    let origin_realm = spec.origin_realm.unwrap_or("example.com");
    if spec.origin_realm.is_some() || !has_raw_code(296) {
        push_avp(&mut avps, 296, 0x40, origin_realm.as_bytes());
    }

    if let Some(dr) = spec.dst_realm {
        push_avp(&mut avps, 283, 0x40, dr.as_bytes());
    }
    if let Some(dh) = spec.dst_host {
        push_avp(&mut avps, 293, 0x40, dh.as_bytes());
    }

    if let Some(rc) = spec.result_code {
        push_avp(&mut avps, 268, 0x40, &rc.to_be_bytes());
    } else if !is_req && !has_raw_code(268) {
        push_avp(&mut avps, 268, 0x40, &2001u32.to_be_bytes());
    }

    if let Some(user) = spec.user {
        push_avp(&mut avps, 1, 0x40, user.as_bytes());
    }

    if cmd_code == 257 {
        if !has_raw_code(257) {
            push_avp(&mut avps, 257, 0x40, &[0x00, 0x01, 127, 0, 0, 1]);
        }
        if !has_raw_code(266) {
            push_avp(&mut avps, 266, 0x40, &0u32.to_be_bytes());
        }
        if !has_raw_code(269) {
            push_avp(&mut avps, 269, 0x00, b"FrameAssembly");
        }
    } else if cmd_code == 272 {
        if !has_raw_code(416) {
            push_avp(&mut avps, 416, 0x40, &1u32.to_be_bytes());
        }
        if !has_raw_code(415) {
            push_avp(&mut avps, 415, 0x40, &0u32.to_be_bytes());
        }
        if is_req && !has_raw_code(461) {
            push_avp(&mut avps, 461, 0x40, b"32251@3gpp.org");
        }
    }

    if !payload_bytes.is_empty() {
        if raw_avp_codes.is_some() {
            avps.extend_from_slice(payload_bytes);
        } else {
            // Wrap unstructured opaque bytes inside RFC 6733 `Class` (AVP 25) so the packet stays valid.
            push_avp(&mut avps, 25, 0x40, payload_bytes);
        }
    }

    let total_len = 20usize.saturating_add(avps.len());
    let len_be = (total_len as u32).to_be_bytes();
    let cmd_be = cmd_code.to_be_bytes();

    let mut out = Vec::with_capacity(total_len);
    out.push(1);
    out.extend_from_slice(&len_be[1..4]);
    out.push(flags);
    out.extend_from_slice(&cmd_be[1..4]);
    out.extend_from_slice(&app_id.to_be_bytes());
    out.extend_from_slice(&hop_id.to_be_bytes());
    out.extend_from_slice(&end_id.to_be_bytes());
    out.extend_from_slice(&avps);
    out
}
