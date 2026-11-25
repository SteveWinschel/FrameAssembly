//! Layer 2 Tunneling Protocol (L2TPv2 RFC 2661 / L2TPv3 RFC 3931) Layer 3 wire builder.
//!
//! Serializes an [`L2tpSpec`] into either an RFC 2661 L2TPv2 message over UDP destination port
//! `1701` (default) or an RFC 3931 L2TPv3 message over IP protocol `115` (or UDP `1701` when
//! `transport udp` is selected). Control frames encode `T=1`, `L=1`, `S=1`, sequence numbers `ns`
//! and `nr`, and Message Type AVPs (`hello`, `sccrq`, `sccrp`, `scccn`, `stopccn`), while `data`
//! frames carry PPP-over-L2TPv2 or Ethernet-over-L2TPv3 pseudowire payloads.
//!
//! Canonical `.frasm` syntax:
//! `a -> b l2tp [v2 | v3 | version <2|3>] [hello | sccrq | sccrp | scccn | stopccn | data | msgtype <str|u16>] [tunnelid <u32>] [sessionid <u32>] [ns <u16>] [nr <u16>] [flags <u16>] [transport udp]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Normalizes a control Message Type string or numeric literal into its RFC 2661 / 3931 `u16` code.
fn resolve_l2tp_msg_code(raw: Option<&str>) -> u16 {
    let Some(val) = raw else {
        return 6; // HELLO
    };
    let clean = val.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match clean.as_str() {
        "SCCRQ" => 1,
        "SCCRP" => 2,
        "SCCCN" => 3,
        "STOPCCN" => 4,
        "HELLO" => 6,
        "OCRQ" => 7,
        "OCRP" => 8,
        "OCCN" => 9,
        "ICRQ" => 10,
        "ICRP" => 11,
        "ICCN" => 12,
        "CDN" => 14,
        "WEN" => 15,
        "SLI" => 16,
        _ => {
            if let Some(hex) = clean.strip_prefix("0X") {
                u16::from_str_radix(hex, 16).unwrap_or(6)
            } else {
                clean.parse::<u16>().unwrap_or(6)
            }
        }
    }
}

/// Appends an L2TP AVP (`M=1`, Length = `6 + value.len()`, Vendor = `0`, `attr`, `value`).
fn push_l2tp_avp(out: &mut Vec<u8>, attr: u16, value: &[u8]) {
    let total_len = ((6 + value.len()) & 0x03FF) as u16;
    let flags_len = 0x8000_u16 | total_len;
    out.extend_from_slice(&flags_len.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&attr.to_be_bytes());
    out.extend_from_slice(value);
}

/// Builds an RFC 2661 L2TPv2 or RFC 3931 L2TPv3 payload and returns `(bytes, use_ip_115, proto_or_port)`.
///
/// When `use_ip_115` is `true`, `proto_or_port` is IP protocol `115`; otherwise it is UDP port `1701`.
pub fn build_l2tp_payload(
    ctx: &WireContext,
    spec: &L2tpSpec,
    payload: &[u8],
) -> (Vec<u8>, bool, u16) {
    let ver = spec.version.unwrap_or(2);
    let use_ip_115 = ver == 3 && ctx.transport != Some(TransportProto::Udp);
    let proto_or_port = if use_ip_115 { 115_u16 } else { 1701_u16 };
    let is_data = spec.is_data || (!payload.is_empty() && spec.msg_type.is_none());
    let tunnel_id = spec.tunnel_id.unwrap_or(1);
    let mut l2tp = Vec::with_capacity(64 + payload.len());

    if !is_data {
        let msg_code = resolve_l2tp_msg_code(spec.msg_type);
        let mut avps = Vec::with_capacity(64);
        push_l2tp_avp(&mut avps, 0, &msg_code.to_be_bytes());
        if msg_code == 1 {
            // Mandatory RFC 2661/3931 SCCRQ AVPs
            push_l2tp_avp(&mut avps, 2, &[0x01, 0x00]); // Protocol Version 1.0
            push_l2tp_avp(&mut avps, 3, &3_u32.to_be_bytes()); // Framing Capabilities
            push_l2tp_avp(&mut avps, 7, b"FrameAssembly"); // Host Name
            if ver == 3 {
                push_l2tp_avp(&mut avps, 60, &tunnel_id.to_be_bytes()); // Router ID / Control ID
            } else {
                push_l2tp_avp(&mut avps, 9, &(tunnel_id as u16).to_be_bytes()); // Assigned Tunnel ID
            }
        }
        if ver == 3
            && let Some(sid) = spec.session_id
            && sid != 0
        {
            push_l2tp_avp(&mut avps, 63, &sid.to_be_bytes()); // Assigned Session ID
        }

        let ns = spec.ns.unwrap_or(0);
        let nr = spec.nr.unwrap_or(0);
        let msg_len = (12 + avps.len() + payload.len()).min(usize::from(u16::MAX)) as u16;
        if ver == 3 {
            if use_ip_115 {
                l2tp.extend_from_slice(&0_u32.to_be_bytes()); // Session ID = 0 marks L2TPv3 Control
            }
            let flags_ver = spec.flags.map_or(0xC803_u16, |f| (f & 0xFFF0) | 3);
            l2tp.extend_from_slice(&flags_ver.to_be_bytes());
            l2tp.extend_from_slice(&msg_len.to_be_bytes());
            l2tp.extend_from_slice(&tunnel_id.to_be_bytes());
        } else {
            let flags_ver = spec.flags.map_or(0xC802_u16, |f| (f & 0xFFF0) | 2);
            l2tp.extend_from_slice(&flags_ver.to_be_bytes());
            l2tp.extend_from_slice(&msg_len.to_be_bytes());
            l2tp.extend_from_slice(&(tunnel_id as u16).to_be_bytes());
            l2tp.extend_from_slice(&(spec.session_id.unwrap_or(0) as u16).to_be_bytes());
        }
        l2tp.extend_from_slice(&ns.to_be_bytes());
        l2tp.extend_from_slice(&nr.to_be_bytes());
        l2tp.extend_from_slice(&avps);
        l2tp.extend_from_slice(payload);
    } else if ver == 3 {
        let sid = spec.session_id.unwrap_or(1).max(1);
        l2tp.extend_from_slice(&sid.to_be_bytes());
        if let Some(ns) = spec.ns {
            let sub_flags = spec.flags.map_or(0x40_u8, |f| (f >> 8) as u8 | 0x40);
            l2tp.extend_from_slice(&[sub_flags, 0]);
            l2tp.extend_from_slice(&ns.to_be_bytes());
        } else {
            l2tp.extend_from_slice(&[0u8; 4]); // Default L2-Specific Sublayer
        }
        if payload.is_empty() {
            l2tp.extend_from_slice(&super::gre::default_overlay_inner_ethernet());
        } else {
            l2tp.extend_from_slice(payload);
        }
    } else {
        let has_seq = spec.ns.is_some() || spec.nr.is_some();
        let default_flags = if has_seq { 0x4802_u16 } else { 0x4002_u16 };
        let flags_ver = spec.flags.map_or(default_flags, |f| (f & 0x7FF0) | 2);
        let hdr_len = if (flags_ver & 0x0800) != 0 { 12 } else { 8 };
        let mut inner = Vec::new();
        if payload.is_empty() {
            inner.extend_from_slice(&[0xFF, 0x03, 0x00, 0x21]); // PPP IPv4
            inner.extend_from_slice(&super::gre::default_gre_inner_packet(0x0800));
        } else {
            inner.extend_from_slice(payload);
        }
        let total_len = (hdr_len + inner.len()).min(usize::from(u16::MAX)) as u16;
        l2tp.extend_from_slice(&flags_ver.to_be_bytes());
        l2tp.extend_from_slice(&total_len.to_be_bytes());
        l2tp.extend_from_slice(&(tunnel_id as u16).to_be_bytes());
        l2tp.extend_from_slice(&(spec.session_id.unwrap_or(1) as u16).to_be_bytes());
        if (flags_ver & 0x0800) != 0 {
            l2tp.extend_from_slice(&spec.ns.unwrap_or(0).to_be_bytes());
            l2tp.extend_from_slice(&spec.nr.unwrap_or(0).to_be_bytes());
        }
        l2tp.extend_from_slice(&inner);
    }

    (l2tp, use_ip_115, proto_or_port)
}
