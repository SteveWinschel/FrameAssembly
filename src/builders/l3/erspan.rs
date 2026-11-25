//! Encapsulated Remote Switch Port Analyzer (ERSPAN Type II & III) Layer 3 wire builder.
//!
//! Serializes an [`ErspanSpec`] into a Cisco ERSPAN packet encapsulated over GRE (IP protocol `47`)
//! with the GRE Sequence Number Present (`S = 0x1000`) flag and GRE EtherType `0x88BE` for ERSPAN
//! Type II (`v2`, 8-byte header) or `0x22EB` for ERSPAN Type III (`v3`, 12-byte header with `P = 1`
//! Ethernet frame indicator). When no explicit `payload` or `hexpayload` is supplied, appends the
//! deterministic 42-byte inner Ethernet + IPv4 + ICMPv4 Echo frame.
//!
//! Canonical `.frasm` syntax:
//! `a -> b erspan [v2 | v3 | version <2|3>] [sessionid <u16>] [vid <u16>] [cos <u8>] [greseq <u32>] [index <u32>] [timestamp <u32>] [direction <0|1>] [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a Cisco ERSPAN Type II (`0x88BE`) or Type III (`0x22EB`) GRE tunnel payload over IP protocol `47`.
pub fn build_erspan_payload(_ctx: &WireContext, spec: &ErspanSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let ver = spec.version.unwrap_or(2);
    let is_v3 = ver == 3;
    let gre_proto: u16 = if is_v3 { 0x22EB } else { 0x88BE };
    let gre_seq = spec.gre_seq.unwrap_or(1);
    let session_id = spec.session_id.unwrap_or(1) & 0x03FF;
    let vid = spec.vid.unwrap_or(0) & 0x0FFF;
    let cos = u16::from(spec.cos.unwrap_or(0) & 0x07);

    let hdr_len = if is_v3 { 20 } else { 16 };
    let mut buf = Vec::with_capacity(hdr_len + payload.len().max(42));

    // 8-byte GRE Header (S = 1 Sequence Present, Version = 0)
    buf.extend_from_slice(&0x1000_u16.to_be_bytes());
    buf.extend_from_slice(&gre_proto.to_be_bytes());
    buf.extend_from_slice(&gre_seq.to_be_bytes());

    if is_v3 {
        // 12-byte ERSPAN Type III Header (Ver = 2)
        let w0 = (2_u16 << 12) | vid;
        let w1 = (cos << 13) | session_id;
        let ts = spec.timestamp.unwrap_or(0);
        let dir_bit = u16::from(spec.direction.unwrap_or(0) & 1) << 3;
        let w3 = 0x8000_u16 | dir_bit; // P = 1 (Ethernet payload present), FT = 0, O = 0
        buf.extend_from_slice(&w0.to_be_bytes());
        buf.extend_from_slice(&w1.to_be_bytes());
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&0_u16.to_be_bytes()); // SGT = 0
        buf.extend_from_slice(&w3.to_be_bytes());
    } else {
        // 8-byte ERSPAN Type II Header (Ver = 1)
        let w0 = (1_u16 << 12) | vid;
        let w1 = (cos << 13) | session_id;
        let index = spec.index.unwrap_or(0) & 0x000F_FFFF;
        buf.extend_from_slice(&w0.to_be_bytes());
        buf.extend_from_slice(&w1.to_be_bytes());
        buf.extend_from_slice(&index.to_be_bytes());
    }

    if payload.is_empty() {
        buf.extend_from_slice(&super::gre::default_overlay_inner_ethernet());
    } else {
        buf.extend_from_slice(payload);
    }

    (buf, 47)
}
