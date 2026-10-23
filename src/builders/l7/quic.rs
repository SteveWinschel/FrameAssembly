//! QUIC protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9000 QUIC packet payload.
pub fn build_quic_payload(
    _ctx: &WireContext,
    spec: &QuicSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Long Header: Initial Packet (0xC0)
    pkt.push(0xC0);
    let version = spec.version.unwrap_or(0x00000001);
    pkt.extend_from_slice(&version.to_be_bytes());

    let dcid = spec.dcid.unwrap_or(0x01020304);
    let dcid_bytes = (dcid as u32).to_be_bytes();
    pkt.push(dcid_bytes.len() as u8);
    pkt.extend_from_slice(&dcid_bytes);

    let scid = spec.scid.unwrap_or(0x05060708);
    let scid_bytes = (scid as u32).to_be_bytes();
    pkt.push(scid_bytes.len() as u8);
    pkt.extend_from_slice(&scid_bytes);

    // Token length = 0
    pkt.push(0);

    // Payload Length & Packet Number
    let inner_len = 1 + payload_bytes.len() as u16;
    pkt.extend_from_slice(&inner_len.to_be_bytes());
    pkt.push(spec.pkt_num.unwrap_or(1) as u8);
    pkt.extend_from_slice(payload_bytes);
    pkt
}
