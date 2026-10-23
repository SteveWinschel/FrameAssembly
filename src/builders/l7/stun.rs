//! STUN protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 8489 STUN NAT traversal packet payload.
pub fn build_stun_payload(
    _ctx: &WireContext,
    spec: &StunSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let msg_type: u16 = if spec.is_binding_response {
        0x0101 // Binding Response
    } else if spec.is_binding_error {
        0x0111 // Binding Error Response
    } else {
        0x0001 // Binding Request (default)
    };

    let mut attrs = Vec::new();
    if let Some(IpAddr::V4(v4)) = spec.xor_mapped_addr {
        // XOR-MAPPED-ADDRESS (Type 0x0020, Length 8)
        attrs.extend_from_slice(&0x0020u16.to_be_bytes());
        attrs.extend_from_slice(&8u16.to_be_bytes());
        attrs.push(0); // Reserved
        attrs.push(1); // Family IPv4
        let xport: u16 = 12345 ^ 0x2112;
        attrs.extend_from_slice(&xport.to_be_bytes());
        let xaddr = u32::from_be_bytes(v4.octets()) ^ 0x2112A442;
        attrs.extend_from_slice(&xaddr.to_be_bytes());
    }

    if !payload_bytes.is_empty() {
        attrs.extend_from_slice(payload_bytes);
    }

    let attr_len = attrs.len() as u16;
    let mut pkt = Vec::with_capacity(20 + attrs.len());
    pkt.extend_from_slice(&msg_type.to_be_bytes());
    pkt.extend_from_slice(&attr_len.to_be_bytes());
    pkt.extend_from_slice(&0x2112A442u32.to_be_bytes()); // Magic Cookie
    let txid = spec.txid.unwrap_or(0x11223344);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]); // Remaining 8 bytes of 96-bit TxID
    pkt.extend_from_slice(&attrs);
    pkt
}
