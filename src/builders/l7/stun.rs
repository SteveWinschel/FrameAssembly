//! Session Traversal Utilities for NAT (STUN) (RFC 8489 / RFC 5389 / RFC 8445 (ICE) / RFC 8656 (TURN)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Session Traversal Utilities for NAT (STUN) frames over UDP port 3478 (and WebRTC port 19302).
//! The wire encoder constructs a 20-byte fixed STUN message header containing 16-bit STUN Message Type (`0x0001` Binding Request, `0x0101` Binding Success Response, `0x0111` Binding Error Response), 16-bit Message Length (excluding 20-byte header), 32-bit Magic Cookie `0x2112A442`, and 96-bit Transaction ID, followed by 4-byte-aligned TLV attributes (`0x0020` XOR-MAPPED-ADDRESS and `0x8022` SOFTWARE). When optional fields in [`StunSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b STUN [BINDING_REQUEST | BINDING_RESPONSE | BINDING_ERROR] [TXID <u32>] [XOR_MAPPED_ADDR <ip>] [SOFTWARE <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 8489 STUN NAT traversal packet payload.
/// Syntax mapping: `STUN [BINDING_REQUEST | BINDING_RESPONSE | BINDING_ERROR] [TXID <u32>] [XOR_MAPPED_ADDR <ip>] [SOFTWARE <str>]`
#[doc(alias = "STUN")]
#[doc(alias = "TURN")]
#[doc(alias = "ICE")]
#[doc(alias = "RFC8489")]
#[doc(alias = "RFC5389")]
#[doc(alias = "XOR_MAPPED_ADDR")]
pub fn build_stun_payload(
    _ctx: &WireContext,
    spec: &StunSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let msg_type: u16 = if spec.is_binding_request {
        0x0001 // Binding Request
    } else if spec.is_binding_response {
        0x0101 // Binding Response
    } else if spec.is_binding_error {
        0x0111 // Binding Error Response
    } else {
        0x0001 // Binding Request (default)
    };

    let txid = spec.txid.unwrap_or(0x11223344);
    let txid_tail: [u8; 8] = [0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];

    let mut attrs = Vec::new();
    match spec.xor_mapped_addr {
        Some(IpAddr::V4(v4)) => {
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
        Some(IpAddr::V6(v6)) => {
            // XOR-MAPPED-ADDRESS (Type 0x0020, Length 20)
            attrs.extend_from_slice(&0x0020u16.to_be_bytes());
            attrs.extend_from_slice(&20u16.to_be_bytes());
            attrs.push(0); // Reserved
            attrs.push(2); // Family IPv6
            let xport: u16 = 12345 ^ 0x2112;
            attrs.extend_from_slice(&xport.to_be_bytes());
            let mut xor_mask = [0u8; 16];
            xor_mask[0..4].copy_from_slice(&0x2112A442u32.to_be_bytes());
            xor_mask[4..8].copy_from_slice(&txid.to_be_bytes());
            xor_mask[8..16].copy_from_slice(&txid_tail);
            let octets = v6.octets();
            for i in 0..16 {
                attrs.push(octets[i] ^ xor_mask[i]);
            }
        }
        None => {}
    }

    if let Some(software) = spec.software {
        // SOFTWARE Attribute (Type 0x8022) padded to 4-byte boundary
        let sw_bytes = software.as_bytes();
        attrs.extend_from_slice(&0x8022u16.to_be_bytes());
        attrs.extend_from_slice(&(sw_bytes.len() as u16).to_be_bytes());
        attrs.extend_from_slice(sw_bytes);
        let pad = (4 - (sw_bytes.len() % 4)) % 4;
        attrs.resize(attrs.len() + pad, 0);
    }

    if !payload_bytes.is_empty() {
        attrs.extend_from_slice(payload_bytes);
    }

    let attr_len = attrs.len() as u16;
    let mut pkt = Vec::with_capacity(20 + attrs.len());
    pkt.extend_from_slice(&msg_type.to_be_bytes());
    pkt.extend_from_slice(&attr_len.to_be_bytes());
    pkt.extend_from_slice(&0x2112A442u32.to_be_bytes()); // Magic Cookie
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&txid_tail); // Remaining 8 bytes of 96-bit TxID
    pkt.extend_from_slice(&attrs);
    pkt
}
