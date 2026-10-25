//! QUIC UDP-Based Multiplexed and Secure Transport (RFC 9000 (QUIC Transport) / RFC 9001 (QUIC-TLS) / RFC 9114 (HTTP/3)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire QUIC UDP-Based Multiplexed and Secure Transport frames over UDP port 443.
//! The wire encoder constructs a RFC 9000 Long Header (`Header Form = 1`, `Fixed Bit = 1`, 2-bit Long Packet Type: `0x0` Initial, `0x1` 0-RTT, `0x2` Handshake, `0x3` Retry; 32-bit Version e.g. `0x00000001` v1 or `0x6b3343cf` v2; DCID Length + 64-bit DCID; SCID Length + 64-bit SCID; variable-length Token; Length; Packet Number) or 1-RTT Short Header (`Header Form = 0`, `Fixed Bit = 1`, DCID, Packet Number). When optional fields in [`QuicSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b QUIC [INITIAL | ZERO_RTT | HANDSHAKE | RETRY | SHORT] [VERSION <u32>] [DCID <u64>] [SCID <u64>] [TOKEN <str>] [PKT_NUM <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 9000 QUIC packet payload.
/// Syntax mapping: `QUIC [INITIAL | ZERO_RTT | HANDSHAKE | RETRY | SHORT] [VERSION <u32>] [DCID <u64>] [SCID <u64>] [TOKEN <str>] [PKT_NUM <u32>]`
#[doc(alias = "QUIC")]
#[doc(alias = "HTTP3")]
#[doc(alias = "RFC9000")]
#[doc(alias = "DCID")]
#[doc(alias = "SCID")]
pub fn build_quic_payload(
    _ctx: &WireContext,
    spec: &QuicSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let dcid = spec.dcid.unwrap_or(0x01020304);
    let dcid_bytes = (dcid as u32).to_be_bytes();

    if spec.is_short
        && !spec.is_initial
        && !spec.is_zero_rtt
        && !spec.is_handshake
        && !spec.is_retry
    {
        // 1-RTT Short Header (Header Form = 0, Fixed Bit = 1 -> 0x40)
        pkt.push(0x40);
        pkt.extend_from_slice(&dcid_bytes);
        pkt.push(spec.pkt_num.unwrap_or(1) as u8);
        pkt.extend_from_slice(payload_bytes);
        return pkt;
    }

    let hdr_type: u8 = if spec.is_initial {
        0
    } else if spec.is_zero_rtt {
        1
    } else if spec.is_handshake {
        2
    } else if spec.is_retry {
        3
    } else {
        0
    };

    // Long Header: Header Form = 1 (0x80) | Fixed Bit = 1 (0x40) | Type (bits 4..5)
    pkt.push(0xC0 | ((hdr_type & 0x03) << 4));
    let version = spec.version.unwrap_or(0x00000001);
    pkt.extend_from_slice(&version.to_be_bytes());

    pkt.push(dcid_bytes.len() as u8);
    pkt.extend_from_slice(&dcid_bytes);

    let scid = spec.scid.unwrap_or(0x05060708);
    let scid_bytes = (scid as u32).to_be_bytes();
    pkt.push(scid_bytes.len() as u8);
    pkt.extend_from_slice(&scid_bytes);

    if hdr_type == 3 {
        // Retry packet: Retry Token + payload / 16-byte Retry Integrity Tag
        if let Some(tok) = spec.token {
            pkt.extend_from_slice(tok.as_bytes());
        }
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        } else {
            pkt.extend_from_slice(&[0u8; 16]);
        }
        return pkt;
    }

    if hdr_type == 0 {
        // Initial packet includes Token Length + Token
        if let Some(tok) = spec.token {
            pkt.push(tok.len() as u8);
            pkt.extend_from_slice(tok.as_bytes());
        } else {
            pkt.push(0);
        }
    }

    // RFC 9000 §16 2-byte variable-length integer (prefix bits 01 -> 0x4000)
    let inner_len = 1 + payload_bytes.len();
    let varint_len = 0x4000u16 | ((inner_len as u16) & 0x3FFF);
    pkt.extend_from_slice(&varint_len.to_be_bytes());
    pkt.push(spec.pkt_num.unwrap_or(1) as u8);
    pkt.extend_from_slice(payload_bytes);
    pkt
}
