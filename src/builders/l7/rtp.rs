//! Real-time Transport Protocol (RTP) (RFC 3550 / RFC 3551 (RTP/AVP Audio and Video Profiles)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Real-time Transport Protocol (RTP) frames over UDP port 5004 (or negotiated even UDP media port).
//! The wire encoder constructs a 12-byte fixed RTP header: Byte 0 packs 2-bit Version (`V = 2`), 1-bit Padding (`P`), 1-bit Extension (`X`), and 4-bit CSRC Count (`CC`); Byte 1 packs 1-bit Marker (`M`) and 7-bit Payload Type (`PT`, e.g. `0` PCMU/G.711u, `8` PCMA/G.711a, `9` G.722, `18` G.729, `96..127` dynamic Opus/H.264); followed by 16-bit Sequence Number, 32-bit Media Timestamp, and 32-bit Synchronization Source (`SSRC`) identifier. When optional fields in [`RtpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b RTP [PT <u8>] [SEQ <u16>] [TIMESTAMP <u32>] [SSRC <u32>] [MARKER <u8>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 3550 RTP real-time audio media payload.
/// Syntax mapping: `RTP [PT <u8>] [SEQ <u16>] [TIMESTAMP <u32>] [SSRC <u32>] [MARKER <u8>]`
#[doc(alias = "RTP")]
#[doc(alias = "RFC3550")]
#[doc(alias = "RFC3551")]
#[doc(alias = "SSRC")]
pub fn build_rtp_payload(
    _ctx: &WireContext,
    spec: &RtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = [0u8; 12];
    pkt[0] = 0x80; // V=2, P=0, X=0, CC=0
    let marker = (spec.marker.unwrap_or(0) & 0x01) << 7;
    let pt = spec.pt.unwrap_or(0) & 0x7F; // Default PT 0: PCMU audio
    pkt[1] = marker | pt;
    pkt[2..4].copy_from_slice(&spec.seq.unwrap_or(1).to_be_bytes());
    pkt[4..8].copy_from_slice(&spec.timestamp.unwrap_or(160).to_be_bytes());
    pkt[8..12].copy_from_slice(&spec.ssrc.unwrap_or(0x12345678).to_be_bytes());

    let mut result = pkt.to_vec();
    if !payload_bytes.is_empty() {
        result.extend_from_slice(payload_bytes);
    } else {
        result.extend_from_slice(&[0u8; 160]); // 160 bytes G.711 PCMU silence
    }
    result
}
