//! RTP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 3550 RTP real-time audio media payload.
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
