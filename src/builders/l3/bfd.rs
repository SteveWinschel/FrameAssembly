//! Bidirectional Forwarding Detection (BFD, RFC 5880 / RFC 5881) Layer 3 wire builder.
//!
//! Serializes a [`BfdSpec`] into a 24-byte RFC 5880 BFD Version 1 Control packet carried over
//! UDP destination port `3784` (single-hop, RFC 5881) or custom multihop ports (`4784`, RFC 5883).
//! Byte 0 packs the 3-bit `Vers` (`1`) in bits `7..5` and the 5-bit Diagnostic code (`DIAG`, default
//! `0`) in bits `4..0`. Byte 1 encodes the 2-bit session `State` (`STATE`, default `3` Up) in bits
//! `7..6`, followed by `Detect Mult` (`MULT`, default `3`), `Length` (`24`), 32-bit `My Discriminator`
//! (`MY_DISC`), 32-bit `Your Discriminator` (`YOUR_DISC`), and 32-bit `MIN_TX` / `MIN_RX` timers.
//!
//! Canonical `.fasm` syntax:
//! `a -> b BFD [STATE <0..3>] [DIAG <0..31>] [MY_DISC <u32>] [YOUR_DISC <u32>] [MIN_TX <u32>] [MIN_RX <u32>] [MULT <u8>]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 5880 BFD Control packet payload over UDP destination port `3784`.
pub fn build_bfd_payload(spec: &BfdSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let state = spec.state.unwrap_or(3) & 0x03; // 3 = Up
    let diag = spec.diag.unwrap_or(0) & 0x1F;
    let b0 = (1_u8 << 5) | diag; // Vers 1, Diag
    let b1 = state << 6; // State

    let mut bfd = Vec::with_capacity(24 + payload.len());
    bfd.push(b0);
    bfd.push(b1);
    bfd.push(spec.mult.unwrap_or(3)); // Detect Mult
    bfd.push(24); // Length 24
    bfd.extend_from_slice(&spec.my_disc.unwrap_or(1).to_be_bytes());
    bfd.extend_from_slice(&spec.your_disc.unwrap_or(0).to_be_bytes());
    bfd.extend_from_slice(&spec.min_tx.unwrap_or(1_000_000).to_be_bytes());
    bfd.extend_from_slice(&spec.min_rx.unwrap_or(1_000_000).to_be_bytes());
    bfd.extend_from_slice(&0_u32.to_be_bytes()); // Required Min Echo RX
    bfd.extend_from_slice(payload);

    (bfd, 3784)
}
