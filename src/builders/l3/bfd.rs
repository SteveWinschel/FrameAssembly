//! BFD Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 5880 BFD Control packet payload over UDP 3784.
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
