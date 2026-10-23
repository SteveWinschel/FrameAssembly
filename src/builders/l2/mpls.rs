//! MPLS Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an RFC 3032 MPLS wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_mpls_frame(
    ctx: &WireContext,
    spec: &MplsSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let exp = spec.exp.unwrap_or(0) & 0x07;
    let bos = spec.bos.unwrap_or(1) & 0x01;
    let ttl = spec.ttl.unwrap_or(64);
    let label_entry: u32 = ((spec.label & 0x000F_FFFF) << 12)
        | ((exp as u32) << 9)
        | ((bos as u32) << 8)
        | (ttl as u32);

    let mut mpls_packet = Vec::with_capacity(4 + payload.len());
    mpls_packet.extend_from_slice(&label_entry.to_be_bytes());
    if payload.is_empty() {
        // Sensible default payload for MPLS test frames
        mpls_packet.extend_from_slice(b"FrameAssembly MPLS Payload");
    } else {
        mpls_packet.extend_from_slice(payload);
    }

    Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, ctx.l2, 0x8847, &mpls_packet))
}
