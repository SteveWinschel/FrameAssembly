//! LACP Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an IEEE 802.3ad / 802.1AX Link Aggregation Control Protocol (LACP) wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_lacp_frame(
    ctx: &WireContext,
    spec: &LacpSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let mut lacpdu = Vec::with_capacity(110 + payload.len());
    // Subtype 0x01 (LACP), Version 0x01
    lacpdu.push(0x01);
    lacpdu.push(0x01);

    // Actor Information TLV (Type 1, Length 20)
    lacpdu.push(1);
    lacpdu.push(20);
    lacpdu.extend_from_slice(&0x8000_u16.to_be_bytes()); // Actor System Priority
    lacpdu.extend_from_slice(&spec.actor_sys.unwrap_or(ctx.src_mac)); // Actor System
    lacpdu.extend_from_slice(&spec.actor_key.unwrap_or(1).to_be_bytes()); // Actor Key
    lacpdu.extend_from_slice(&0x8000_u16.to_be_bytes()); // Port Priority
    lacpdu.extend_from_slice(&spec.actor_port.unwrap_or(1).to_be_bytes()); // Port
    lacpdu.push(spec.actor_state.unwrap_or(0x3D)); // State: Active, Short, Agg, InSync, Collect, Dist
    lacpdu.extend_from_slice(&[0, 0, 0]); // Reserved 3 bytes

    // Partner Information TLV (Type 2, Length 20)
    lacpdu.push(2);
    lacpdu.push(20);
    lacpdu.extend_from_slice(&0x8000_u16.to_be_bytes()); // Partner System Priority
    lacpdu.extend_from_slice(&spec.partner_sys.unwrap_or(ctx.dst_mac)); // Partner System
    lacpdu.extend_from_slice(&spec.partner_key.unwrap_or(1).to_be_bytes()); // Partner Key
    lacpdu.extend_from_slice(&0x8000_u16.to_be_bytes()); // Port Priority
    lacpdu.extend_from_slice(&spec.partner_port.unwrap_or(1).to_be_bytes()); // Port
    lacpdu.push(spec.partner_state.unwrap_or(0x3D)); // State
    lacpdu.extend_from_slice(&[0, 0, 0]); // Reserved 3 bytes

    // Collector Information TLV (Type 3, Length 16)
    lacpdu.push(3);
    lacpdu.push(16);
    lacpdu.extend_from_slice(&0_u16.to_be_bytes()); // Max Delay
    lacpdu.extend_from_slice(&[0u8; 12]); // Reserved 12 bytes

    // Terminator TLV (Type 0, Length 0)
    lacpdu.push(0);
    lacpdu.push(0);

    // Reserved padding (50 bytes zeros per IEEE 802.3ad)
    lacpdu.extend_from_slice(&[0u8; 50]);
    lacpdu.extend_from_slice(payload);

    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);
    Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, 0x8809, &lacpdu))
}
