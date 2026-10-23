//! VLAN Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds a standalone IEEE 802.1Q VLAN wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_vlan_frame(
    ctx: &WireContext,
    spec: &VlanSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let mut l2 = ctx.l2.clone();
    if l2.vlan.is_none() {
        let vid = if spec.vid != 0 { spec.vid } else { 1 };
        l2.vlan = Some(VlanSpec {
            vid,
            pcp: spec.pcp,
            dei: spec.dei,
        });
    }
    let default_data = b"FrameAssembly VLAN Payload";
    let effective_data = if payload.is_empty() {
        &default_data[..]
    } else {
        payload
    };
    Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, 0x0800, effective_data))
}
