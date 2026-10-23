//! QINQ Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds a standalone IEEE 802.1ad QinQ wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_qinq_frame(
    ctx: &WireContext,
    spec: &QinqSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let mut l2 = ctx.l2.clone();
    if l2.qinq.is_none() {
        let outer_vid = if spec.outer_vid != 0 { spec.outer_vid } else { 1 };
        l2.qinq = Some(QinqSpec {
            outer_vid,
            inner_vid: spec.inner_vid.or(Some(2)),
        });
    }
    let default_data = b"FrameAssembly QINQ Payload";
    let effective_data = if payload.is_empty() {
        &default_data[..]
    } else {
        payload
    };
    Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, 0x0800, effective_data))
}
