//! IEEE 802.1Qbb Priority-based Flow Control (PFC) wire frame builder.
//!
//! Synthesizes IEEE 802.1Qbb / IEEE 802.3bd MAC Control PFC pause frames over Ethernet II
//! (`EtherType = 0x8808`) addressed by default to the MAC Control multicast address
//! `01:80:C2:00:00:01`. Encodes MAC Control OpCode `0x0101`, the 16-bit Class Enable Vector, eight
//! big-endian 16-bit pause-quanta timers (`q0`..`q7`), and 26 trailing reserved zero octets to
//! construct the canonical 46-byte MAC Control SDU.
//!
//! Canonical `.frasm` syntax:
//! `a -> b pfc [enable <u16>] [quanta <u16>] [q0 <u16>] .. [q7 <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Resolves the 16-bit IEEE 802.1Qbb Class Enable Vector from `enable`, `quanta`, and `class_quanta`.
fn resolve_pfc_enable_mask(spec: &PfcSpec) -> u16 {
    if let Some(enable) = spec.enable {
        return enable;
    }
    let any_per_class = spec.class_quanta.iter().any(Option::is_some);
    if any_per_class && spec.quanta.is_none() {
        let mut mask = 0_u16;
        for (idx, q) in spec.class_quanta.iter().enumerate() {
            if q.is_some() {
                mask |= 1_u16 << idx;
            }
        }
        return mask;
    }
    0x00FF
}

/// Builds an IEEE 802.1Qbb Priority-based Flow Control frame (`EtherType = 0x8808`, OpCode `0x0101`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_pfc_frame(
    ctx: &WireContext,
    spec: &PfcSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let enable = resolve_pfc_enable_mask(spec);
    let mut pfc = Vec::with_capacity(46 + payload.len());
    pfc.extend_from_slice(&0x0101_u16.to_be_bytes());
    pfc.extend_from_slice(&enable.to_be_bytes());

    for (idx, class_q) in spec.class_quanta.iter().enumerate() {
        let q = if let Some(explicit_q) = *class_q {
            explicit_q
        } else if (enable & (1_u16 << idx)) != 0 {
            spec.quanta.unwrap_or(0xFFFF)
        } else {
            0
        };
        pfc.extend_from_slice(&q.to_be_bytes());
    }

    pfc.extend_from_slice(&[0u8; 26]);
    pfc.extend_from_slice(payload);

    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x01]);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x8808,
        &pfc,
    ))
}
