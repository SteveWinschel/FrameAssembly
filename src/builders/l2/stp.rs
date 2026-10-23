//! STP Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an IEEE 802.1D / 802.1w Spanning Tree Protocol (STP) BPDU wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_stp_frame(
    ctx: &WireContext,
    spec: &StpSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    // 35-byte Configuration BPDU
    let mut bpdu = Vec::with_capacity(35 + payload.len());
    // Protocol Identifier: 0x0000 (STP)
    bpdu.extend_from_slice(&0_u16.to_be_bytes());
    // Protocol Version: 0x00 (STP) or 0x02 (RSTP)
    bpdu.push(if spec.is_rstp { 2 } else { 0 });
    // BPDU Type: 0x00 (Configuration) or 0x02 (RSTP)
    bpdu.push(if spec.is_rstp { 2 } else { 0 });
    // Flags: 0x00
    bpdu.push(spec.flags.unwrap_or(0));

    // Root ID (8 bytes: 2B Priority + 6B MAC)
    bpdu.extend_from_slice(&0x8000_u16.to_be_bytes()); // Priority 32768
    bpdu.extend_from_slice(&ctx.src_mac);

    // Root Path Cost (4 bytes)
    bpdu.extend_from_slice(&spec.cost.unwrap_or(0).to_be_bytes());

    // Bridge ID (8 bytes: 2B Priority + 6B MAC)
    bpdu.extend_from_slice(&0x8000_u16.to_be_bytes());
    bpdu.extend_from_slice(&ctx.src_mac);

    // Port ID (2 bytes: 0x8001 = priority 128, port 1)
    bpdu.extend_from_slice(&spec.port_id.unwrap_or(0x8001).to_be_bytes());

    // Message Age (2 bytes: in 1/256ths of a second, 0)
    bpdu.extend_from_slice(&0_u16.to_be_bytes());
    // Max Age (2 bytes: default 20s = 0x1400)
    let max_age = spec.max_age.unwrap_or(20) << 8;
    bpdu.extend_from_slice(&max_age.to_be_bytes());
    // Hello Time (2 bytes: default 2s = 0x0200)
    let hello = spec.hello_time.unwrap_or(2) << 8;
    bpdu.extend_from_slice(&hello.to_be_bytes());
    // Forward Delay (2 bytes: default 15s = 0x0F00)
    let fwd_delay = spec.forward_delay.unwrap_or(15) << 8;
    bpdu.extend_from_slice(&fwd_delay.to_be_bytes());

    bpdu.extend_from_slice(payload);

    // IEEE 802.3 LLC Framing: DSAP 0x42, SSAP 0x42, Control 0x03
    let mut llc_packet = Vec::with_capacity(3 + bpdu.len());
    llc_packet.push(0x42);
    llc_packet.push(0x42);
    llc_packet.push(0x03);
    llc_packet.extend_from_slice(&bpdu);

    // 802.3 Length field
    let length_field = llc_packet.len() as u16;
    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);

    Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, length_field, &llc_packet))
}
