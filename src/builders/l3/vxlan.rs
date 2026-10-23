//! VXLAN Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 7348 VXLAN payload over UDP 4789.
pub fn build_vxlan_payload(spec: &VxlanSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let vni = spec.vni.unwrap_or(4096) & 0x00FF_FFFF;
    let mut vxlan = Vec::with_capacity(8 + payload.len());
    vxlan.push(0x08); // I flag
    vxlan.extend_from_slice(&[0, 0, 0]); // Reserved
    vxlan.push((vni >> 16) as u8);
    vxlan.push((vni >> 8) as u8);
    vxlan.push(vni as u8);
    vxlan.push(0); // Reserved

    if payload.is_empty() {
        // Sensible default inner Ethernet frame
        vxlan.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
        vxlan.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        vxlan.extend_from_slice(&0x0800_u16.to_be_bytes());
        vxlan.extend_from_slice(b"FrameAssembly VXLAN Inner Data");
    } else {
        vxlan.extend_from_slice(payload);
    }

    (vxlan, 4789)
}
