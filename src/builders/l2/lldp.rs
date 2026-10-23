//! LLDP Layer 2 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an IEEE 802.1AB LLDP wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_lldp_frame(
    ctx: &WireContext,
    spec: &LldpSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let mut lldpdu = Vec::with_capacity(64 + payload.len());

    // Chassis ID TLV (Type 1)
    let chassis = spec.chassis_id;
    if let Some(ch) = chassis {
        let ch_bytes = ch.as_bytes();
        let tlv_len = 1 + ch_bytes.len();
        let header: u16 = (1_u16 << 9) | (tlv_len as u16 & 0x01FF);
        lldpdu.extend_from_slice(&header.to_be_bytes());
        lldpdu.push(4); // Subtype 4: MAC address / Subtype 7: locally assigned
        lldpdu.extend_from_slice(ch_bytes);
    } else {
        // Default: Chassis ID Subtype 4 (MAC address)
        let header: u16 = (1_u16 << 9) | (7_u16 & 0x01FF);
        lldpdu.extend_from_slice(&header.to_be_bytes());
        lldpdu.push(4);
        lldpdu.extend_from_slice(&ctx.src_mac);
    }

    // Port ID TLV (Type 2)
    let port = spec.port_id.unwrap_or("eth0");
    let port_bytes = port.as_bytes();
    let port_tlv_len = 1 + port_bytes.len();
    let port_hdr: u16 = (2_u16 << 9) | (port_tlv_len as u16 & 0x01FF);
    lldpdu.extend_from_slice(&port_hdr.to_be_bytes());
    lldpdu.push(5); // Subtype 5: Interface name
    lldpdu.extend_from_slice(port_bytes);

    // TTL TLV (Type 3)
    let ttl_val = spec.ttl.unwrap_or(120);
    let ttl_hdr: u16 = (3_u16 << 9) | 2_u16;
    lldpdu.extend_from_slice(&ttl_hdr.to_be_bytes());
    lldpdu.extend_from_slice(&ttl_val.to_be_bytes());

    // Optional SysName TLV (Type 5)
    if let Some(sysname) = spec.sysname {
        let name_bytes = sysname.as_bytes();
        let hdr: u16 = (5_u16 << 9) | (name_bytes.len() as u16 & 0x01FF);
        lldpdu.extend_from_slice(&hdr.to_be_bytes());
        lldpdu.extend_from_slice(name_bytes);
    }

    // Optional SysDesc TLV (Type 6)
    if let Some(sysdesc) = spec.sysdesc {
        let desc_bytes = sysdesc.as_bytes();
        let hdr: u16 = (6_u16 << 9) | (desc_bytes.len() as u16 & 0x01FF);
        lldpdu.extend_from_slice(&hdr.to_be_bytes());
        lldpdu.extend_from_slice(desc_bytes);
    }

    // Custom injected payload bytes
    lldpdu.extend_from_slice(payload);

    // End of LLDPDU TLV (Type 0, Length 0)
    lldpdu.extend_from_slice(&0_u16.to_be_bytes());

    let dst_mac = ctx.l2.dst_mac.unwrap_or([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    Ok(build_ethernet_and_l2(ctx.src_mac, dst_mac, ctx.l2, 0x88CC, &lldpdu))
}
