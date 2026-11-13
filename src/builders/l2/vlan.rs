//! IEEE 802.1Q Virtual Local Area Network (VLAN) wire frame builder.
//!
//! Synthesizes standalone IEEE 802.1Q single-tagged Ethernet frames inserting a 32-bit VLAN
//! tag (`TPID = 0x8100` followed by 16-bit Tag Control Information packing 3-bit `pcp`, 1-bit
//! `dei`, and 12-bit `VID`) between the Ethernet Source MAC address and the inner payload
//! EtherType (`0x0800` / `0x86DD` for IP hosts, or `0x88B5` IEEE 802.1 Local Experimental
//! EtherType for MAC-only Layer 2 hosts), followed by the encapsulated frame payload bytes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b vlan <vid> [pcp <0..7>] [dei <0|1>] [payload "<str>" | hexpayload "<hex>"]`

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
    if ctx.src_ip.is_unspecified() || ctx.dst_ip.is_unspecified() {
        let ethertype = l2.ethertype.unwrap_or(0x88B5);
        return Ok(build_ethernet_and_l2(
            ctx.src_mac,
            ctx.dst_mac,
            &l2,
            ethertype,
            payload,
        ));
    }
    let ethertype = if ctx.src_ip.is_ipv4() { 0x0800 } else { 0x86DD };
    if payload.is_empty() {
        let udp = crate::packet::build_udp_datagram(ctx.src_ip, ctx.dst_ip, ctx.src_port, ctx.dst_port, b"")?;
        let ip = crate::packet::build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &udp)?;
        Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, ethertype, &ip))
    } else {
        Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, ethertype, payload))
    }
}

