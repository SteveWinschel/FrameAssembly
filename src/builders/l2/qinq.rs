//! IEEE 802.1ad Provider Bridges (QinQ) dual VLAN wire frame builder.
//!
//! Synthesizes IEEE 802.1ad double-tagged Ethernet frames carrying an outer 32-bit Service
//! VLAN tag (S-Tag, `TPID = 0x88A8` followed by 16-bit TCI containing `outer_vid`) and an
//! inner 32-bit Customer VLAN tag (C-Tag, `TPID = 0x8100` followed by 16-bit TCI containing
//! `inner_vid`), ahead of the encapsulated inner EtherType (`0x0800` / `0x86DD` for IP hosts,
//! or `0x88B5` for MAC-only Layer 2 hosts) and payload bytes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b qinq <outer_vid> [innervlan <inner_vid>] [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Encodes an 8-byte IEEE 802.1ad QinQ tag stack (`0x88A8` outer S-Tag + `0x8100` inner C-Tag).
pub fn encode_qinq_tags(qinq: &QinqSpec, fallback_vlan: Option<&VlanSpec>) -> [u8; 8] {
    let pcp = qinq
        .pcp
        .or_else(|| fallback_vlan.and_then(|v| v.pcp))
        .unwrap_or(0)
        & 0x07;
    let dei = qinq
        .dei
        .or_else(|| fallback_vlan.and_then(|v| v.dei))
        .unwrap_or(0)
        & 0x01;
    let outer_tci: u16 = ((pcp as u16) << 13) | ((dei as u16) << 12) | (qinq.outer_vid & 0x0FFF);
    let inner_tci: u16 = qinq.inner_vid.unwrap_or(1) & 0x0FFF;
    let [o0, o1] = outer_tci.to_be_bytes();
    let [i0, i1] = inner_tci.to_be_bytes();
    [0x88, 0xA8, o0, o1, 0x81, 0x00, i0, i1]
}

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
        l2.qinq = Some(QinqSpec {
            outer_vid: spec.outer_vid,
            inner_vid: spec.inner_vid.or(Some(1)),
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
    if let Some(explicit_et) = l2.ethertype
        && !matches!(explicit_et, 0x0800 | 0x86DD)
    {
        return Ok(build_ethernet_and_l2(
            ctx.src_mac,
            ctx.dst_mac,
            &l2,
            explicit_et,
            payload,
        ));
    }
    let ethertype = if ctx.src_ip.is_ipv4() { 0x0800 } else { 0x86DD };
    let ip_payload = if ctx.l3.frag_offset.unwrap_or(0) > 0 {
        payload.to_vec()
    } else {
        crate::packet::build_udp_datagram_with_opts(
            ctx.src_ip,
            ctx.dst_ip,
            ctx.src_port,
            ctx.dst_port,
            payload,
            ctx.l4,
        )?
    };
    let ip = crate::packet::build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &ip_payload)?;
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        ctx.dst_mac,
        &l2,
        ethertype,
        &ip,
    ))
}

