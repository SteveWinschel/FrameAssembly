//! IEEE 802.1ad Provider Bridges (QinQ) dual VLAN wire frame builder.
//!
//! Synthesizes IEEE 802.1ad double-tagged Ethernet frames carrying an outer 32-bit Service
//! VLAN tag (S-Tag, `TPID = 0x88A8` followed by 16-bit TCI containing `outer_vid`) and an
//! inner 32-bit Customer VLAN tag (C-Tag, `TPID = 0x8100` followed by 16-bit TCI containing
//! `inner_vid`), ahead of the encapsulated inner EtherType (`0x0800`) and payload bytes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b QINQ <outer_vid> [INNER_VLAN <inner_vid>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

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
    let ethertype = if ctx.src_ip.is_ipv4() { 0x0800 } else { 0x86DD };
    if payload.is_empty() {
        let udp = crate::packet::build_udp_datagram(ctx.src_ip, ctx.dst_ip, ctx.src_port, ctx.dst_port, b"")?;
        let ip = crate::packet::build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &udp)?;
        Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, ethertype, &ip))
    } else {
        Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, ethertype, payload))
    }
}

