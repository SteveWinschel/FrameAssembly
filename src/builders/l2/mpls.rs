//! RFC 3032 / RFC 5462 Multi-Protocol Label Switching (MPLS) wire frame builder.
//!
//! Synthesizes standalone MPLS unicast frames over Ethernet II (`EtherType = 0x8847`). Encodes
//! the 32-bit MPLS label stack entry in big-endian network byte order per RFC 3032 §2.1: a
//! 20-bit Label value (`(label & 0xFFFFF) << 12`), a 3-bit Traffic Class / Experimental field
//! (`(exp & 0x07) << 9`), a 1-bit Bottom-of-Stack flag (`(bos & 0x01) << 8`), and an 8-bit
//! Time-to-Live (`ttl`), followed by the encapsulated MPLS payload bytes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b MPLS <label> [EXP <0..7>] [BOS <0|1>] [MPLS_TTL <u8>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an RFC 3032 MPLS wire frame.
///
/// # Errors
/// Returns `CompilerError::BackendError` if construction fails.
pub fn build_mpls_frame(
    ctx: &WireContext,
    spec: &MplsSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let exp = spec.exp.unwrap_or(0) & 0x07;
    let bos = spec.bos.unwrap_or(1) & 0x01;
    let ttl = spec.ttl.unwrap_or(64);
    let label_entry: u32 = ((spec.label & 0x000F_FFFF) << 12)
        | ((exp as u32) << 9)
        | ((bos as u32) << 8)
        | (ttl as u32);

    let mut mpls_packet = Vec::with_capacity(4 + payload.len());
    mpls_packet.extend_from_slice(&label_entry.to_be_bytes());
    if payload.is_empty() {
        let udp = crate::packet::build_udp_datagram(ctx.src_ip, ctx.dst_ip, ctx.src_port, ctx.dst_port, b"")?;
        let ip = crate::packet::build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &udp)?;
        mpls_packet.extend_from_slice(&ip);
    } else {
        mpls_packet.extend_from_slice(payload);
    }

    Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, ctx.l2, 0x8847, &mpls_packet))
}

