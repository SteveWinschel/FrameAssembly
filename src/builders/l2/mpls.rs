//! RFC 3032 / RFC 5462 Multi-Protocol Label Switching (MPLS) wire frame builder.
//!
//! Synthesizes standalone MPLS unicast frames over Ethernet II (`EtherType = 0x8847`). Encodes
//! the 32-bit MPLS label stack entry in big-endian network byte order per RFC 3032 §2.1: a
//! 20-bit Label value (`(label & 0xFFFFF) << 12`), a 3-bit Traffic Class / Experimental field
//! (`(exp & 0x07) << 9`), a 1-bit Bottom-of-Stack flag (`(bos & 0x01) << 8`), and an 8-bit
//! Time-to-Live (`ttl`), followed by the encapsulated MPLS payload bytes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b mpls <label> [exp <0..7>] [bos <0|1>] [mplsttl <u8>] [payload "<str>" | hexpayload "<hex>"]`

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
    let mut l2 = ctx.l2.clone();
    if l2.mpls.is_none() {
        l2.mpls = Some(MplsSpec {
            label: spec.label,
            exp: spec.exp,
            bos: spec.bos,
            ttl: spec.ttl,
        });
    }

    if !payload.is_empty() || ctx.src_ip.is_unspecified() || ctx.dst_ip.is_unspecified() {
        Ok(build_ethernet_and_l2(
            ctx.src_mac,
            ctx.dst_mac,
            &l2,
            0x8847,
            payload,
        ))
    } else {
        let udp = crate::packet::build_udp_datagram(ctx.src_ip, ctx.dst_ip, ctx.src_port, ctx.dst_port, b"")?;
        let ip = crate::packet::build_ip_packet(ctx.src_ip, ctx.dst_ip, 17, ctx.l3, &udp)?;
        Ok(build_ethernet_and_l2(ctx.src_mac, ctx.dst_mac, &l2, 0x8847, &ip))
    }
}

