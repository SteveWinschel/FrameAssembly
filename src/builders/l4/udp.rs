//! User Datagram Protocol (UDP, RFC 768) Layer 4 wire builder module.
//!
//! Documents the wire-level framing rules for RFC 768 connectionless UDP datagrams over IPv4
//! (`0x0800`) and IPv6 (`0x86DD`) using IP Protocol number `17` (`0x11`). The 8-byte UDP
//! header encodes 16-bit `SRCPORT` (bits 0..15), 16-bit `DSTPORT` (bits 16..31), 16-bit Total
//! Length in bytes (bits 32..47, minimum `8`), and a 16-bit one's complement Checksum
//! (bits 48..63) computed over the IPv4/IPv6 pseudo-header, 8-byte UDP header, and payload.
//!
//! Canonical `.fasm` syntax:
//! `a -> b UDP [SRCPORT <u16>] [DSTPORT <u16>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::UdpSpec;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_udp_datagram;
use alloc::vec::Vec;

/// Builds an RFC 768 UDP datagram from [`WireContext`] and [`UdpSpec`], returning `(bytes, 17)`.
///
/// # Errors
/// Returns `CompilerError::BackendError` if IP endpoints have mismatched address families.
pub fn build_udp_payload(
    ctx: &WireContext,
    _spec: &UdpSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, u8), CompilerError> {
    let datagram = build_udp_datagram(ctx.src_ip, ctx.dst_ip, ctx.src_port, ctx.dst_port, payload)?;
    Ok((datagram, 17))
}

