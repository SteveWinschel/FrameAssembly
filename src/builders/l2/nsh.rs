//! Network Service Header (NSH, RFC 8300) Layer 2 wire frame builder.
//!
//! Synthesizes RFC 8300 Service Function Chaining (SFC) Network Service Header frames over
//! Ethernet II (`EtherType = 0x894F`). Constructs the 4-byte NSH Base Header (`Ver`, `O` OAM
//! bit, 6-bit `TTL`, 6-bit 4-byte word `Length`, 4-bit `MD Type`, and 8-bit `Next Protocol`),
//! the 4-byte Service Path Header (`24`-bit `SPI` and `8`-bit `SI`), fixed 16-byte (`MD Type 1`)
//! or 4-byte-aligned variable (`MD Type 2`) context headers, and either the caller's custom
//! payload or a valid default inner Ethernet / IPv4 / IPv6 / MPLS passenger packet.
//!
//! Canonical `.frasm` syntax:
//! `a -> b nsh [version <0..3>] [oam] [ttl <0..63>] [mdtype <1|2>] [nextproto <u8|ethernet|ipv4|ipv6|nsh|mpls>] [spi <u24>] [si <u8>] [context <hex>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::build_ethernet_and_l2;
use alloc::vec::Vec;

/// Builds an RFC 8300 NSH encapsulation payload (Base Header + Service Path Header + Context + Inner Packet).
///
/// # Errors
/// Returns `CompilerError::BackendError` if MD Type 2 context exceeds the 6-bit NSH header length limit.
pub fn build_nsh_payload(spec: &NshSpec, payload: &[u8]) -> Result<Vec<u8>, CompilerError> {
    let ver = spec.version.unwrap_or(0) & 0x03;
    let oam_bit = u8::from(spec.oam);
    let ttl = spec.ttl.unwrap_or(63) & 0x3F;
    let md_type = spec.md_type.unwrap_or(1) & 0x0F;
    let next_proto = spec.next_proto.unwrap_or(0x03);
    let spi = spec.spi.unwrap_or(1) & 0x00FF_FFFF;
    let si = spec.si.unwrap_or(255);

    let mut ctx_bytes = Vec::new();
    let length_words: u8 = if md_type == 1 {
        ctx_bytes.resize(16, 0);
        if let Some(raw) = &spec.context {
            let n = raw.len().min(16);
            ctx_bytes[..n].copy_from_slice(&raw[..n]);
        }
        6
    } else {
        if let Some(raw) = &spec.context
            && !raw.is_empty()
        {
            ctx_bytes.extend_from_slice(raw);
            while ctx_bytes.len() % 4 != 0 {
                ctx_bytes.push(0);
            }
        }
        let words = 2usize.saturating_add(ctx_bytes.len() / 4);
        if words > 63 {
            return Err(CompilerError::BackendError(alloc::format!(
                "NSH header length ({words} 4-byte words) exceeds 6-bit RFC 8300 maximum (63 words)"
            )));
        }
        words as u8
    };

    let mut nsh = Vec::with_capacity(8 + ctx_bytes.len() + payload.len().max(48));
    // Base Header (4 bytes): Ver(2) | O(1) | U(1) | TTL(6) | Length(6) | U(4) | MD Type(4) | Next Proto(8)
    let b0 = (ver << 6) | (oam_bit << 5) | ((ttl >> 2) & 0x0F);
    let b1 = ((ttl & 0x03) << 6) | (length_words & 0x3F);
    let b2 = md_type & 0x0F;
    nsh.push(b0);
    nsh.push(b1);
    nsh.push(b2);
    nsh.push(next_proto);

    // Service Path Header (4 bytes): SPI(24) | SI(8)
    let sph = (spi << 8) | u32::from(si);
    nsh.extend_from_slice(&sph.to_be_bytes());
    nsh.extend_from_slice(&ctx_bytes);

    if payload.is_empty() {
        match next_proto {
            0x03 => nsh.extend_from_slice(&crate::builders::l3::gre::default_overlay_inner_ethernet()),
            0x01 => nsh.extend_from_slice(&crate::builders::l3::gre::default_gre_inner_packet(0x0800)),
            0x02 => nsh.extend_from_slice(&crate::builders::l3::gre::default_gre_inner_packet(0x86DD)),
            0x05 => {
                nsh.extend_from_slice(&[0x00, 0x01, 0x01, 0x40]);
                nsh.extend_from_slice(&crate::builders::l3::gre::default_gre_inner_packet(0x0800));
            }
            _ => nsh.extend_from_slice(b"FrameAssembly NSH Data"),
        }
    } else {
        nsh.extend_from_slice(payload);
    }

    Ok(nsh)
}

/// Builds a complete IEEE 802.3 Ethernet II NSH wire frame (`EtherType = 0x894F`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if NSH header constraints are exceeded.
pub fn build_nsh_frame(
    ctx: &WireContext,
    spec: &NshSpec,
    payload: &[u8],
) -> Result<Vec<u8>, CompilerError> {
    let nsh_pkt = build_nsh_payload(spec, payload)?;
    let dst_mac = ctx.l2.dst_mac.unwrap_or(ctx.dst_mac);
    Ok(build_ethernet_and_l2(
        ctx.src_mac,
        dst_mac,
        ctx.l2,
        0x894F,
        &nsh_pkt,
    ))
}
