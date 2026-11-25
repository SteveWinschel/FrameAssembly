//! Segment Routing over IPv6 (SRv6 Segment Routing Header, RFC 8754) Layer 3 wire builder.
//!
//! Serializes an [`Srv6Spec`] into an RFC 8754 IPv6 Segment Routing Header (`Routing Type = 4`)
//! encapsulated directly under IPv6 `Next Header = 43`. Encodes the 8-byte fixed SRH prefix
//! (`Next Header`, `Hdr Ext Len = 2 * N`, `Routing Type = 4`, `Segments Left`, `Last Entry = N - 1`,
//! `Flags`, `Tag`) followed by `N` 128-bit Segment IDs (`Segment List[0..N]`), defaulting to a
//! single SID matching the outer destination IPv6 address when `sid` is omitted.
//!
//! Canonical `.frasm` syntax:
//! `a -> b srv6 [nextheader <u8>] [segleft <u8>] [flags <u8>] [tag <u16>] [sid <ipv6>]... [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv6Addr};

/// Builds a deterministic 8-byte ICMPv6 Echo Request stub for `srv6 nextheader 58` frames.
pub(crate) fn default_srv6_icmpv6_echo(src_v6: [u8; 16], dst_v6: [u8; 16]) -> [u8; 8] {
    let mut icmp6 = [0x80_u8, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src_v6);
    pseudo[16..32].copy_from_slice(&dst_v6);
    pseudo[35] = 8;
    pseudo[39] = 58;
    let csum = internet_checksum(&[&pseudo, &icmp6]);
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());
    icmp6
}

/// Builds an RFC 8754 IPv6 Segment Routing Header (`srv6`) payload over IPv6 Next Header `43`.
///
/// # Errors
/// Returns `CompilerError::BackendError` if called with IPv4 endpoints.
pub fn build_srv6_payload(
    ctx: &WireContext,
    spec: &Srv6Spec,
    payload: &[u8],
) -> Result<(Vec<u8>, u8), CompilerError> {
    let (src_v6, dst_v6) = match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => {
            return Err(CompilerError::BackendError(
                "SRv6 is strictly an IPv6 protocol (RFC 8754)".to_string(),
            ));
        }
    };

    let mut sids: Vec<[u8; 16]> = spec
        .sids
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(v6) => Some(v6.octets()),
            IpAddr::V4(_) => None,
        })
        .take(127)
        .collect();
    if sids.is_empty() {
        let fallback_sid = if dst_v6.is_unspecified() {
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)
        } else {
            dst_v6
        };
        sids.push(fallback_sid.octets());
    }

    let last_entry = (sids.len() - 1) as u8;
    let hdr_ext_len = (sids.len() * 2) as u8;
    let seg_left = spec.seg_left.unwrap_or(last_entry);
    let flags = spec.flags.unwrap_or(0);
    let tag = spec.tag.unwrap_or(0);
    let next_hdr = spec
        .next_header
        .unwrap_or(if payload.is_empty() { 59 } else { 253 });

    let mut srh = Vec::with_capacity(8 + sids.len() * 16 + payload.len().max(8));
    srh.push(next_hdr);
    srh.push(hdr_ext_len);
    srh.push(4); // Routing Type 4: Segment Routing Header (RFC 8754)
    srh.push(seg_left);
    srh.push(last_entry);
    srh.push(flags);
    srh.extend_from_slice(&tag.to_be_bytes());
    for sid in &sids {
        srh.extend_from_slice(sid);
    }

    if payload.is_empty() && next_hdr == 58 {
        srh.extend_from_slice(&default_srv6_icmpv6_echo(src_v6.octets(), sids[0]));
    } else {
        srh.extend_from_slice(payload);
    }

    Ok((srh, 43))
}
