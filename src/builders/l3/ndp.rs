//! IPv6 Neighbor Discovery Protocol (NDP, RFC 4861) Layer 3 wire builder.
//!
//! Serializes an [`NdpSpec`] into an RFC 4861 IPv6 Neighbor Discovery ICMPv6 control frame over
//! IPv6 Next Header `58` (`0x3A`). Supports `NEIGHBOR_SOLICIT` (Type `135`, deriving the
//! Solicited-Node Multicast destination `ff02::1:ffXX:XXXX` from the low 24 bits of `TARGET` and
//! appending Option 1 Source Link-Layer Address `SLLA`), `NEIGHBOR_ADVERT` (Type `136`, setting
//! Solicited + Override flags `0x60` and appending Option 2 Target Link-Layer Address `TLLA`),
//! `ROUTER_SOLICIT` (Type `133` to `ff02::2`), `ROUTER_ADVERT` (Type `134` with `ROUTER_LIFETIME`),
//! and `REDIRECT` (Type `137`), with full 40-byte IPv6 pseudo-header checksum calculation.
//!
//! Canonical `.fasm` syntax:
//! `a -> b NDP [ROUTER_SOLICIT | ROUTER_ADVERT | NEIGHBOR_SOLICIT | NEIGHBOR_ADVERT | REDIRECT] [TARGET <ipv6>] [SLLA <mac>] [TLLA <mac>] [ROUTER_LIFETIME <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 4861 IPv6 Neighbor Discovery Protocol (`NDP`) payload over ICMPv6 (`58`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if called with IPv4 endpoints.
pub fn build_ndp_payload(
    ctx: &WireContext,
    spec: &NdpSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, IpAddr, u8), CompilerError> {
    let (src_v6, dst_v6) = match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => {
            return Err(CompilerError::BackendError(
                "NDP is strictly an IPv6 protocol".to_string(),
            ));
        }
    };

    let target_v6 = match spec.target {
        Some(IpAddr::V6(t)) => t,
        _ => dst_v6,
    };

    let ndp_type = spec.ndp_type.unwrap_or(NdpType::NeighborSolicit);
    let mut ndp_body = Vec::with_capacity(32 + payload.len());

    let mut actual_dst_ip = IpAddr::V6(dst_v6);

    match ndp_type {
        NdpType::NeighborSolicit => {
            ndp_body.push(135); // Type 135
            ndp_body.push(0); // Code 0
            ndp_body.extend_from_slice(&[0, 0]); // Checksum placeholder
            ndp_body.extend_from_slice(&[0u8; 4]); // Reserved
            ndp_body.extend_from_slice(&target_v6.octets()); // Target Address

            // Option 1: Source Link-Layer Address (Type 1, Length 1 = 8 bytes)
            let slla = spec.slla.unwrap_or(ctx.src_mac);
            ndp_body.push(1);
            ndp_body.push(1);
            ndp_body.extend_from_slice(&slla);

            // Compute Solicited-Node Multicast destination
            let target_octets = target_v6.octets();
            actual_dst_ip = IpAddr::V6(core::net::Ipv6Addr::new(
                0xff02, 0, 0, 0, 0, 1,
                0xff00 | (target_octets[13] as u16),
                ((target_octets[14] as u16) << 8) | (target_octets[15] as u16),
            ));
        }
        NdpType::NeighborAdvert => {
            ndp_body.push(136); // Type 136
            ndp_body.push(0); // Code 0
            ndp_body.extend_from_slice(&[0, 0]); // Checksum placeholder
            ndp_body.extend_from_slice(&[0x60, 0, 0, 0]); // Flags: Solicited (0x40) + Override (0x20)
            ndp_body.extend_from_slice(&target_v6.octets()); // Target Address

            // Option 2: Target Link-Layer Address (Type 2, Length 1 = 8 bytes)
            let tlla = spec.tlla.unwrap_or(ctx.src_mac);
            ndp_body.push(2);
            ndp_body.push(1);
            ndp_body.extend_from_slice(&tlla);
        }
        NdpType::RouterSolicit => {
            ndp_body.push(133); // Type 133
            ndp_body.push(0);
            ndp_body.extend_from_slice(&[0, 0]);
            ndp_body.extend_from_slice(&[0u8; 4]);
            // Option 1: SLLA
            let slla = spec.slla.unwrap_or(ctx.src_mac);
            ndp_body.push(1);
            ndp_body.push(1);
            ndp_body.extend_from_slice(&slla);
            actual_dst_ip = IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
        }
        NdpType::RouterAdvert => {
            ndp_body.push(134); // Type 134
            ndp_body.push(0);
            ndp_body.extend_from_slice(&[0, 0]);
            ndp_body.push(64); // Cur Hop Limit
            ndp_body.push(0); // Flags
            ndp_body.extend_from_slice(&spec.router_lifetime.unwrap_or(1800).to_be_bytes());
            ndp_body.extend_from_slice(&0_u32.to_be_bytes()); // Reachable Time
            ndp_body.extend_from_slice(&0_u32.to_be_bytes()); // Retrans Timer
        }
        NdpType::Redirect => {
            ndp_body.push(137);
            ndp_body.push(0);
            ndp_body.extend_from_slice(&[0, 0]);
            ndp_body.extend_from_slice(&[0u8; 4]);
            ndp_body.extend_from_slice(&target_v6.octets());
            ndp_body.extend_from_slice(&dst_v6.octets());
        }
    }
    ndp_body.extend_from_slice(payload);

    let pseudo = {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(&src_v6.octets());
        if let IpAddr::V6(ad) = actual_dst_ip {
            p.extend_from_slice(&ad.octets());
        }
        p.extend_from_slice(&(ndp_body.len() as u32).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 58]);
        p
    };
    let cksum = internet_checksum(&[&pseudo, &ndp_body]);
    ndp_body[2..4].copy_from_slice(&cksum.to_be_bytes());

    Ok((ndp_body, actual_dst_ip, 58))
}
