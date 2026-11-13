//! IPv6 Multicast Listener Discovery (MLD, RFC 2710 / RFC 3810) Layer 3 wire builder.
//!
//! Serializes an [`MldSpec`] into a 24-byte RFC 2710 MLDv1 ICMPv6 control message carried over IPv6
//! Next Header `58` (`0x3A`). The builder maps `query` (`Type = 130`, default group `ff02::1`),
//! `report` (`Type = 131`, default group `ff02::1`), and `done` (`Type = 132`, default group
//! `ff02::2`), writes the 16-bit `Maximum Response Delay` (`maxrespdelay`) and 128-bit IPv6
//! `Multicast Address` (`multicastaddr`), and computes the mandatory 40-byte IPv6 pseudo-header checksum.
//!
//! Canonical `.frasm` syntax:
//! `a -> b mld [query | report | done] [multicastaddr <ipv6>] [maxrespdelay <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2710 / RFC 3810 MLD payload for IPv6 over ICMPv6 (`58`).
///
/// # Errors
/// Returns `CompilerError::BackendError` if called with IPv4 endpoints.
pub fn build_mld_payload(
    ctx: &WireContext,
    spec: &MldSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, IpAddr, u8), CompilerError> {
    let (src_v6, _) = match (ctx.src_ip, ctx.dst_ip) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => {
            return Err(CompilerError::BackendError(
                "MLD is strictly an IPv6 protocol".to_string(),
            ));
        }
    };

    let mld_type = spec.mld_type.unwrap_or(MldType::Report);
    let (type_byte, default_mcast) = match mld_type {
        MldType::Report => (131_u8, [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        MldType::Query => (130_u8, [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        MldType::Done => (132_u8, [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
    };

    let mcast_octets = match spec.multicast_addr {
        Some(IpAddr::V6(m)) => m.octets(),
        _ => default_mcast,
    };

    let mut mld = Vec::with_capacity(24 + payload.len());
    mld.push(type_byte);
    mld.push(0); // Code 0
    mld.extend_from_slice(&[0, 0]); // Checksum placeholder
    mld.extend_from_slice(&spec.max_resp_delay.unwrap_or(0).to_be_bytes());
    mld.extend_from_slice(&[0, 0]); // Reserved
    mld.extend_from_slice(&mcast_octets);
    mld.extend_from_slice(payload);

    let pseudo = {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(&src_v6.octets());
        p.extend_from_slice(&mcast_octets);
        p.extend_from_slice(&(mld.len() as u32).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 58]);
        p
    };
    let cksum = internet_checksum(&[&pseudo, &mld]);
    mld[2..4].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = IpAddr::V6(core::net::Ipv6Addr::from(mcast_octets));
    Ok((mld, dst_ip, 58))
}
