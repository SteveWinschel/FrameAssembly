//! MLD Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2710 / RFC 3810 MLD payload for IPv6.
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
