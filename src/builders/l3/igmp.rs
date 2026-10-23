//! IGMP Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2236 / RFC 3376 IGMP payload.
///
/// # Errors
/// Returns `CompilerError::BackendError` if called with IPv6 endpoints.
pub fn build_igmp_payload(
    _ctx: &WireContext,
    spec: &IgmpSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, IpAddr, u8), CompilerError> {
    let igmp_type = spec.igmp_type.unwrap_or(IgmpType::Report);
    let (type_byte, max_resp, default_group) = match igmp_type {
        IgmpType::Report => (0x16_u8, 0_u8, [239, 1, 1, 1]), // IGMPv2 Report
        IgmpType::Query => (0x11_u8, spec.max_resp.unwrap_or(100), [224, 0, 0, 1]), // General Query
        IgmpType::Leave => (0x17_u8, 0_u8, [224, 0, 0, 2]), // Leave Group
    };

    let group_octets = match spec.group {
        Some(IpAddr::V4(g)) => g.octets(),
        _ => default_group,
    };

    let mut igmp = Vec::with_capacity(8 + payload.len());
    igmp.push(type_byte);
    igmp.push(max_resp);
    igmp.extend_from_slice(&[0, 0]); // Checksum placeholder
    igmp.extend_from_slice(&group_octets);
    igmp.extend_from_slice(payload);

    let cksum = internet_checksum(&[&igmp]);
    igmp[2..4].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = IpAddr::V4(core::net::Ipv4Addr::from(group_octets));
    Ok((igmp, dst_ip, 2))
}
