//! Internet Group Management Protocol (IGMP, RFC 2236 / RFC 3376) Layer 3 wire builder.
//!
//! Serializes an [`IgmpSpec`] into an 8-byte RFC 2236 IGMPv2 packet encapsulated directly over IPv4
//! with IP protocol number `2` (`0x02`). The wire builder maps `REPORT` (`0x16`, default group
//! `239.1.1.1`), `QUERY` (`0x11`, default `Max Resp Time = 100` tenths of a second, default group
//! `224.0.0.1`), and `LEAVE` (`0x17`, default group `224.0.0.2`), writes the 32-bit IPv4 `GROUP`
//! address, and computes the 16-bit RFC 1071 ones'-complement Internet checksum.
//!
//! Canonical `.fasm` syntax:
//! `a -> b IGMP [QUERY | REPORT | LEAVE] [GROUP <ipv4>] [MAX_RESP <u8>] [V1 | V2 | V3]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::error::CompilerError;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2236 / RFC 3376 IGMP payload over IPv4 protocol `2`.
///
/// # Errors
/// Returns `CompilerError::BackendError` if called with invalid parameters.
pub fn build_igmp_payload(
    _ctx: &WireContext,
    spec: &IgmpSpec,
    payload: &[u8],
) -> Result<(Vec<u8>, IpAddr, u8), CompilerError> {
    let igmp_type = spec.igmp_type.unwrap_or(IgmpType::Report);
    let report_type = match spec.version {
        Some(1) => 0x12_u8, // IGMPv1 Membership Report (RFC 1112)
        Some(3) => 0x22_u8, // IGMPv3 Membership Report (RFC 3376)
        _ => 0x16_u8,       // IGMPv2 Membership Report (RFC 2236)
    };
    let (type_byte, max_resp, default_group) = match igmp_type {
        IgmpType::Report => (
            report_type,
            0_u8,
            if spec.version == Some(3) {
                [224, 0, 0, 22]
            } else {
                [239, 1, 1, 1]
            },
        ),
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
