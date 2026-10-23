//! RIP Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2453 / RFC 2080 RIP payload over UDP 520 / 521.
pub fn build_rip_payload(ctx: &WireContext, spec: &RipSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u16) {
    let is_v6 = matches!(ctx.dst_ip, IpAddr::V6(_));
    let port = if is_v6 { 521 } else { 520 };
    let cmd = match spec.command.unwrap_or(RipCommand::Response) {
        RipCommand::Request => 1,
        RipCommand::Response => 2,
    };

    let mut rip = Vec::with_capacity(24 + payload.len());
    rip.push(cmd);
    rip.push(2); // Version 2
    rip.extend_from_slice(&0_u16.to_be_bytes()); // Routing Domain

    // 20-byte Route Table Entry
    rip.extend_from_slice(&2_u16.to_be_bytes()); // AFI: IP
    rip.extend_from_slice(&spec.tag.unwrap_or(0).to_be_bytes());
    let prefix_octets = match spec.prefix {
        Some(IpAddr::V4(p)) => p.octets(),
        _ => [10, 0, 0, 0],
    };
    rip.extend_from_slice(&prefix_octets);
    rip.extend_from_slice(&[255, 255, 255, 0]); // Subnet Mask
    let nexthop_octets = match spec.nexthop {
        Some(IpAddr::V4(n)) => n.octets(),
        _ => [0, 0, 0, 0],
    };
    rip.extend_from_slice(&nexthop_octets);
    rip.extend_from_slice(&spec.metric.unwrap_or(1).to_be_bytes());
    rip.extend_from_slice(payload);

    let dst_ip = if is_v6 {
        IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 9))
    } else {
        IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 9))
    };

    (rip, dst_ip, port)
}
