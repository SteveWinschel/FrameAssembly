//! Routing Information Protocol (RIPv2 RFC 2453 / RIPng RFC 2080) Layer 3 wire builder.
//!
//! Serializes a [`RipSpec`] into a 24-byte RFC 2453 RIPv2 / RFC 2080 RIPng routing table message
//! carried over UDP port `520` to IPv4 multicast `224.0.0.9` (or UDP port `521` to IPv6 multicast
//! `ff02::9`). The 4-byte RIP header writes `Command` (`1` `REQUEST`, `2` `RESPONSE`), `Version` (`2`),
//! and 16-bit `Routing Domain` (`0`), followed by a 20-byte Route Table Entry encoding `AFI = 2` (IP),
//! 16-bit `Route Tag` (`TAG`, default `0`), 32-bit `PREFIX` (default `10.0.0.0`), 32-bit Subnet Mask
//! (`255.255.255.0`), 32-bit `NEXTHOP` (default `0.0.0.0`), and 32-bit `METRIC` (default `1`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b RIP [REQUEST | RESPONSE] [PREFIX <ip>] [METRIC <1..16>] [NEXTHOP <ip>] [TAG <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2453 RIPv2 / RFC 2080 RIPng payload over UDP port `520` (IPv4) or `521` (IPv6).
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
