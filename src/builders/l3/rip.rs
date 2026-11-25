//! Routing Information Protocol (RIPv2 RFC 2453 / RIPng RFC 2080) Layer 3 wire builder.
//!
//! Serializes a [`RipSpec`] into an RFC 2453 RIPv2 message over UDP port `520` (default destination
//! `224.0.0.9`) on IPv4 endpoints, or an RFC 2080 RIPng message over UDP port `521` (default
//! destination `ff02::9`) on IPv6 endpoints. RIPv2 writes `Command` (`1`/`2`), `Version` (`2`),
//! `0x0000`, and a 20-byte IPv4 Route Table Entry (`AFI = 2`, `tag`, `prefix`, `255.255.255.0`,
//! `nexthop`, `metric`). RIPng writes `Command` (`1`/`2`), `Version` (`1`), `0x0000` must-be-zero,
//! an optional 20-byte Next Hop RTE (`metric = 0xFF`), and a 20-byte IPv6 prefix RTE (`prefix`,
//! `tag`, `prefix_len`, `metric`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b rip [request | response] [prefix <ip>] [metric <1..16>] [nexthop <ip>] [tag <u16>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Builds an RFC 2453 RIPv2 / RFC 2080 RIPng payload over UDP port `520` (IPv4) or `521` (IPv6).
pub fn build_rip_payload(ctx: &WireContext, spec: &RipSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u16) {
    let is_v6 = ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6();
    let cmd = match spec.command.unwrap_or(RipCommand::Response) {
        RipCommand::Request => 1_u8,
        RipCommand::Response => 2_u8,
    };

    if is_v6 {
        let mut rip = Vec::with_capacity(44 + payload.len());
        rip.push(cmd);
        rip.push(1); // RFC 2080 RIPng Version 1
        rip.extend_from_slice(&0_u16.to_be_bytes()); // Must be zero

        // Optional RFC 2080 §2.1.1 Next Hop RTE (metric = 0xFF) when non-unspecified IPv6 nexthop set
        if let Some(IpAddr::V6(nh)) = spec.nexthop
            && !nh.is_unspecified()
        {
            rip.extend_from_slice(&nh.octets());
            rip.extend_from_slice(&0_u16.to_be_bytes()); // Route Tag = 0
            rip.push(0); // Prefix Len = 0
            rip.push(0xFF); // Next Hop RTE marker
        }

        // 20-byte RFC 2080 §2.1 IPv6 Route Table Entry
        let prefix_octets = match spec.prefix {
            Some(IpAddr::V6(p)) => p.octets(),
            _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let prefix_len = if prefix_octets == [0u8; 16] { 0_u8 } else { 64_u8 };
        let metric = spec.metric.unwrap_or(1).min(255) as u8;
        rip.extend_from_slice(&prefix_octets);
        rip.extend_from_slice(&spec.tag.unwrap_or(0).to_be_bytes());
        rip.push(prefix_len);
        rip.push(metric);
        rip.extend_from_slice(payload);

        let dst_ip = match ctx.dst_ip {
            IpAddr::V6(d) if !d.is_unspecified() => IpAddr::V6(d),
            _ => IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 9)),
        };
        return (rip, dst_ip, 521);
    }

    let mut rip = Vec::with_capacity(24 + payload.len());
    rip.push(cmd);
    rip.push(2); // Version 2
    rip.extend_from_slice(&0_u16.to_be_bytes()); // Routing Domain

    // 20-byte IPv4 Route Table Entry
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

    let dst_ip = match ctx.dst_ip {
        IpAddr::V4(d) if !d.is_unspecified() => IpAddr::V4(d),
        _ => IpAddr::V4(Ipv4Addr::new(224, 0, 0, 9)),
    };

    (rip, dst_ip, 520)
}
