//! HSRP Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2281 Cisco HSRP Hello payload over UDP 1985 (or RFC 2281/HSRPv2 IPv6 over UDP 2029).
pub fn build_hsrp_payload(ctx: &WireContext, spec: &HsrpSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u16) {
    let is_v6 = ctx.src_ip.is_ipv6();
    let mut hsrp = Vec::with_capacity(20 + payload.len());
    hsrp.push(if is_v6 { 2 } else { 0 }); // Version 2 for IPv6, Version 0 for IPv4
    hsrp.push(0); // Opcode 0: Hello
    hsrp.push(spec.state.unwrap_or(16)); // State: Active (16)
    hsrp.push(spec.hellotime.unwrap_or(3));
    hsrp.push(spec.holdtime.unwrap_or(10));
    hsrp.push(spec.priority.unwrap_or(100));
    hsrp.push(spec.group.unwrap_or(1));
    hsrp.push(0); // Reserved

    let auth = spec.auth.unwrap_or("cisco");
    let mut auth_bytes = [0u8; 8];
    for (i, b) in auth.as_bytes().iter().take(8).enumerate() {
        auth_bytes[i] = *b;
    }
    hsrp.extend_from_slice(&auth_bytes);

    if is_v6 {
        let vip_bytes = match spec.vip {
            Some(IpAddr::V6(v)) => v.octets(),
            _ => match ctx.src_ip {
                IpAddr::V6(s) => s.octets(),
                _ => [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
        };
        hsrp.extend_from_slice(&vip_bytes);
    } else {
        let vip_bytes = match spec.vip {
            Some(IpAddr::V4(v)) => v.octets(),
            _ => match ctx.src_ip {
                IpAddr::V4(s) => s.octets(),
                _ => [192, 168, 1, 1],
            },
        };
        hsrp.extend_from_slice(&vip_bytes);
    }
    hsrp.extend_from_slice(payload);

    let (dst_ip, dport) = if is_v6 {
        (
            IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x66)),
            2029,
        )
    } else {
        (
            IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 2)),
            1985,
        )
    };
    (hsrp, dst_ip, dport)
}
