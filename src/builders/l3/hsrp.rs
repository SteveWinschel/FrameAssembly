//! Cisco Hot Standby Router Protocol (HSRP, RFC 2281) Layer 3 wire builder.
//!
//! Serializes an [`HsrpSpec`] into an RFC 2281 Cisco HSRP Hello packet carried over UDP port `1985`
//! to the IPv4 all-routers multicast address `224.0.0.2` (or over UDP port `2029` to IPv6 link-local
//! multicast `ff02::66` when the endpoints are IPv6). The header encodes Version (`0` for IPv4, `2`
//! for IPv6), Op Code (`0` Hello), State (`STATE`, default `16` Active), `Hellotime` (`HELLOTIME`,
//! default `3`s), `Holdtime` (`HOLDTIME`, default `10`s), `Priority` (`PRIORITY`, default `100`),
//! Standby `Group` (`GROUP`, default `1`), 8-byte zero-padded `Authentication Data` (`AUTH`, default
//! `"cisco"`), and the 4-byte or 16-byte Virtual IP address (`VIP`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b HSRP [GROUP <u8>] [PRIORITY <u8>] [STATE <u8>] [HELLOTIME <u8>] [HOLDTIME <u8>] [AUTH "<str>"] [VIP <ip>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2281 Cisco HSRP Hello payload over UDP `1985` (IPv4) or `2029` (IPv6).
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
