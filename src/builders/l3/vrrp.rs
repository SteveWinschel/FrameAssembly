//! VRRP Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 5798 VRRPv3 advertisement payload over IP proto 112.
pub fn build_vrrp_payload(ctx: &WireContext, spec: &VrrpSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let is_v6 = matches!(ctx.src_ip, IpAddr::V6(_));
    let vrid = spec.vrid.unwrap_or(1);
    let priority = spec.priority.unwrap_or(100);
    let adv_int = spec.adv_int.unwrap_or(100); // 100 centiseconds = 1.0s

    let mut vrrp = Vec::with_capacity(28 + payload.len());
    vrrp.push(0x31); // Version 3, Type 1
    vrrp.push(vrid);
    vrrp.push(priority);
    vrrp.push(1); // Count IPvX Addr
    vrrp.extend_from_slice(&adv_int.to_be_bytes());
    vrrp.extend_from_slice(&[0, 0]); // Checksum placeholder

    match spec.vip.unwrap_or(ctx.src_ip) {
        IpAddr::V4(v4) => vrrp.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => vrrp.extend_from_slice(&v6.octets()),
    }
    vrrp.extend_from_slice(payload);

    let cksum = internet_checksum(&[&vrrp]);
    vrrp[6..8].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = if is_v6 {
        IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12))
    } else {
        IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 18))
    };

    (vrrp, dst_ip, 112)
}
