//! Virtual Router Redundancy Protocol (VRRPv3 RFC 5798) Layer 3 wire builder.
//!
//! Serializes a [`VrrpSpec`] into an RFC 5798 VRRPv3 Advertisement packet carried over IP protocol
//! `112` (`0x70`) and addressed to the VRRP multicast group (`224.0.0.18` for IPv4, `ff02::12` for
//! IPv6). The wire header encodes `Version = 3` and `Type = 1` (`0x31`), 8-bit `Virtual Rtr ID`
//! (`VRID`, default `1`), 8-bit `Priority` (`PRIORITY`, default `100`), `Count IPvX Addr = 1`,
//! 16-bit `Max Adver Int` in centiseconds (`ADV_INT`, default `100`), 16-bit Checksum, and the
//! 4-byte IPv4 or 16-byte IPv6 Virtual IP address (`VIP`).
//!
//! Canonical `.fasm` syntax:
//! `a -> b VRRP [VRID <1..255>] [PRIORITY <0..255>] [ADV_INT <u16>] [VIP <ip>] [VERSION <2|3>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 5798 VRRPv3 or RFC 3768 VRRPv2 advertisement payload over IP protocol `112`.
pub fn build_vrrp_payload(ctx: &WireContext, spec: &VrrpSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let is_v6 = matches!(ctx.src_ip, IpAddr::V6(_));
    let version = spec.version.unwrap_or(3);
    let vrid = spec.vrid.unwrap_or(1);
    let priority = spec.priority.unwrap_or(100);

    let dst_ip = if is_v6 {
        IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12))
    } else {
        IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 18))
    };

    let mut vrrp = Vec::with_capacity(28 + payload.len());
    if version == 2 {
        // RFC 3768 VRRPv2 Advertisement
        let adv_sec = spec.adv_int.unwrap_or(1).clamp(1, 255) as u8;
        vrrp.push(0x21); // Version 2, Type 1
        vrrp.push(vrid);
        vrrp.push(priority);
        vrrp.push(1); // Count IP Addrs
        vrrp.push(0); // Auth Type: 0 (No Authentication)
        vrrp.push(adv_sec);
        vrrp.extend_from_slice(&[0, 0]); // Checksum placeholder

        match spec.vip.unwrap_or(ctx.src_ip) {
            IpAddr::V4(v4) => vrrp.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => vrrp.extend_from_slice(&v6.octets()),
        }
        vrrp.extend_from_slice(&[0u8; 8]); // RFC 3768 Auth Data (8 zero octets)
        vrrp.extend_from_slice(payload);

        let cksum = internet_checksum(&[&vrrp]);
        vrrp[6..8].copy_from_slice(&cksum.to_be_bytes());
    } else {
        // RFC 5798 VRRPv3 Advertisement
        let adv_int = spec.adv_int.unwrap_or(100) & 0x0FFF; // 12-bit Max Adver Int in centiseconds
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

        // RFC 5798 §5.2.8: VRRPv3 checksum includes the IPv4 (12B) or IPv6 (40B) pseudo-header
        let cksum = match (ctx.src_ip, dst_ip) {
            (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
                let mut pseudo = [0u8; 12];
                pseudo[0..4].copy_from_slice(&src_v4.octets());
                pseudo[4..8].copy_from_slice(&dst_v4.octets());
                pseudo[8] = 0;
                pseudo[9] = 112;
                pseudo[10..12].copy_from_slice(&(vrrp.len() as u16).to_be_bytes());
                internet_checksum(&[&pseudo, &vrrp])
            }
            (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
                let mut pseudo = [0u8; 40];
                pseudo[0..16].copy_from_slice(&src_v6.octets());
                pseudo[16..32].copy_from_slice(&dst_v6.octets());
                pseudo[32..36].copy_from_slice(&(vrrp.len() as u32).to_be_bytes());
                pseudo[39] = 112;
                internet_checksum(&[&pseudo, &vrrp])
            }
            _ => internet_checksum(&[&vrrp]),
        };
        vrrp[6..8].copy_from_slice(&cksum.to_be_bytes());
    }

    (vrrp, dst_ip, 112)
}

