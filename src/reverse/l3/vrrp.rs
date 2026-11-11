//! Virtual Router Redundancy Protocol (VRRPv2 RFC 3768 & VRRPv3 RFC 5798) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Virtual Router Redundancy
//! Protocol (`vrrp`, IP protocol `112`) advertisement packets across both IPv4 and IPv6. It
//! extracts the VRRP protocol `version` (`2` or `3`), Virtual Router Identifier (`vrid`), router
//! `priority`, advertisement interval (`advint`), and IPv4 or IPv6 virtual IP address (`vip`).

use alloc::string::String;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, ipv4_at, ipv6_at, push_if, sd, src_v4_or};

/// Decompiles an RFC 3768 / RFC 5798 `vrrp` packet (`ip_proto == 112`) into a [`ProtocolDissection`].
pub(crate) fn dissect_vrrp(b: &[u8], is_ipv6: bool, src_ip: Option<IpAddr>) -> ProtocolDissection {
    if b.len() < 8 {
        return sd(Protocol::Vrrp, String::from("vrrp"), b.to_vec());
    }
    let ver = b[0] >> 4;
    let mut t = String::from("vrrp");
    push_if(&mut t, "version", ver, 3);
    push_if(&mut t, "vrid", b[1], 1);
    push_if(&mut t, "priority", u16::from(b[2]), 100);
    push_if(
        &mut t,
        "advint",
        if ver == 2 {
            u16::from(b[5])
        } else {
            be_u16(b, 4) & 0x0FFF
        },
        if ver == 2 { 1 } else { 100 },
    );
    let res = if !is_ipv6 && b.len() >= 12 {
        push_if(
            &mut t,
            "vip",
            ipv4_at(b, 8),
            src_v4_or(src_ip, Ipv4Addr::new(192, 168, 1, 254)),
        );
        b[if ver == 2 && b.len() >= 20 { 20 } else { 12 }..].to_vec()
    } else if is_ipv6 && b.len() >= 24 {
        let dvip = match src_ip {
            Some(IpAddr::V6(v6)) => v6,
            _ => Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xfe),
        };
        push_if(&mut t, "vip", ipv6_at(b, 8), dvip);
        b[24..].to_vec()
    } else {
        b[8..].to_vec()
    };
    sd(Protocol::Vrrp, t, res)
}
