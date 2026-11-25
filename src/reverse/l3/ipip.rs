//! IP-in-IP Encapsulation (RFC 2003 / RFC 2473 / RFC 4213) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IP-in-IP encapsulated
//! packets carried over outer IP protocol `4` (IPv4-in-IP) and `41` (IPv6-in-IP). It extracts
//! the inner IPv4 or IPv6 header fields (`v4` / `v6`, `srcip`, `dstip`, `innerttl`, `innerdscp`,
//! and inner `proto`), elides default inner ICMP/UDP/TCP probes, and emits canonical `.frasm`
//! `ipip` statements.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, push_if, sd};

/// Decompiles an RFC 2003 / RFC 2473 / RFC 4213 `ipip` packet (`ip_proto == 4 | 41`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ipip(
    b: &[u8],
    outer_ip_proto: u8,
    outer_is_ipv6: bool,
) -> ProtocolDissection {
    let mut t = String::from("ipip");
    if outer_ip_proto == 41 {
        let Some(v6) = super::ipv6::extract_ipv6_l3(b) else {
            return sd(Protocol::Ipip, t, b.to_vec());
        };
        if !outer_is_ipv6 {
            t.push_str(" v6");
        }
        let def_src = Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 1);
        let def_dst = Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 2);
        push_if(&mut t, "srcip", v6.src_ip, def_src);
        push_if(&mut t, "dstip", v6.dst_ip, def_dst);
        push_if(&mut t, "innerttl", v6.ttl, 64);
        push_if(&mut t, "innerdscp", v6.dscp, 0);
        let stub = crate::builders::l3::ipip::default_ipip_inner_stub(
            true,
            v6.next_header,
            IpAddr::V6(v6.src_ip),
            IpAddr::V6(v6.dst_ip),
        );
        let res = if !stub.is_empty() && v6.payload == stub.as_slice() {
            Vec::new()
        } else {
            v6.payload.to_vec()
        };
        let expected_proto = if res.is_empty() { 58 } else { 253 };
        push_if(&mut t, "proto", v6.next_header, expected_proto);
        sd(Protocol::Ipip, t, res)
    } else {
        let Some(v4) = super::ip::extract_ipv4_l3(b) else {
            return sd(Protocol::Ipip, t, b.to_vec());
        };
        if outer_is_ipv6 {
            t.push_str(" v4");
        }
        let def_src = Ipv4Addr::new(198, 51, 100, 1);
        let def_dst = Ipv4Addr::new(198, 51, 100, 2);
        push_if(&mut t, "srcip", v4.src_ip, def_src);
        push_if(&mut t, "dstip", v4.dst_ip, def_dst);
        push_if(&mut t, "innerttl", v4.ttl, 64);
        push_if(&mut t, "innerdscp", v4.dscp, 0);
        let stub = crate::builders::l3::ipip::default_ipip_inner_stub(
            false,
            v4.protocol,
            IpAddr::V4(v4.src_ip),
            IpAddr::V4(v4.dst_ip),
        );
        let res = if !stub.is_empty() && v4.payload == stub.as_slice() {
            Vec::new()
        } else {
            v4.payload.to_vec()
        };
        let expected_proto = if res.is_empty() { 1 } else { 253 };
        push_if(&mut t, "proto", v4.protocol, expected_proto);
        sd(Protocol::Ipip, t, res)
    }
}
