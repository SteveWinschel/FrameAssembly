//! Routing Information Protocol (RIPv2 RFC 2453 & RIPng RFC 2080) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Routing Information
//! Protocol (`rip`, RFC 2453 RIPv2 / RFC 2080 RIPng) messages carried over UDP ports `520` and
//! `521`. It validates both 24-byte RIPv2 IPv4 entries and RFC 2080 IPv6 RIPng headers with
//! optional 20-byte Next-Hop RTE (`metric = 0xFF`) and Route RTE (`prefix`, `nexthop`, `tag`,
//! `metric`) while emitting canonical `.frasm` statements.

use alloc::string::String;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if, sd};

/// Decompiles an RFC 2453 `RIPv2` or RFC 2080 `RIPng` UDP payload (`520` / `521`).
pub(crate) fn dissect_rip(b: &[u8], is_ipv6: bool) -> Option<ProtocolDissection> {
    if b.len() < 24 || !matches!(b[0], 1 | 2) {
        return None;
    }
    let mut t = String::from(if b[0] == 1 {
        "rip request"
    } else {
        "rip reply"
    });
    if is_ipv6 && b[1] == 1 {
        let mut pos = 4usize;
        let mut nh_opt: Option<Ipv6Addr> = None;
        if b.len() >= 44 && b[pos + 19] == 0xFF {
            nh_opt = Some(ipv6_at(b, pos));
            pos += 20;
        }
        let prefix = ipv6_at(b, pos);
        let tag = be_u16(b, pos + 16);
        let metric = u32::from(b[pos + 19]);
        pos += 20;
        push_if(
            &mut t,
            "prefix",
            prefix,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        );
        if let Some(nh) = nh_opt {
            push_if(&mut t, "nexthop", nh, Ipv6Addr::UNSPECIFIED);
        }
        push_if(&mut t, "tag", tag, 0);
        push_if(&mut t, "metric", metric, 1);
        return Some(sd(Protocol::Rip, t, b[pos..].to_vec()));
    }
    push_if(&mut t, "prefix", ipv4_at(b, 8), Ipv4Addr::new(10, 0, 0, 0));
    push_if(&mut t, "nexthop", ipv4_at(b, 16), Ipv4Addr::UNSPECIFIED);
    push_if(&mut t, "tag", be_u16(b, 6), 0);
    push_if(&mut t, "metric", be_u32(b, 20), 1);
    Some(sd(Protocol::Rip, t, b[24..].to_vec()))
}
