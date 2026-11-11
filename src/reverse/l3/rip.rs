//! Routing Information Protocol (RIPv2 RFC 2453 & RIPng RFC 2080) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Routing Information
//! Protocol (`rip`, RFC 2453 / RFC 2080) messages carried over UDP ports `520` and `521`. It
//! validates the 24-byte RIPv2 header + Route Table Entry (RTE) and decodes `request` (`1`) and
//! `reply` (`2`) commands along with route `prefix`, `nexthop`, route `tag`, and hop `metric`.

use alloc::string::String;
use core::net::Ipv4Addr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, push_if, sd};

/// Decompiles an RFC 2453 `RIPv2` UDP payload (ports `520` / `521`) into a [`ProtocolDissection`].
pub(crate) fn dissect_rip(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 24 || !matches!(b[0], 1 | 2) {
        return None;
    }
    let mut t = String::from(if b[0] == 1 {
        "rip request"
    } else {
        "rip reply"
    });
    push_if(&mut t, "prefix", ipv4_at(b, 8), Ipv4Addr::new(10, 0, 0, 0));
    push_if(&mut t, "nexthop", ipv4_at(b, 16), Ipv4Addr::UNSPECIFIED);
    push_if(&mut t, "tag", be_u16(b, 6), 0);
    push_if(&mut t, "metric", be_u32(b, 20), 1);
    Some(sd(Protocol::Rip, t, b[24..].to_vec()))
}
