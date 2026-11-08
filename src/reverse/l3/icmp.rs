//! Internet Control Message Protocol (ICMPv4 RFC 792 & ICMPv6 RFC 4443) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IPv4 `ICMP` (IP protocol
//! `1`) and IPv6 `ICMPv6` (Next Header `58`) diagnostic and control messages. It maps message
//! types to canonical keywords (`echo_request`, `echo_reply`, `dest_unreach`, `time_exceeded`,
//! `redirect`, or numeric `type`), extracts `code`, Echo `id` and `seq`, or IPv4 Redirect
//! `gateway`, and elides default FrameAssembly echo payload bytes when unchanged.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, ipv4_at, push_hex, push_if, sd};

/// Decompiles an RFC 792 / RFC 4443 `ICMP` or `ICMPv6` message into a [`ProtocolDissection`].
pub(crate) fn dissect_icmp(b: &[u8], is_ipv6: bool, _src_ip: Option<IpAddr>) -> ProtocolDissection {
    if b.len() < 4 {
        return sd(Protocol::Icmp, String::from("icmp"), b.to_vec());
    }
    let (tp, c, mut t) = (b[0], b[1], String::from("icmp"));
    let (kw, is_echo, is_v4_red) = match (is_ipv6, tp) {
        (false, 8) | (true, 128) => (Some(" echo_request"), true, false),
        (false, 0) | (true, 129) => (Some(" echo_reply"), true, false),
        (false, 3) | (true, 1) => (Some(" dest_unreach"), false, false),
        (false, 11) | (true, 3) => (Some(" time_exceeded"), false, false),
        (false, 5) => (Some(" redirect"), false, true),
        (true, 137) => (Some(" redirect"), false, false),
        _ => (None, false, false),
    };
    if let Some(s) = kw {
        t.push_str(s);
    } else {
        let _ = write!(t, " type {tp}");
    }
    push_if(&mut t, "code", c, 0);
    let res = if is_echo && b.len() >= 8 {
        push_hex(&mut t, "id", u64::from(be_u16(b, 4)), 0x1234, 4);
        push_if(&mut t, "seq", be_u16(b, 6), 1);
        if &b[8..] == b"FrameAssembly ICMP Echo" {
            Vec::new()
        } else {
            b[8..].to_vec()
        }
    } else if is_v4_red && b.len() >= 8 {
        push_if(&mut t, "gateway", ipv4_at(b, 4), Ipv4Addr::UNSPECIFIED);
        b[8..].to_vec()
    } else {
        b.get(8..).unwrap_or(&b[4..]).to_vec()
    };
    sd(Protocol::Icmp, t, res)
}

/// Decompiles an RFC 4443 `ICMPv6` diagnostic or control message (`ip_proto == 58`) into a [`ProtocolDissection`].
pub(crate) fn dissect_icmpv6(b: &[u8], src_ip: Option<IpAddr>) -> ProtocolDissection {
    dissect_icmp(b, true, src_ip)
}

