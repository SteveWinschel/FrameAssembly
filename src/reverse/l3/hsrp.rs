//! Hot Standby Router Protocol (HSRP, RFC 2281) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Cisco Hot Standby Router
//! Protocol (`hsrp`, RFC 2281) messages carried over UDP ports `1985` (IPv4) and `2029` (IPv6).
//! It decodes the standby `group`, router `priority`, HSRP `state`, `hellotime`, `holdtime`,
//! cleartext `auth` string, and IPv4 or IPv6 virtual IP (`vip`) into canonical `.fasm` tokens.

use alloc::string::String;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, escape_fasm_string, ipv4_at, ipv6_at, push_if, sd, src_v4_or,
};

/// Decompiles an RFC 2281 `hsrp` UDP payload (ports `1985` / `2029`) into a [`ProtocolDissection`].
pub(crate) fn dissect_hsrp(b: &[u8], src_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
    if b.len() < 20 {
        return None;
    }
    let mut t = String::from("hsrp");
    push_if(&mut t, "group", b[6], 1);
    push_if(&mut t, "priority", u16::from(b[5]), 100);
    push_if(&mut t, "state", b[2], 16);
    push_if(&mut t, "hellotime", b[3], 3);
    push_if(&mut t, "holdtime", u16::from(b[4]), 10);
    let ab = &b[8..16];
    let at = ab.iter().position(|&c| c == 0).map_or(ab, |idx| &ab[..idx]);
    if let Ok(s) = core::str::from_utf8(at)
        && s != "cisco"
    {
        let _ = write!(t, " auth \"{}\"", escape_fasm_string(s));
    }
    let res = if b[0] == 2 && b.len() >= 32 {
        let dvip = match src_ip {
            Some(IpAddr::V6(v6)) => v6,
            _ => Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        };
        push_if(&mut t, "vip", ipv6_at(b, 16), dvip);
        b[32..].to_vec()
    } else {
        push_if(
            &mut t,
            "vip",
            ipv4_at(b, 16),
            src_v4_or(src_ip, Ipv4Addr::new(192, 168, 1, 1)),
        );
        b[20..].to_vec()
    };
    Some(sd(Protocol::Hsrp, t, res))
}
