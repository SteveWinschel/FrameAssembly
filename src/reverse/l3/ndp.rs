//! IPv6 Neighbor Discovery Protocol (NDP, RFC 4861) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 4861 IPv6 Neighbor
//! Discovery Protocol (`ndp`, carried over ICMPv6 Next Header `58` with message types `133..=137`).
//! It decodes `routersolicit` (`133`), `routeradvert` (`134`, `routerlifetime`),
//! `neighborsolicit` (`135`, `target`), and `neighboradvert` (`136`, `target`), as well as
//! Source and Target Link-Layer Address options (`slla` and `tlla`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, format_mac_lower, ipv6_at, mac_at, push_if, push_mac_if, sd,
};

/// Decompiles an RFC 4861 IPv6 `ndp` message (`133..=137`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ndp(b: &[u8], src_mac: [u8; 6], dst_ip: Option<IpAddr>) -> ProtocolDissection {
    let (tp, mut t) = (b[0], String::from("ndp"));
    let dtgt = match dst_ip {
        Some(IpAddr::V6(v6)) if !v6.is_multicast() => IpAddr::V6(v6),
        _ => IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
    };
    let opt_off = match tp {
        133 if b.len() >= 8 => {
            t.push_str(" routersolicit");
            8
        }
        134 if b.len() >= 16 => {
            t.push_str(" routeradvert");
            push_if(&mut t, "routerlifetime", be_u16(b, 6), 1800);
            16
        }
        135 | 136 if b.len() >= 24 => {
            t.push_str(if tp == 135 {
                " neighborsolicit"
            } else {
                " neighboradvert"
            });
            push_if(&mut t, "target", IpAddr::V6(ipv6_at(b, 8)), dtgt);
            24
        }
        _ => b.len(),
    };
    let (mut pos, mut res) = (opt_off, Vec::new());
    while pos + 8 <= b.len() {
        let (ot, ob) = (b[pos], (b[pos + 1] as usize) * 8);
        if ob == 0 || pos + ob > b.len() {
            res.extend_from_slice(&b[pos..]);
            pos = b.len();
            break;
        }
        match (ot, ob) {
            (1, 8) => push_mac_if(&mut t, "slla", mac_at(b, pos + 2), src_mac),
            (2, 8) => {
                let m = mac_at(b, pos + 2);
                if tp != 136 || m != src_mac {
                    let _ = write!(t, " tlla {}", format_mac_lower(m));
                }
            }
            _ => res.extend_from_slice(&b[pos..pos + ob]),
        }
        pos += ob;
    }
    if pos < b.len() && res.is_empty() {
        res.extend_from_slice(&b[pos..]);
    }
    sd(Protocol::Ndp, t, res)
}
