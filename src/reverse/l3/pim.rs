//! Protocol Independent Multicast - Sparse Mode (PIM-SM, RFC 7761) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 7761 Protocol
//! Independent Multicast (`pim`, IP protocol `103`) packets across IPv4 and IPv6. It inspects the
//! 4-byte PIM common header and decodes `hello` (Holdtime option `1` and DR Priority option `19`),
//! `joinprune` (`rp`, `holdtime`, `group`, `source` for Family `1` IPv4 and Family `2` IPv6), and
//! `register` (`source`, `group` for inner IPv4 and IPv6 headers) into canonical `.frasm` tokens.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if, sd};

/// Decompiles an RFC 7761 `pim` packet (`ip_proto == 103`) into a [`ProtocolDissection`].
pub(crate) fn dissect_pim(
    b: &[u8],
    src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
) -> ProtocolDissection {
    if b.len() < 4 {
        return sd(Protocol::Pim, String::from("pim"), b.to_vec());
    }
    let (body, mut t, mut res) = (&b[4..], String::from("pim"), Vec::new());
    match b[0] & 0x0F {
        0 => {
            t.push_str(" hello");
            let mut pos = 0usize;
            while pos + 4 <= body.len() {
                let (ot, ol) = (be_u16(body, pos), be_u16(body, pos + 2) as usize);
                if pos + 4 + ol > body.len() {
                    break;
                }
                match (ot, ol) {
                    (1, 2) => push_if(&mut t, "holdtime", be_u16(body, pos + 4), 105),
                    (19, 4) => push_if(&mut t, "drpriority", be_u32(body, pos + 4), 1),
                    (20, 4) => {}
                    _ => res.extend_from_slice(&body[pos..pos + 4 + ol]),
                }
                pos += 4 + ol;
            }
            res.extend_from_slice(&body[pos..]);
        }
        3 if body.first() == Some(&2) && body.len() >= 66 => {
            t.push_str(" joinprune");
            let rp_v6 = ipv6_at(body, 2);
            let _ = write!(t, " rp {rp_v6}");
            push_if(&mut t, "holdtime", be_u16(body, 20), 210);
            push_if(
                &mut t,
                "group",
                ipv6_at(body, 26),
                Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1),
            );
            push_if(&mut t, "source", ipv6_at(body, 50), rp_v6);
            res.extend_from_slice(&body[66..]);
        }
        3 if body.len() >= 30 => {
            t.push_str(" joinprune");
            let rp_v4 = ipv4_at(body, 2);
            let _ = write!(t, " rp {rp_v4}");
            push_if(&mut t, "holdtime", be_u16(body, 8), 210);
            push_if(
                &mut t,
                "group",
                ipv4_at(body, 14),
                Ipv4Addr::new(239, 1, 1, 1),
            );
            push_if(&mut t, "source", ipv4_at(body, 26), rp_v4);
            res.extend_from_slice(&body[30..]);
        }
        1 if body.len() >= 44 && (body[4] >> 4) == 6 => {
            t.push_str(" register");
            let dsrc = match src_ip {
                Some(IpAddr::V6(v6)) => v6,
                _ => Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            };
            push_if(&mut t, "source", ipv6_at(body, 12), dsrc);
            push_if(
                &mut t,
                "group",
                ipv6_at(body, 28),
                Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1),
            );
            res.extend_from_slice(&body[44..]);
        }
        1 if body.len() >= 24 => {
            t.push_str(" register");
            let dsrc = match src_ip {
                Some(IpAddr::V4(v4)) => v4,
                Some(IpAddr::V6(v6)) => {
                    let o = v6.octets();
                    Ipv4Addr::new(o[12], o[13], o[14], o[15])
                }
                None => Ipv4Addr::new(10, 0, 0, 1),
            };
            push_if(&mut t, "source", ipv4_at(body, 16), dsrc);
            push_if(
                &mut t,
                "group",
                ipv4_at(body, 20),
                Ipv4Addr::new(239, 1, 1, 1),
            );
            res.extend_from_slice(&body[24..]);
        }
        _ => res.extend_from_slice(body),
    }
    sd(Protocol::Pim, t, res)
}
