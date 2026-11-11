//! Protocol Independent Multicast - Sparse Mode (PIM-SM, RFC 7761) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 7761 Protocol
//! Independent Multicast (`pim`, IP protocol `103`) packets. It inspects the 4-byte PIM common
//! header and decodes `hello` (Holdtime option `1` and DR Priority option `19`), `joinprune`
//! (`rp`, `holdtime`, `group`, `source`), and `register` (`source`, `group`) messages into
//! canonical `.fasm` statements.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, push_if, sd, src_v4_or};

/// Decompiles an RFC 7761 `pim` packet (`ip_proto == 103`) into a [`ProtocolDissection`].
pub(crate) fn dissect_pim(b: &[u8], src_ip: Option<IpAddr>) -> ProtocolDissection {
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
        3 if body.len() >= 30 => {
            t.push_str(" joinprune");
            let dup = src_v4_or(src_ip, Ipv4Addr::new(10, 0, 0, 1));
            push_if(&mut t, "rp", ipv4_at(body, 2), dup);
            push_if(&mut t, "holdtime", be_u16(body, 8), 210);
            push_if(
                &mut t,
                "group",
                ipv4_at(body, 14),
                Ipv4Addr::new(239, 1, 1, 1),
            );
            push_if(&mut t, "source", ipv4_at(body, 26), dup);
            res.extend_from_slice(&body[30..]);
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
