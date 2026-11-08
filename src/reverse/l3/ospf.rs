//! Open Shortest Path First (OSPFv2 RFC 2328 & OSPFv3 RFC 5340) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Open Shortest Path First
//! (`OSPF`, IP protocol `89`) routing protocol packets across both OSPFv2 (24-byte header) and
//! OSPFv3 (16-byte header). It decodes `hello`, `dbd`, `lsr`, `lsu`, and `lsack` message types,
//! `router_id`, `area_id`, `hello_interval`, `priority`, and `dead_interval` into canonical
//! `.fasm` statements.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, push_if, sd, src_v4_or};

/// Decompiles an RFC 2328 / RFC 5340 `OSPF` packet (`ip_proto == 89`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ospf(b: &[u8], src_ip: Option<IpAddr>) -> ProtocolDissection {
    if b.len() < 16 {
        return sd(Protocol::Ospf, String::from("ospf"), b.to_vec());
    }
    let (ver, mt, mut t) = (b[0], b[1], String::from("ospf"));
    if let Some(kw) = [" hello", " dbd", " lsr", " lsu", " lsack"].get(mt.wrapping_sub(1) as usize)
    {
        t.push_str(kw);
    }
    push_if(
        &mut t,
        "router_id",
        ipv4_at(b, 4),
        src_v4_or(src_ip, Ipv4Addr::new(10, 0, 0, 1)),
    );
    push_if(&mut t, "area_id", be_u32(b, 8), 0);
    let hb = if ver == 3 { 16usize } else { 24usize };
    if b.len() < hb {
        return sd(Protocol::Ospf, t, Vec::new());
    }
    let body = &b[hb..];
    let res = match mt {
        1 if ver != 3 && body.len() >= 20 => {
            push_if(&mut t, "hello_interval", be_u16(body, 4), 10);
            push_if(&mut t, "priority", u16::from(body[7]), 1);
            push_if(&mut t, "dead_interval", be_u32(body, 8), 40);
            body[20..].to_vec()
        }
        1 if ver == 3 && body.len() >= 20 => {
            push_if(&mut t, "hello_interval", be_u16(body, 8), 10);
            push_if(&mut t, "priority", u16::from(body[4]), 1);
            push_if(&mut t, "dead_interval", u32::from(be_u16(body, 10)), 40);
            body[20..].to_vec()
        }
        2 if body.len() >= 8 => {
            push_if(&mut t, "dead_interval", be_u32(body, 4), 1);
            body[8..].to_vec()
        }
        3 if body.len() >= 12 => body[12..].to_vec(),
        4 if body.len() >= 4 => body[4..].to_vec(),
        5 if body.len() >= 20 => {
            push_if(&mut t, "hello_interval", be_u16(body, 0), 1);
            body[20..].to_vec()
        }
        _ => body.to_vec(),
    };
    sd(Protocol::Ospf, t, res)
}
