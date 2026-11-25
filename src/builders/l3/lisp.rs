//! Locator/ID Separation Protocol (LISP, RFC 9300 / RFC 9301) Layer 3 wire builder.
//!
//! Serializes a [`LispSpec`] into either an RFC 9300 LISP Data-Plane packet over UDP destination
//! port `4341` (8-byte flags/nonce/`iid` header + inner IPv4/IPv6 packet) or an RFC 9301 LISP
//! Control-Plane packet over UDP destination port `4342` (`maprequest`, `mapreply`, `mapregister`,
//! `mapnotify`, or `ecm`). Locator priority (`priority`), load weight (`weight`), Instance ID
//! (`iid`), `nonce`, `eid` prefix, and `rloc` address are encoded verbatim in wire order.
//!
//! Canonical `.frasm` syntax:
//! `a -> b lisp [data | maprequest | mapreply | mapregister | mapnotify | ecm] [flags <u8>] [iid <u24>] [nonce <u64>] [eid "<cidr>"] [rloc <ip>] [priority <u8>] [weight <u8>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parses an EID CIDR string into `(is_v6, addr_bytes, mask_len)`.
fn parse_lisp_eid(eid: Option<&str>, prefer_v6: bool) -> (bool, Vec<u8>, u8) {
    if let Some(raw) = eid {
        let s = raw.trim();
        let (ip_part, len_opt) = match s.split_once('/') {
            Some((ip, l)) => (ip.trim(), l.trim().parse::<u8>().ok()),
            None => (s, None),
        };
        if let Ok(addr) = ip_part.parse::<IpAddr>() {
            return match addr {
                IpAddr::V4(v4) => (false, v4.octets().to_vec(), len_opt.unwrap_or(24).min(32)),
                IpAddr::V6(v6) => (true, v6.octets().to_vec(), len_opt.unwrap_or(64).min(128)),
            };
        }
    }
    if prefer_v6 {
        (
            true,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)
                .octets()
                .to_vec(),
            32,
        )
    } else {
        (false, [192, 0, 2, 0].to_vec(), 24)
    }
}

/// Appends an AFI + IP address (or LCAF Instance ID `0x4003` when `iid` is `Some`) onto `out`.
fn push_lisp_afi_addr(out: &mut Vec<u8>, is_v6: bool, addr: &[u8], iid: Option<u32>) {
    let inner_afi = if is_v6 { 2_u16 } else { 1_u16 };
    if let Some(id) = iid {
        let lcaf_len = (6 + addr.len()) as u16;
        out.extend_from_slice(&16387_u16.to_be_bytes()); // AFI 16387: LCAF
        out.extend_from_slice(&[0, 0, 2, 0]); // Rsvd1=0, Flags=0, Type=2 (Instance ID), Rsvd2=0
        out.extend_from_slice(&lcaf_len.to_be_bytes());
        out.extend_from_slice(&(id & 0x00FF_FFFF).to_be_bytes());
        out.extend_from_slice(&inner_afi.to_be_bytes());
        out.extend_from_slice(addr);
    } else {
        out.extend_from_slice(&inner_afi.to_be_bytes());
        out.extend_from_slice(addr);
    }
}

/// Encodes an IPv4 or IPv6 address into `(afi, bytes)`.
fn encode_ip_afi(ip: IpAddr) -> (u16, Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2, v6.octets().to_vec()),
    }
}

/// Builds an RFC 9300 / RFC 9301 LISP payload and returns `(bytes, dst_port)` (`4341` Data / `4342` Control).
pub fn build_lisp_payload(ctx: &WireContext, spec: &LispSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let prefer_v6 = ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6();
    let msg_type = spec.msg_type.unwrap_or_else(|| {
        if spec.rloc.is_some() || spec.priority.is_some() || spec.weight.is_some() {
            LispType::MapReply
        } else if spec.eid.is_some() {
            LispType::MapRequest
        } else {
            LispType::Data
        }
    });

    let mut lisp = Vec::with_capacity(64 + payload.len());
    if msg_type == LispType::Data {
        let flags = spec
            .flags
            .unwrap_or_else(|| if spec.nonce.is_some() { 0x88 } else { 0x08 });
        let nonce24 = (spec.nonce.unwrap_or(0) & 0x00FF_FFFF) as u32;
        let iid24 = spec.iid.unwrap_or(0) & 0x00FF_FFFF;
        lisp.push(flags);
        lisp.push((nonce24 >> 16) as u8);
        lisp.push((nonce24 >> 8) as u8);
        lisp.push(nonce24 as u8);
        lisp.push((iid24 >> 16) as u8);
        lisp.push((iid24 >> 8) as u8);
        lisp.push(iid24 as u8);
        lisp.push(0); // LSB
        if payload.is_empty() {
            let inner_ethertype = if prefer_v6 { 0x86DD } else { 0x0800 };
            lisp.extend_from_slice(&super::gre::default_gre_inner_packet(inner_ethertype));
        } else {
            lisp.extend_from_slice(payload);
        }
        return (lisp, 4341);
    }

    let nonce = spec.nonce.unwrap_or(0x1122_3344_5566_7788);
    let flags_lo = spec.flags.unwrap_or(0) & 0x0F;
    let (eid_v6, eid_bytes, eid_plen) = parse_lisp_eid(spec.eid, prefer_v6);
    let rloc_ip = spec.rloc.unwrap_or(if prefer_v6 {
        if let IpAddr::V6(v6) = ctx.src_ip {
            IpAddr::V6(v6)
        } else {
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        }
    } else if let IpAddr::V4(v4) = ctx.src_ip {
        IpAddr::V4(v4)
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    });
    let (rloc_afi, rloc_bytes) = encode_ip_afi(rloc_ip);
    let prio = spec.priority.unwrap_or(1);
    let weight = spec.weight.unwrap_or(100);

    match msg_type {
        LispType::Data => unreachable!(),
        LispType::MapRequest => {
            lisp.extend_from_slice(&[0x10 | flags_lo, 0, 0, 1]);
            lisp.extend_from_slice(&nonce.to_be_bytes());
            let (src_afi, src_bytes) = encode_ip_afi(ctx.src_ip);
            lisp.extend_from_slice(&src_afi.to_be_bytes()); // Source EID AFI
            lisp.extend_from_slice(&src_bytes);
            lisp.extend_from_slice(&rloc_afi.to_be_bytes()); // ITR-RLOC AFI
            lisp.extend_from_slice(&rloc_bytes);
            lisp.push(0); // Reserved
            lisp.push(eid_plen);
            push_lisp_afi_addr(&mut lisp, eid_v6, &eid_bytes, spec.iid);
            lisp.extend_from_slice(payload);
        }
        LispType::MapReply => {
            lisp.extend_from_slice(&[0x20 | flags_lo, 0, 0, 1]);
            lisp.extend_from_slice(&nonce.to_be_bytes());
            lisp.extend_from_slice(&60_u32.to_be_bytes()); // Record TTL
            lisp.push(1); // Locator Count
            lisp.push(eid_plen);
            lisp.extend_from_slice(&[0, 0, 0, 0]); // ACT|A|Rsvd + Map Version
            push_lisp_afi_addr(&mut lisp, eid_v6, &eid_bytes, spec.iid);
            lisp.extend_from_slice(&[prio, weight, 255, 0]); // Priority, Weight, M-Prio, M-Weight
            lisp.extend_from_slice(&0x0004_u16.to_be_bytes()); // Locator flags: Reachable (R)
            lisp.extend_from_slice(&rloc_afi.to_be_bytes());
            lisp.extend_from_slice(&rloc_bytes);
            lisp.extend_from_slice(payload);
        }
        LispType::MapRegister | LispType::MapNotify => {
            let hi = if msg_type == LispType::MapRegister {
                0x30_u8
            } else {
                0x40_u8
            };
            lisp.extend_from_slice(&[hi | flags_lo, 0, 0, 1]);
            lisp.extend_from_slice(&nonce.to_be_bytes());
            lisp.extend_from_slice(&0_u16.to_be_bytes()); // Key ID (0 = None)
            lisp.extend_from_slice(&0_u16.to_be_bytes()); // Auth Data Length
            lisp.extend_from_slice(&60_u32.to_be_bytes()); // Record TTL
            lisp.push(1); // Locator Count
            lisp.push(eid_plen);
            lisp.extend_from_slice(&[0, 0, 0, 0]); // ACT|A|Rsvd + Map Version
            push_lisp_afi_addr(&mut lisp, eid_v6, &eid_bytes, spec.iid);
            lisp.extend_from_slice(&[prio, weight, 255, 0]);
            lisp.extend_from_slice(&0x0004_u16.to_be_bytes());
            lisp.extend_from_slice(&rloc_afi.to_be_bytes());
            lisp.extend_from_slice(&rloc_bytes);
            lisp.extend_from_slice(payload);
        }
        LispType::Ecm => {
            lisp.extend_from_slice(&[0x80 | flags_lo, 0, 0, 0]);
            if payload.is_empty() {
                // Minimal encapsulated IPv4+UDP+LISP Map-Request stub
                let mut inner_req = Vec::new();
                inner_req.extend_from_slice(&[0x10, 0, 0, 1]);
                inner_req.extend_from_slice(&nonce.to_be_bytes());
                let (src_afi, src_bytes) = encode_ip_afi(ctx.src_ip);
                inner_req.extend_from_slice(&src_afi.to_be_bytes());
                inner_req.extend_from_slice(&src_bytes);
                inner_req.extend_from_slice(&rloc_afi.to_be_bytes());
                inner_req.extend_from_slice(&rloc_bytes);
                inner_req.push(0);
                inner_req.push(eid_plen);
                push_lisp_afi_addr(&mut inner_req, eid_v6, &eid_bytes, spec.iid);
                let udp_len = (8 + inner_req.len()) as u16;
                let mut udp = Vec::with_capacity(usize::from(udp_len));
                udp.extend_from_slice(&4342_u16.to_be_bytes());
                udp.extend_from_slice(&4342_u16.to_be_bytes());
                udp.extend_from_slice(&udp_len.to_be_bytes());
                udp.extend_from_slice(&0_u16.to_be_bytes());
                udp.extend_from_slice(&inner_req);
                let total_ip = (20 + udp.len()) as u16;
                let mut ip4 = [
                    0x45, 0x00, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 198, 51, 100, 1, 198, 51, 100, 2,
                ];
                ip4[2..4].copy_from_slice(&total_ip.to_be_bytes());
                let ip_csum = crate::packet::internet_checksum(&[&ip4]);
                ip4[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                lisp.extend_from_slice(&ip4);
                lisp.extend_from_slice(&udp);
            } else {
                lisp.extend_from_slice(payload);
            }
        }
    }

    (lisp, 4342)
}
