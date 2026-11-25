//! Cisco Gateway Load Balancing Protocol (GLBP) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for Cisco GLBP redundancy and
//! active-active load-balancing packets carried over UDP port `3222`. It validates the 12-byte
//! GLBP common header (`version`, `group`, `ownerid` MAC) and parses Type `1` Hello TLVs (`state`,
//! `priority`, `hellotime`, `holdtime`, `redirect`, `timeout`, `vip`), Type `2` Request/Response
//! TLVs (`forwarder`, `state`, `priority`, `weight`, `vmac`), and Type `3` plain-text Auth TLVs
//! (`auth`) into canonical `.frasm` tokens.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, be_u32, format_mac_lower, ipv4_at, ipv6_at, mac_at, push_hex,
    push_if, push_str_if, sd, src_v4_or,
};

/// Decompiles a Cisco `glbp` UDP payload (port `3222`) into a [`ProtocolDissection`].
pub(crate) fn dissect_glbp(b: &[u8], src_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
    if b.len() < 14 {
        return None;
    }
    let ver = b[0];
    let group = be_u16(b, 2);
    let owner_id = mac_at(b, 6);

    let mut t = String::from("glbp");
    let mut pos = 12usize;
    let mut saw_primary = false;
    let mut deferred_hdr = String::new();
    push_if(&mut deferred_hdr, "version", ver, 1);
    push_if(&mut deferred_hdr, "group", group, 1);
    let _ = write!(deferred_hdr, " ownerid {}", format_mac_lower(owner_id));

    while pos + 2 <= b.len() {
        let tlv_type = b[pos];
        let tlv_len = usize::from(b[pos + 1]);
        if tlv_len < 2 || pos + tlv_len > b.len() {
            break;
        }
        let tlv = &b[pos..pos + tlv_len];
        match tlv_type {
            1 if !saw_primary && tlv.len() >= 24 => {
                saw_primary = true;
                t.push_str(&deferred_hdr);
                push_hex(&mut t, "state", u64::from(tlv[3]), 0x20, 2);
                push_if(&mut t, "priority", tlv[5], 100);
                push_if(&mut t, "hellotime", be_u32(tlv, 8), 3000);
                push_if(&mut t, "holdtime", be_u32(tlv, 12), 10000);
                push_if(&mut t, "redirect", be_u16(tlv, 16), 600);
                push_if(&mut t, "timeout", be_u16(tlv, 18), 14400);
                let addr_type = tlv[22];
                let addr_len = tlv[23];
                if addr_type == 1 && addr_len == 4 && tlv.len() >= 28 {
                    let dv4 = src_v4_or(src_ip, Ipv4Addr::new(192, 168, 1, 1));
                    push_if(&mut t, "vip", ipv4_at(tlv, 24), dv4);
                } else if addr_type == 2 && addr_len == 16 && tlv.len() >= 40 {
                    let dv6 = match src_ip {
                        Some(IpAddr::V6(v6)) => v6,
                        _ => Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                    };
                    push_if(&mut t, "vip", ipv6_at(tlv, 24), dv6);
                }
            }
            2 if !saw_primary && tlv.len() >= 20 => {
                saw_primary = true;
                let fwd = tlv[2];
                let vf_state = tlv[3];
                let prio = tlv[5];
                let weight = tlv[6];
                let vmac = mac_at(tlv, 14);
                let is_req = vmac == [0; 6] && vf_state == 0;
                t.push_str(if is_req { " request" } else { " response" });
                t.push_str(&deferred_hdr);
                if is_req {
                    push_if(&mut t, "forwarder", fwd, 0);
                    push_hex(&mut t, "state", u64::from(vf_state), 0, 2);
                } else {
                    push_if(&mut t, "forwarder", fwd, 1);
                    push_hex(&mut t, "state", u64::from(vf_state), 0x20, 2);
                    let def_vmac = [0x00, 0x07, 0xb4, 0x00, (group & 0xFF) as u8, fwd];
                    if vmac != def_vmac {
                        let _ = write!(t, " vmac {}", format_mac_lower(vmac));
                    }
                }
                push_if(&mut t, "priority", prio, 100);
                push_if(&mut t, "weight", weight, 100);
            }
            3 if tlv.len() >= 4 && tlv[2] == 1 => {
                if !saw_primary {
                    t.push_str(&deferred_hdr);
                    saw_primary = true;
                }
                let alen = usize::from(tlv[3]);
                if 4 + alen <= tlv.len()
                    && let Ok(auth_str) = core::str::from_utf8(&tlv[4..4 + alen])
                {
                    push_str_if(&mut t, "auth", auth_str, "");
                }
            }
            _ => break,
        }
        pos += tlv_len;
    }

    if !saw_primary {
        return None;
    }
    let res: Vec<u8> = b[pos..].to_vec();
    Some(sd(Protocol::Glbp, t, res))
}
