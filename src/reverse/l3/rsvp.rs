//! Resource Reservation Protocol (RSVP / RSVP-TE, RFC 2205 / RFC 3209) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 2205 / RFC 3209 RSVP
//! signaling packets carried over IP protocol `46` (`0x2E`). It validates the 8-byte common
//! header and message length, walks typed RSVP objects (`SESSION`, `TIME_VALUES`, `ERROR_SPEC`,
//! `SENDER_TEMPLATE` / `FILTER_SPEC`, `LABEL`, and `HELLO`) with checked bounds, and extracts
//! message type, `tunnelid`, `lspid`, `label`, `refresh`, `srcip`, `dstip`, and `errcode`.

use alloc::string::String;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_if, sd};

/// Decompiles an RFC 2205 / RFC 3209 `rsvp` packet (`ip_proto == 46`) into a [`ProtocolDissection`].
pub(crate) fn dissect_rsvp(
    b: &[u8],
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
) -> ProtocolDissection {
    if b.len() < 8 || (b[0] >> 4) != 1 {
        return sd(Protocol::Rsvp, String::from("rsvp"), b.to_vec());
    }
    let msg_len = (be_u16(b, 6) as usize).clamp(8, b.len());
    let mut t = String::from("rsvp");
    let msg_type = b[1];
    match msg_type {
        1 => {} // default: path
        2 => t.push_str(" resv"),
        3 => t.push_str(" patherr"),
        4 => t.push_str(" resverr"),
        5 => t.push_str(" pathtear"),
        6 => t.push_str(" resvtear"),
        7 => t.push_str(" resvconf"),
        20 => t.push_str(" hello"),
        _ => {}
    }

    let mut sess_dst: Option<IpAddr> = None;
    let mut sess_src: Option<IpAddr> = None;
    let mut tunnel_id: Option<u16> = None;
    let mut lsp_id: Option<u16> = None;
    let mut label: Option<u32> = None;
    let mut refresh: Option<u32> = None;
    let mut err_code: Option<u8> = None;

    let mut pos = 8usize;
    while pos + 4 <= msg_len {
        let obj_len = be_u16(b, pos) as usize;
        if obj_len < 4 || pos + obj_len > msg_len {
            break;
        }
        let class = b[pos + 2];
        let ctype = b[pos + 3];
        let obj = &b[pos..pos + obj_len];
        match (class, ctype) {
            (1, 1) if obj.len() >= 12 => {
                sess_dst = Some(IpAddr::V4(ipv4_at(obj, 4)));
            }
            (1, 2) if obj.len() >= 24 => {
                sess_dst = Some(IpAddr::V6(ipv6_at(obj, 4)));
            }
            (1, 7) if obj.len() >= 16 => {
                sess_dst = Some(IpAddr::V4(ipv4_at(obj, 4)));
                tunnel_id = Some(be_u16(obj, 10));
            }
            (1, 8) if obj.len() >= 40 => {
                sess_dst = Some(IpAddr::V6(ipv6_at(obj, 4)));
                tunnel_id = Some(be_u16(obj, 22));
            }
            (5, 1) if obj.len() >= 8 => {
                refresh = Some(be_u32(obj, 4));
            }
            (6, 1) if obj.len() >= 12 => {
                sess_src.get_or_insert_with(|| IpAddr::V4(ipv4_at(obj, 4)));
                err_code = Some(obj[9]);
            }
            (6, 2) if obj.len() >= 24 => {
                sess_src.get_or_insert_with(|| IpAddr::V6(ipv6_at(obj, 4)));
                err_code = Some(obj[21]);
            }
            (10 | 11, 1) if obj.len() >= 12 => {
                sess_src = Some(IpAddr::V4(ipv4_at(obj, 4)));
            }
            (10 | 11, 7) if obj.len() >= 12 => {
                sess_src = Some(IpAddr::V4(ipv4_at(obj, 4)));
                lsp_id = Some(be_u16(obj, 10));
            }
            (10 | 11, 2) if obj.len() >= 24 => {
                sess_src = Some(IpAddr::V6(ipv6_at(obj, 4)));
            }
            (10 | 11, 8) if obj.len() >= 24 => {
                sess_src = Some(IpAddr::V6(ipv6_at(obj, 4)));
                lsp_id = Some(be_u16(obj, 22));
            }
            (16, 1) if obj.len() >= 8 => {
                label = Some(be_u32(obj, 4) & 0x000F_FFFF);
            }
            _ => {}
        }
        pos += obj_len;
    }

    if let Some(tid) = tunnel_id {
        let _ = write!(t, " tunnelid {tid}");
    }
    if let Some(lid) = lsp_id {
        let _ = write!(t, " lspid {lid}");
    }
    if let Some(lbl) = label {
        let _ = write!(t, " label {lbl}");
    }
    if let Some(ref_ms) = refresh {
        push_if(&mut t, "refresh", ref_ms, 30_000);
    }
    if let Some(s) = sess_src {
        let def_s = match (s, src_ip) {
            (IpAddr::V6(_), Some(IpAddr::V6(v6))) if !v6.is_unspecified() => IpAddr::V6(v6),
            (IpAddr::V6(_), _) => IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            (IpAddr::V4(_), Some(IpAddr::V4(v4))) if !v4.is_unspecified() => IpAddr::V4(v4),
            (IpAddr::V4(_), _) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        push_if(&mut t, "srcip", s, def_s);
    }
    if let Some(d) = sess_dst {
        let def_d = match (d, dst_ip) {
            (IpAddr::V6(_), Some(IpAddr::V6(v6))) if !v6.is_unspecified() => IpAddr::V6(v6),
            (IpAddr::V6(_), _) => IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            (IpAddr::V4(_), Some(IpAddr::V4(v4))) if !v4.is_unspecified() => IpAddr::V4(v4),
            (IpAddr::V4(_), _) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        };
        push_if(&mut t, "dstip", d, def_d);
    }
    if let Some(ec) = err_code {
        push_if(&mut t, "errcode", ec, 2);
    }

    let res = b.get(msg_len..).unwrap_or(&[]).to_vec();
    sd(Protocol::Rsvp, t, res)
}
