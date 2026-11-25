//! Locator/ID Separation Protocol (LISP, RFC 9300 / RFC 9301) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for LISP Data-Plane packets
//! over UDP port `4341` (RFC 9300) and LISP Control-Plane packets over UDP port `4342` (RFC 9301).
//! It validates the 8-byte LISP data header (`flags`, `nonce`, `iid`) and control message headers
//! (`maprequest`, `mapreply`, `mapregister`, `mapnotify`, `ecm`) including LCAF Instance IDs
//! (`0x4003`), `eid` prefixes, `rloc` addresses, `priority`, and `weight`, while eliding default
//! inner payloads cleanly.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, be_u64, ipv4_at, ipv6_at, push_hex, push_if, sd};

/// Appends `eid` and `rloc` modifiers when they differ from default values for `src_ip`.
fn push_lisp_eid_rloc(
    t: &mut String,
    eid_ip: IpAddr,
    plen: u8,
    iid: Option<u32>,
    rloc: IpAddr,
    src_ip: Option<IpAddr>,
) {
    if let Some(id) = iid {
        let _ = write!(t, " iid {id}");
    }
    let prefer_v6 = src_ip.is_some_and(|ip| ip.is_ipv6());
    let is_def_eid = if prefer_v6 {
        eid_ip == IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)) && plen == 32
    } else {
        eid_ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)) && plen == 24
    };
    if !is_def_eid {
        let _ = write!(t, " eid \"{eid_ip}/{plen}\"");
    }
    if Some(rloc) != src_ip {
        let _ = write!(t, " rloc {rloc}");
    }
}

/// Parses an AFI-encoded address (IPv4 `1`, IPv6 `2`, or LCAF Instance ID `16387`) at `pos`.
fn decode_afi_addr(b: &[u8], pos: usize) -> Option<(IpAddr, Option<u32>, usize)> {
    if pos + 2 > b.len() {
        return None;
    }
    let afi = be_u16(b, pos);
    match afi {
        1 if pos + 6 <= b.len() => Some((IpAddr::V4(ipv4_at(b, pos + 2)), None, pos + 6)),
        2 if pos + 18 <= b.len() => Some((IpAddr::V6(ipv6_at(b, pos + 2)), None, pos + 18)),
        16387 if pos + 14 <= b.len() => {
            let lcaf_type = b[pos + 4];
            let lcaf_len = be_u16(b, pos + 6) as usize;
            let end = pos.checked_add(8)?.checked_add(lcaf_len)?;
            if lcaf_type != 2 || end > b.len() || lcaf_len < 6 {
                return None;
            }
            let iid = be_u32(b, pos + 8) & 0x00FF_FFFF;
            let (inner_ip, _, next) = decode_afi_addr(b, pos + 12)?;
            Some((inner_ip, Some(iid), next.max(end)))
        }
        _ => None,
    }
}

/// Decompiles an RFC 9301 LISP Control-Plane message over UDP port `4342`.
fn dissect_lisp_control(b: &[u8], src_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
    if b.len() < 4 {
        return None;
    }
    let mtype = b[0] >> 4;
    let flags_lo = b[0] & 0x0F;
    let mut t = String::from("lisp");

    match mtype {
        1 if b.len() >= 12 => {
            t.push_str(" maprequest");
            push_hex(&mut t, "flags", u64::from(flags_lo), 0, 2);
            let nonce = be_u64(b, 4);
            push_hex(&mut t, "nonce", nonce, 0x1122_3344_5566_7788, 16);
            let (_, _, p1) = decode_afi_addr(b, 12)?;
            let (rloc, _, p2) = decode_afi_addr(b, p1)?;
            if p2 + 2 > b.len() {
                return None;
            }
            let plen = b[p2 + 1];
            let (eid_ip, iid, p3) = decode_afi_addr(b, p2 + 2)?;
            push_lisp_eid_rloc(&mut t, eid_ip, plen, iid, rloc, src_ip);
            Some(sd(Protocol::Lisp, t, b[p3..].to_vec()))
        }
        2 if b.len() >= 24 => {
            t.push_str(" mapreply");
            push_hex(&mut t, "flags", u64::from(flags_lo), 0, 2);
            let nonce = be_u64(b, 4);
            push_hex(&mut t, "nonce", nonce, 0x1122_3344_5566_7788, 16);
            let plen = b[17];
            let (eid_ip, iid, p1) = decode_afi_addr(b, 22)?;
            if p1 + 6 > b.len() {
                if let Some(id) = iid {
                    let _ = write!(t, " iid {id}");
                }
                let _ = write!(t, " eid \"{eid_ip}/{plen}\"");
                return Some(sd(Protocol::Lisp, t, b[p1..].to_vec()));
            }
            let prio = b[p1];
            let weight = b[p1 + 1];
            let (rloc, _, p2) = decode_afi_addr(b, p1 + 6)?;
            push_lisp_eid_rloc(&mut t, eid_ip, plen, iid, rloc, src_ip);
            push_if(&mut t, "priority", prio, 1);
            push_if(&mut t, "weight", weight, 100);
            Some(sd(Protocol::Lisp, t, b[p2..].to_vec()))
        }
        3 | 4 if b.len() >= 28 => {
            t.push_str(if mtype == 3 {
                " mapregister"
            } else {
                " mapnotify"
            });
            push_hex(&mut t, "flags", u64::from(flags_lo), 0, 2);
            let nonce = be_u64(b, 4);
            push_hex(&mut t, "nonce", nonce, 0x1122_3344_5566_7788, 16);
            let auth_len = be_u16(b, 14) as usize;
            let rec_off = 16usize.checked_add(auth_len)?;
            if rec_off + 10 > b.len() {
                return None;
            }
            let plen = b[rec_off + 5];
            let (eid_ip, iid, p1) = decode_afi_addr(b, rec_off + 10)?;
            if p1 + 6 > b.len() {
                if let Some(id) = iid {
                    let _ = write!(t, " iid {id}");
                }
                let _ = write!(t, " eid \"{eid_ip}/{plen}\"");
                return Some(sd(Protocol::Lisp, t, b[p1..].to_vec()));
            }
            let prio = b[p1];
            let weight = b[p1 + 1];
            let (rloc, _, p2) = decode_afi_addr(b, p1 + 6)?;
            push_lisp_eid_rloc(&mut t, eid_ip, plen, iid, rloc, src_ip);
            push_if(&mut t, "priority", prio, 1);
            push_if(&mut t, "weight", weight, 100);
            Some(sd(Protocol::Lisp, t, b[p2..].to_vec()))
        }
        8 => {
            t.push_str(" ecm");
            push_hex(&mut t, "flags", u64::from(flags_lo), 0, 2);
            let inner = &b[4..];
            let is_default_ecm = inner.len() >= 28
                && inner[0] == 0x45
                && inner[9] == 17
                && inner[12..20] == [198, 51, 100, 1, 198, 51, 100, 2]
                && inner.get(20..24) == Some(&[0x10, 0xf6, 0x10, 0xf6][..]);
            let mut res = Vec::new();
            if is_default_ecm {
                if let Some(sub) = inner.get(28..)
                    && sub.len() >= 12
                    && (sub[0] >> 4) == 1
                {
                    let nonce = be_u64(sub, 4);
                    push_hex(&mut t, "nonce", nonce, 0x1122_3344_5566_7788, 16);
                    if let Some((_, _, p1)) = decode_afi_addr(sub, 12)
                        && let Some((rloc, _, p2)) = decode_afi_addr(sub, p1)
                        && p2 + 2 <= sub.len()
                    {
                        let plen = sub[p2 + 1];
                        if let Some((eid_ip, iid, p3)) = decode_afi_addr(sub, p2 + 2)
                            && p3 == sub.len()
                        {
                            push_lisp_eid_rloc(&mut t, eid_ip, plen, iid, rloc, src_ip);
                        } else {
                            res.extend_from_slice(inner);
                        }
                    } else {
                        res.extend_from_slice(inner);
                    }
                } else {
                    res.extend_from_slice(inner);
                }
            } else {
                res.extend_from_slice(inner);
            }
            Some(sd(Protocol::Lisp, t, res))
        }
        _ => None,
    }
}

/// Decompiles an RFC 9300 LISP Data (`4341`) or RFC 9301 LISP Control (`4342`) UDP payload.
pub(crate) fn dissect_lisp(
    b: &[u8],
    sp: u16,
    dp: u16,
    src_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if sp == 4342 || dp == 4342 {
        return dissect_lisp_control(b, src_ip);
    }
    if b.len() < 8 {
        return None;
    }
    let flags = b[0];
    let nonce24 = (u64::from(b[1]) << 16) | (u64::from(b[2]) << 8) | u64::from(b[3]);
    let iid24 = (u32::from(b[4]) << 16) | (u32::from(b[5]) << 8) | u32::from(b[6]);
    let def_flags = if nonce24 != 0 { 0x88 } else { 0x08 };

    let mut t = String::from("lisp");
    push_hex(&mut t, "flags", u64::from(flags), def_flags, 2);
    push_hex(&mut t, "nonce", nonce24, 0, 1);
    push_if(&mut t, "iid", iid24, 0);

    let inner = &b[8..];
    let def_v4 = crate::builders::l3::gre::default_gre_inner_packet(0x0800);
    let def_v6 = crate::builders::l3::gre::default_gre_inner_packet(0x86DD);
    let rem = if inner == def_v4.as_slice() || inner == def_v6.as_slice() {
        &[][..]
    } else {
        inner
    };
    Some(sd(Protocol::Lisp, t, rem.to_vec()))
}
