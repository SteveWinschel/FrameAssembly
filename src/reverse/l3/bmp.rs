//! BGP Monitoring Protocol (BMP, RFC 7854) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 7854 BGP Monitoring
//! Protocol (`bmp`) messages carried over TCP port `1790`. It validates the 6-byte BMP common
//! header and total length, parses the 42-byte Per-Peer Header (`peertype`, `flags`, `peerip`,
//! `asn`, `bgpid`), decodes `routemon`, `statsreport`, `peerdown`, `peerup`, `initiation`
//! (`sysname`, `sysdesc`), and `termination` (`reason`) messages into canonical `.frasm` tokens,
//! and preserves non-default encapsulated BGP payloads as residual payload.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_hex, push_if, push_str_if, sd,
};

/// Checks if `b` matches a 29-byte default BGP `OPEN` message with `asn` and `bgpid`.
fn is_default_bgp_open(b: &[u8], asn32: u32, bgpid: [u8; 4]) -> bool {
    if b.len() != 29 || b[0..16] != [0xFF; 16] {
        return false;
    }
    let asn16: u16 = if asn32 > 65535 { 23456 } else { asn32 as u16 };
    b[16..24] == [0, 29, 1, 4, (asn16 >> 8) as u8, asn16 as u8, 0, 180]
        && b[24..28] == bgpid
        && b[28] == 0
}

/// Appends Per-Peer Header modifiers and returns `(peer_ip, peer_asn, peer_bgpid)`.
fn decode_pph(pph: &[u8], t: &mut String) -> (IpAddr, u32, [u8; 4]) {
    let peer_type = pph[0];
    let flags = pph[1];
    let is_v6 = (flags & 0x80) != 0;
    push_if(t, "peertype", peer_type, 0);
    let def_flags: u8 = if is_v6 { 0x80 } else { 0x00 };
    push_hex(t, "flags", u64::from(flags), u64::from(def_flags), 2);

    let peer_ip = if is_v6 {
        IpAddr::V6(ipv6_at(pph, 10))
    } else {
        IpAddr::V4(ipv4_at(pph, 22))
    };
    let _ = write!(t, " peerip {peer_ip}");

    let asn = be_u32(pph, 26);
    push_if(t, "asn", asn, 65001);

    let bgpid = ipv4_at(pph, 30);
    let def_bgpid = match peer_ip {
        IpAddr::V4(v4) if !v4.is_unspecified() => v4,
        _ => Ipv4Addr::new(192, 0, 2, 2),
    };
    push_if(t, "bgpid", bgpid, def_bgpid);
    (peer_ip, asn, bgpid.octets())
}

/// Decompiles an RFC 7854 `bmp` TCP payload (port `1790`) into a [`ProtocolDissection`].
pub(crate) fn dissect_bmp(b: &[u8], src_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
    if b.len() < 6 || !matches!(b[0], 1..=4) {
        return None;
    }
    let msg_len = be_u32(b, 1) as usize;
    if msg_len < 6 || msg_len > b.len() {
        return None;
    }
    let pdu = &b[..msg_len];
    let trailing = &b[msg_len..];
    let mtype = pdu[5];
    let mut t = String::from("bmp");
    let mut res = Vec::new();

    match mtype {
        0 => {
            let pph = pdu.get(6..48)?;
            t.push_str(" routemon");
            push_if(&mut t, "version", pdu[0], 3);
            decode_pph(pph, &mut t);
            let body = &pdu[48..];
            let is_default_eor = body.len() == 23
                && body[0..16] == [0xFF; 16]
                && body[16..23] == [0, 23, 2, 0, 0, 0, 0];
            if !is_default_eor {
                res.extend_from_slice(body);
            }
        }
        1 => {
            let pph = pdu.get(6..48)?;
            t.push_str(" statsreport");
            push_if(&mut t, "version", pdu[0], 3);
            decode_pph(pph, &mut t);
            let body = &pdu[48..];
            if body.len() >= 12
                && be_u32(body, 0) == 1
                && be_u16(body, 6) == 4
                && be_u32(body, 8) == 0
            {
                push_if(&mut t, "reason", be_u16(body, 4), 0);
                res.extend_from_slice(&body[12..]);
            } else {
                res.extend_from_slice(body);
            }
        }
        2 => {
            let pph = pdu.get(6..48)?;
            let reason = *pdu.get(48)?;
            t.push_str(" peerdown");
            push_if(&mut t, "version", pdu[0], 3);
            decode_pph(pph, &mut t);
            push_if(&mut t, "reason", u16::from(reason), 3);
            let rest = &pdu[49..];
            let is_default_sub = (reason == 1
                && rest.len() == 21
                && rest[0..16] == [0xFF; 16]
                && rest[16..21] == [0, 21, 3, 6, 0])
                || (reason == 2 && rest == [0, 0]);
            if !is_default_sub {
                res.extend_from_slice(rest);
            }
        }
        3 => {
            let pph = pdu.get(6..48)?;
            let local_slice = pdu.get(48..68)?;
            let _ = local_slice;
            t.push_str(" peerup");
            push_if(&mut t, "version", pdu[0], 3);
            let (_, asn, peer_bgpid) = decode_pph(pph, &mut t);
            let local_bgpid = match src_ip {
                Some(IpAddr::V4(v4)) if !v4.is_unspecified() => v4.octets(),
                _ => [192, 0, 2, 1],
            };
            let opens = &pdu[68..];
            if opens.len() == 58
                && is_default_bgp_open(&opens[0..29], asn, local_bgpid)
                && is_default_bgp_open(&opens[29..58], asn, peer_bgpid)
            {
                // Default OPEN pair elided
            } else {
                res.extend_from_slice(opens);
            }
        }
        4 => {
            push_if(&mut t, "version", pdu[0], 3);
            let mut pos = 6usize;
            let mut sysdesc: Option<&str> = None;
            let mut sysname: Option<&str> = None;
            let mut extra_tlvs = false;
            while pos + 4 <= pdu.len() {
                let ttype = be_u16(pdu, pos);
                let tlen = be_u16(pdu, pos + 2) as usize;
                let Some(val_end) = pos.checked_add(4).and_then(|s| s.checked_add(tlen)) else {
                    break;
                };
                if val_end > pdu.len() {
                    break;
                }
                let val = &pdu[pos + 4..val_end];
                if ttype == 1 && sysdesc.is_none() {
                    if let Ok(s) = core::str::from_utf8(val) {
                        sysdesc = Some(s);
                    } else {
                        extra_tlvs = true;
                        break;
                    }
                } else if ttype == 2 && sysname.is_none() {
                    if let Ok(s) = core::str::from_utf8(val) {
                        sysname = Some(s);
                    } else {
                        extra_tlvs = true;
                        break;
                    }
                } else {
                    extra_tlvs = true;
                    break;
                }
                pos = val_end;
            }
            if extra_tlvs || pos < pdu.len() {
                t.push_str(" initiation");
                if let Some(d) = sysdesc {
                    push_str_if(&mut t, "sysdesc", d, "");
                }
                if let Some(n) = sysname {
                    push_str_if(&mut t, "sysname", n, "");
                }
                res.extend_from_slice(&pdu[pos..]);
            } else if sysdesc.is_none() && sysname == Some("FrameAssembly") {
                // Default bare `bmp` initiation elides `initiation sysname "FrameAssembly"`
            } else {
                t.push_str(" initiation");
                if let Some(d) = sysdesc {
                    push_str_if(&mut t, "sysdesc", d, "");
                }
                if let Some(n) = sysname {
                    push_str_if(&mut t, "sysname", n, "");
                }
            }
        }
        5 => {
            t.push_str(" termination");
            push_if(&mut t, "version", pdu[0], 3);
            if pdu.len() >= 12 && be_u16(pdu, 6) == 1 && be_u16(pdu, 8) == 2 {
                push_if(&mut t, "reason", be_u16(pdu, 10), 0);
                res.extend_from_slice(&pdu[12..]);
            } else {
                res.extend_from_slice(&pdu[6..]);
            }
        }
        _ => return None,
    }

    res.extend_from_slice(trailing);
    Some(sd(Protocol::Bmp, t, res))
}
