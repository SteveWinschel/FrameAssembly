//! RPKI to Router Protocol (RPKI-RTR, RFC 6810 / RFC 8210) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 6810 and RFC 8210
//! RPKI-RTR cache synchronization packets carried over TCP port `323`. It validates the common
//! 8-byte RPKI-RTR header (`version` `0` or `1`, `PDU Type`, and 32-bit `Length`), decodes all
//! standard PDU variants (`serialnotify`, `serialquery`, `resetquery`, `cacheresponse`,
//! `ipv4prefix`, `ipv6prefix`, `endofdata`, `cachereset`, `errorreport`), elides RFC defaults,
//! and returns any trailing octets as residual payload.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, be_u32, ipv4_at, ipv6_at, push_hex, push_if, push_str_if, sd,
};

/// Decompiles an RFC 6810 / RFC 8210 `rpkirtr` TCP payload (port `323`) into a [`ProtocolDissection`].
pub(crate) fn dissect_rpkirtr(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 8 || !matches!(b[0], 0 | 1) {
        return None;
    }
    let pdu_len = be_u32(b, 4) as usize;
    if pdu_len < 8 || pdu_len > b.len() {
        return None;
    }
    let pdu = &b[..pdu_len];
    let trailing = &b[pdu_len..];
    let ver = pdu[0];
    let ptype = pdu[1];
    let sid_or_err = be_u16(pdu, 2);

    let mut t = String::from("rpkirtr");
    let mut res = Vec::new();

    match ptype {
        0 | 1 => {
            if pdu.len() < 12 {
                return None;
            }
            t.push_str(if ptype == 0 {
                " serialnotify"
            } else {
                " serialquery"
            });
            push_if(&mut t, "version", ver, 1);
            push_if(&mut t, "sessionid", sid_or_err, 1);
            push_if(&mut t, "serial", be_u32(pdu, 8), 1);
            res.extend_from_slice(&pdu[12..]);
        }
        2 => {
            // Bare `rpkirtr` defaults to Reset Query
            push_if(&mut t, "version", ver, 1);
            res.extend_from_slice(&pdu[8..]);
        }
        3 => {
            t.push_str(" cacheresponse");
            push_if(&mut t, "version", ver, 1);
            push_if(&mut t, "sessionid", sid_or_err, 1);
            res.extend_from_slice(&pdu[8..]);
        }
        4 => {
            if pdu.len() < 20 {
                return None;
            }
            t.push_str(" ipv4prefix");
            push_if(&mut t, "version", ver, 1);
            let flags = pdu[8];
            if flags == 0 {
                t.push_str(" withdraw");
            } else if flags != 1 {
                push_hex(&mut t, "flags", u64::from(flags), 1, 2);
            }
            let plen = pdu[9];
            let max_len = pdu[10];
            let addr = ipv4_at(pdu, 12);
            let asn = be_u32(pdu, 16);
            if addr != Ipv4Addr::new(192, 0, 2, 0) || plen != 24 {
                let _ = write!(t, " prefix \"{addr}/{plen}\"");
            }
            push_if(&mut t, "maxlen", max_len, plen);
            push_if(&mut t, "asn", asn, 65001);
            res.extend_from_slice(&pdu[20..]);
        }
        6 => {
            if pdu.len() < 32 {
                return None;
            }
            t.push_str(" ipv6prefix");
            push_if(&mut t, "version", ver, 1);
            let flags = pdu[8];
            if flags == 0 {
                t.push_str(" withdraw");
            } else if flags != 1 {
                push_hex(&mut t, "flags", u64::from(flags), 1, 2);
            }
            let plen = pdu[9];
            let max_len = pdu[10];
            let addr = ipv6_at(pdu, 12);
            let asn = be_u32(pdu, 28);
            let def_v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
            if addr != def_v6 || plen != 32 {
                let _ = write!(t, " prefix \"{addr}/{plen}\"");
            }
            push_if(&mut t, "maxlen", max_len, plen);
            push_if(&mut t, "asn", asn, 65001);
            res.extend_from_slice(&pdu[32..]);
        }
        7 => {
            t.push_str(" endofdata");
            push_if(&mut t, "version", ver, 1);
            push_if(&mut t, "sessionid", sid_or_err, 1);
            if ver == 0 {
                if pdu.len() < 12 {
                    return None;
                }
                push_if(&mut t, "serial", be_u32(pdu, 8), 1);
                res.extend_from_slice(&pdu[12..]);
            } else {
                if pdu.len() < 24 {
                    return None;
                }
                push_if(&mut t, "serial", be_u32(pdu, 8), 1);
                push_if(&mut t, "refresh", be_u32(pdu, 12), 3600);
                push_if(&mut t, "retry", be_u32(pdu, 16), 600);
                push_if(&mut t, "expire", be_u32(pdu, 20), 7200);
                res.extend_from_slice(&pdu[24..]);
            }
        }
        8 => {
            t.push_str(" cachereset");
            push_if(&mut t, "version", ver, 1);
            res.extend_from_slice(&pdu[8..]);
        }
        10 => {
            if pdu.len() < 16 {
                return None;
            }
            t.push_str(" errorreport");
            push_if(&mut t, "version", ver, 1);
            push_if(&mut t, "errcode", sid_or_err, 2);
            let enc_len = be_u32(pdu, 8) as usize;
            let err_len_off = 12usize.checked_add(enc_len)?;
            let txt_start_opt = err_len_off.checked_add(4);
            if let Some(txt_start) = txt_start_opt
                && txt_start <= pdu.len()
            {
                let txt_len = be_u32(pdu, err_len_off) as usize;
                let txt_end = txt_start.checked_add(txt_len)?;
                if enc_len == 0 && txt_end <= pdu.len() {
                    if let Ok(msg) = core::str::from_utf8(&pdu[txt_start..txt_end]) {
                        push_str_if(&mut t, "errmsg", msg, "");
                        res.extend_from_slice(&pdu[txt_end..]);
                    } else {
                        res.extend_from_slice(&pdu[8..]);
                    }
                } else {
                    res.extend_from_slice(&pdu[8..]);
                }
            } else {
                res.extend_from_slice(&pdu[8..]);
            }
        }
        _ => return None,
    }

    res.extend_from_slice(trailing);
    Some(sd(Protocol::Rpkirtr, t, res))
}
