//! Border Gateway Protocol v4 (BGP-4, RFC 4271) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 4271 Border Gateway
//! Protocol (`bgp`) messages carried over TCP port `179`. It verifies the 16-byte all-ones BGP
//! marker and decodes `open` (`asn`, `holdtime`, `bgpid`), `update` (`AS_PATH` `asn`, `NEXT_HOP`
//! `nexthop`, and NLRI `prefix`), `notification`, and `keepalive` PDUs into canonical `.frasm`
//! statements while preserving any trailing bytes as residual payload.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, ipv4_at, push_if, sd, src_v4_or};

/// Decompiles an RFC 4271 `bgp` message over TCP port `179` into a [`ProtocolDissection`].
pub(crate) fn dissect_bgp(b: &[u8], src_ip: Option<IpAddr>) -> Option<ProtocolDissection> {
    if b.len() < 19 || b[0..16] != [0xFF; 16] {
        return None;
    }
    let (body, dv4, mut t, mut res) = (
        &b[19..],
        src_v4_or(src_ip, Ipv4Addr::new(192, 0, 2, 1)),
        String::from("bgp"),
        Vec::new(),
    );
    match b[18] {
        1 if body.len() >= 10 => {
            t.push_str(" open");
            push_if(&mut t, "asn", u32::from(be_u16(body, 1)), 65001);
            push_if(&mut t, "holdtime", be_u16(body, 3), 180);
            push_if(&mut t, "bgpid", ipv4_at(body, 5), dv4);
            res.extend_from_slice(&body[(10 + body[9] as usize).min(body.len())..]);
        }
        2 if body.len() >= 4 => {
            t.push_str(" update");
            let pa_off = 2 + be_u16(body, 0) as usize;
            if pa_off + 2 <= body.len() {
                let pa_end = (pa_off + 2 + be_u16(body, pa_off) as usize).min(body.len());
                let mut p = pa_off + 2;
                while p + 3 <= pa_end {
                    let (at, al) = (body[p + 1], body[p + 2] as usize);
                    p += 3;
                    if at == 2 && al >= 4 && p + al <= pa_end {
                        let _ = write!(t, " asn {}", be_u16(body, p + al - 2));
                    } else if at == 3 && al == 4 && p + 4 <= pa_end {
                        push_if(&mut t, "nexthop", ipv4_at(body, p), dv4);
                    }
                    p = p.saturating_add(al);
                }
                if pa_end < body.len() {
                    let plen = body[pa_end];
                    let blen = (plen as usize).div_ceil(8);
                    if pa_end + 1 + blen <= body.len() && plen <= 32 {
                        let mut oct = [0u8; 4];
                        for (idx, &v) in body[pa_end + 1..pa_end + 1 + blen].iter().enumerate() {
                            if idx < 4 {
                                oct[idx] = v;
                            }
                        }
                        let _ = write!(t, " prefix \"{}/{plen}\"", Ipv4Addr::from(oct));
                        res.extend_from_slice(&body[pa_end + 1 + blen..]);
                    } else {
                        res.extend_from_slice(&body[pa_end..]);
                    }
                }
            }
        }
        3 if body.len() >= 2 => {
            t.push_str(" notification");
            res.extend_from_slice(&body[2..]);
        }
        4 => {
            t.push_str(" keepalive");
            res.extend_from_slice(body);
        }
        _ => return None,
    }
    Some(sd(Protocol::Bgp, t, res))
}
