//! IPv6 Layer 3 header extraction (RFC 8200 / RFC 2474 / RFC 3168) for PCAP-to-`.frasm` decompilation.
//!
//! This module implements fuzz-safe IPv6 header parsing ([`extract_ipv6_l3`]) and `.frasm` Layer 3
//! modifier emission for FrameAssembly's PCAP and PCAPNG decompiler. It validates the 40-byte RFC
//! 8200 fixed IPv6 header and version nibble (`6`), traverses standard IPv6 extension headers
//! (`Hop-by-Hop` with Router Alert option `5`, `Routing`, `Fragment` `44`, and `Destination Options`),
//! and extracts `src_ip`, `dst_ip`, `next_header`, Hop Limit (`ttl`), `dscp`, `ecn`, `flowlabel`,
//! `routeralert`, `ipid`, `mf`, and `fragoffset`.

use alloc::string::String;
use core::net::Ipv6Addr;

use crate::reverse::{be_u16, be_u32, ipv6_at, push_hex, push_if};

/// Decoded RFC 8200 IPv6 Layer 3 header fields, extension header flags, and upper-layer payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6HeaderFields<'a> {
    /// Source IPv6 address (`bytes 8..24`).
    pub(crate) src_ip: Ipv6Addr,
    /// Destination IPv6 address (`bytes 24..40`).
    pub(crate) dst_ip: Ipv6Addr,
    /// Terminal upper-layer IPv6 Next Header protocol number (`byte 6` or final extension header).
    pub(crate) next_header: u8,
    /// IPv6 Hop Limit mapped to canonical `.frasm` `ttl` (`byte 7`).
    pub(crate) ttl: u8,
    /// 6-bit Differentiated Services Code Point (`dscp`, Traffic Class `>> 2`).
    pub(crate) dscp: u8,
    /// 2-bit Explicit Congestion Notification (`ecn`, Traffic Class `& 0x03`).
    pub(crate) ecn: u8,
    /// 20-bit IPv6 Flow Label (`flowlabel`, `bytes 0..4 & 0x000F_FFFF`).
    pub(crate) flowlabel: u32,
    /// RFC 2711 Hop-by-Hop Router Alert option (`routeralert`, NH `0` option `5`).
    pub(crate) router_alert: bool,
    /// RFC 8200 Fragment Header identification (`ipid`, present when NH `44` specifies non-zero ID
    /// or zero-ID initial fragment without `mf`/`fragoffset`).
    pub(crate) ipid: Option<u16>,
    /// RFC 8200 Fragment Header More Fragments bit (`mf`, NH `44`).
    pub(crate) mf: bool,
    /// RFC 8200 Fragment Header 13-bit Fragment Offset in 8-octet units (`fragoffset`, NH `44`).
    pub(crate) frag_offset: u16,
    /// Encapsulated upper-layer payload slice following the IPv6 fixed and extension headers.
    pub(crate) payload: &'a [u8],
}

impl<'a> Ipv6HeaderFields<'a> {
    /// Returns the RFC 8200 IPv6 Hop Limit (`ttl` in `.frasm` syntax).
    pub(crate) const fn hop_limit(&self) -> u8 {
        self.ttl
    }

    /// Appends non-default `.frasm` IPv6 Layer 3 modifiers (`ttl`, `dscp`, `ecn`, `flowlabel`,
    /// `ipid`, `mf`, `fragoffset`, `routeralert`) to the statement token buffer.
    pub(crate) fn append_fasm_modifiers(&self, out: &mut String, default_ttl: u8) {
        push_if(out, "ttl", self.ttl, default_ttl);
        push_if(out, "dscp", self.dscp, 0);
        push_if(out, "ecn", self.ecn, 0);
        push_hex(out, "flowlabel", u64::from(self.flowlabel), 0, 1);
        if let Some(ipid) = self.ipid {
            push_hex(out, "ipid", u64::from(ipid), 0x1234, 4);
        }
        if self.mf {
            out.push_str(" mf");
        }
        push_if(out, "fragoffset", self.frag_offset, 0);
        if self.router_alert {
            out.push_str(" routeralert");
        }
    }

    /// Returns `true` when all IPv6 header fields match a zeroed overlay inner stub.
    pub(crate) fn is_zero_overlay_stub(&self) -> bool {
        if !self.src_ip.is_unspecified()
            || !self.dst_ip.is_unspecified()
            || self.next_header != 0
            || self.hop_limit() != 0
            || self.dscp != 0
            || self.ecn != 0
            || self.flowlabel != 0
            || self.router_alert
            || self.ipid.is_some()
            || self.mf
            || self.frag_offset != 0
        {
            return false;
        }
        let mut mods = String::new();
        self.append_fasm_modifiers(&mut mods, 0);
        mods.is_empty()
    }
}

/// Extracts RFC 8200 IPv6 Layer 3 header fields (`ttl`/hop_limit, `dscp`, `ecn`, `flowlabel`,
/// `router_alert`, `ipid`, `mf`, `frag_offset`), endpoint addresses, upper-layer Next Header
/// number, and payload slice from `b`.
pub(crate) fn extract_ipv6_l3(b: &[u8]) -> Option<Ipv6HeaderFields<'_>> {
    if b.len() < 40 || (b[0] >> 4) != 6 {
        return None;
    }
    let ver_tc_fl = be_u32(b, 0);
    let tc = ((ver_tc_fl >> 20) & 0xFF) as u8;
    let payload_len = be_u16(b, 4) as usize;
    let pkt_end = if 40 + payload_len <= b.len() {
        40 + payload_len
    } else {
        b.len()
    };
    let mut next_header = b[6];
    let mut pos = 40usize;
    let mut router_alert = false;
    let mut ipid: Option<u16> = None;
    let mut mf = false;
    let mut frag_offset = 0u16;
    let mut ext_count = 0usize;

    while pos < pkt_end && ext_count < 16 {
        ext_count += 1;
        if matches!(next_header, 0 | 43 | 60) {
            if pos + 2 > pkt_end {
                break;
            }
            // Preserve SRv6 Routing Header (type 4) for L3 protocol 43 dissection.
            if next_header == 43 && b[..pkt_end].get(pos + 2) == Some(&4) {
                break;
            }
            let ext_len = ((b[pos + 1] as usize) + 1) * 8;
            if pos + ext_len > pkt_end {
                break;
            }
            if next_header == 0 {
                let mut o = pos + 2;
                let ext_end = pos + ext_len;
                while o < ext_end {
                    let kind = b[o];
                    if kind == 0 {
                        o += 1;
                        continue;
                    }
                    if o + 2 > ext_end {
                        break;
                    }
                    let dlen = usize::from(b[o + 1]);
                    let tlv_len = 2usize.saturating_add(dlen);
                    if o + tlv_len > ext_end {
                        break;
                    }
                    if kind == 5 && dlen >= 2 {
                        router_alert = true;
                    }
                    o += tlv_len;
                }
            }
            next_header = b[pos];
            pos += ext_len;
        } else if next_header == 44 {
            if pos + 8 > pkt_end {
                break;
            }
            let off_m = be_u16(b, pos + 2);
            let fo = (off_m >> 3) & 0x1FFF;
            let frag_mf = (off_m & 0x0001) != 0;
            let frag_id = (be_u32(b, pos + 4) & 0xFFFF) as u16;
            frag_offset = fo;
            mf = frag_mf;
            if frag_id != 0 || (!frag_mf && fo == 0) {
                ipid = Some(frag_id);
            }
            next_header = b[pos];
            pos += 8;
        } else {
            break;
        }
    }
    Some(Ipv6HeaderFields {
        src_ip: ipv6_at(b, 8),
        dst_ip: ipv6_at(b, 24),
        next_header,
        ttl: b[7],
        dscp: tc >> 2,
        ecn: tc & 0x03,
        flowlabel: ver_tc_fl & 0x000F_FFFF,
        router_alert,
        ipid,
        mf,
        frag_offset,
        payload: &b[pos..pkt_end],
    })
}
