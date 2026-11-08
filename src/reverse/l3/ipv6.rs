//! IPv6 Layer 3 header extraction (RFC 8200 / RFC 2474 / RFC 3168) for PCAP-to-`.fasm` decompilation.
//!
//! This module implements fuzz-safe IPv6 header parsing ([`extract_ipv6_l3`]) and `.fasm` Layer 3
//! modifier emission for FrameAssembly's PCAP and PCAPNG decompiler. It validates the 40-byte RFC
//! 8200 fixed IPv6 header and version nibble (`6`), traverses standard IPv6 extension headers
//! (`Hop-by-Hop`, `Routing`, `Fragment`, and `Destination Options`), and extracts `src_ip`,
//! `dst_ip`, `next_header`, Hop Limit (`ttl`), `dscp`, `ecn`, and 20-bit `flowlabel`.

use alloc::string::String;
use core::net::Ipv6Addr;

use crate::reverse::{be_u16, be_u32, ipv6_at, push_hex, push_if};

/// Decoded RFC 8200 IPv6 Layer 3 header fields and upper-layer payload slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6HeaderFields<'a> {
    /// Source IPv6 address (`bytes 8..24`).
    pub(crate) src_ip: Ipv6Addr,
    /// Destination IPv6 address (`bytes 24..40`).
    pub(crate) dst_ip: Ipv6Addr,
    /// Terminal upper-layer IPv6 Next Header protocol number (`byte 6` or final extension header).
    pub(crate) next_header: u8,
    /// IPv6 Hop Limit mapped to canonical `.fasm` `ttl` (`byte 7`).
    pub(crate) ttl: u8,
    /// 6-bit Differentiated Services Code Point (`dscp`, Traffic Class `>> 2`).
    pub(crate) dscp: u8,
    /// 2-bit Explicit Congestion Notification (`ecn`, Traffic Class `& 0x03`).
    pub(crate) ecn: u8,
    /// 20-bit IPv6 Flow Label (`flowlabel`, `bytes 0..4 & 0x000F_FFFF`).
    pub(crate) flowlabel: u32,
    /// Encapsulated upper-layer payload slice following the IPv6 fixed and extension headers.
    pub(crate) payload: &'a [u8],
}

impl<'a> Ipv6HeaderFields<'a> {
    /// Returns the RFC 8200 IPv6 Hop Limit (`ttl` in `.fasm` syntax).
    pub(crate) const fn hop_limit(&self) -> u8 {
        self.ttl
    }

    /// Appends non-default `.fasm` IPv6 Layer 3 modifiers (`ttl`, `dscp`, `ecn`, `flowlabel`)
    /// to the statement token buffer.
    pub(crate) fn append_fasm_modifiers(&self, out: &mut String, default_ttl: u8) {
        push_if(out, "ttl", self.ttl, default_ttl);
        push_if(out, "dscp", self.dscp, 0);
        push_if(out, "ecn", self.ecn, 0);
        push_hex(out, "flowlabel", u64::from(self.flowlabel), 0, 1);
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
        {
            return false;
        }
        let mut mods = String::new();
        self.append_fasm_modifiers(&mut mods, 0);
        mods.is_empty()
    }
}

/// Extracts RFC 8200 IPv6 Layer 3 header fields (`ttl`/hop_limit, `dscp`, `ecn`, `flowlabel`),
/// endpoint addresses, upper-layer Next Header number, and payload slice from `b`.
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
    while pos < pkt_end {
        if matches!(next_header, 0 | 43 | 60) {
            if pos + 2 > pkt_end {
                break;
            }
            let ext_len = ((b[pos + 1] as usize) + 1) * 8;
            if pos + ext_len > pkt_end {
                break;
            }
            next_header = b[pos];
            pos += ext_len;
        } else if next_header == 44 {
            if pos + 8 > pkt_end {
                break;
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
        payload: &b[pos..pkt_end],
    })
}
