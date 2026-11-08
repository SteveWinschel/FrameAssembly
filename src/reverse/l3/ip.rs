//! IPv4 Layer 3 header extraction (RFC 791 / RFC 2474 / RFC 3168) for PCAP-to-`.fasm` decompilation.
//!
//! This module implements fuzz-safe IPv4 header parsing ([`extract_ipv4_l3`]) and `.fasm` Layer 3
//! modifier emission for FrameAssembly's PCAP and PCAPNG decompiler. It validates the IPv4 version
//! nibble (`4`) and Internet Header Length (`IHL >= 20`), clamps the packet slice to Total Length,
//! and extracts `src_ip`, `dst_ip`, encapsulated `protocol`, `ttl`, `dscp`, `ecn`, `ipid`, `df`,
//! `mf`, and `frag_offset` alongside the upper-layer payload slice.

use alloc::string::String;
use core::net::Ipv4Addr;

use crate::reverse::{be_u16, ipv4_at, push_hex, push_if};

/// Decoded RFC 791 IPv4 Layer 3 header fields and upper-layer payload slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv4HeaderFields<'a> {
    /// Source IPv4 address (`bytes 12..16`).
    pub(crate) src_ip: Ipv4Addr,
    /// Destination IPv4 address (`bytes 16..20`).
    pub(crate) dst_ip: Ipv4Addr,
    /// Upper-layer IP protocol number (`byte 9`).
    pub(crate) protocol: u8,
    /// IPv4 Time To Live (`ttl`, `byte 8`).
    pub(crate) ttl: u8,
    /// 6-bit Differentiated Services Code Point (`dscp`, `byte 1 >> 2`).
    pub(crate) dscp: u8,
    /// 2-bit Explicit Congestion Notification (`ecn`, `byte 1 & 0x03`).
    pub(crate) ecn: u8,
    /// 16-bit IPv4 Identification field (`ipid`, `bytes 4..6`).
    pub(crate) ipid: u16,
    /// Don't Fragment flag (`df`, bit 14 of `bytes 6..8`).
    pub(crate) df: bool,
    /// More Fragments flag (`mf`, bit 13 of `bytes 6..8`).
    pub(crate) mf: bool,
    /// 13-bit Fragment Offset field (`frag_offset`, `bytes 6..8 & 0x1FFF`).
    pub(crate) frag_offset: u16,
    /// Encapsulated upper-layer payload slice following the IPv4 header and options.
    pub(crate) payload: &'a [u8],
}

impl<'a> Ipv4HeaderFields<'a> {
    /// Appends non-default `.fasm` IPv4 Layer 3 modifiers (`ttl`, `dscp`, `ecn`, `ipid`, `df`,
    /// `mf`, `frag_offset`) to the statement token buffer.
    pub(crate) fn append_fasm_modifiers(&self, out: &mut String, default_ttl: u8) {
        push_if(out, "ttl", self.ttl, default_ttl);
        push_if(out, "dscp", self.dscp, 0);
        push_if(out, "ecn", self.ecn, 0);
        push_hex(out, "ipid", u64::from(self.ipid), 0x1234, 4);
        if self.df {
            out.push_str(" df");
        }
        if self.mf {
            out.push_str(" mf");
        }
        push_if(out, "frag_offset", self.frag_offset, 0);
    }

    /// Returns `true` when all IPv4 header fields match FrameAssembly's zeroed overlay inner stub.
    pub(crate) fn is_zero_overlay_stub(&self) -> bool {
        if !self.src_ip.is_unspecified()
            || !self.dst_ip.is_unspecified()
            || self.protocol != 0
            || self.ttl != 0
            || self.dscp != 0
            || self.ecn != 0
            || self.ipid != 0
            || self.df
            || self.mf
            || self.frag_offset != 0
        {
            return false;
        }
        let mut mods = String::new();
        self.append_fasm_modifiers(&mut mods, 0);
        mods == " ipid 0x0000"
    }
}

/// Extracts RFC 791 IPv4 Layer 3 header fields (`ttl`, `dscp`, `ecn`, `ipid`, `df`, `mf`,
/// `frag_offset`), endpoint addresses, protocol number, and upper-layer payload from `b`.
pub(crate) fn extract_ipv4_l3(b: &[u8]) -> Option<Ipv4HeaderFields<'_>> {
    if b.len() < 20 || (b[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ihl > b.len() {
        return None;
    }
    let total_len = be_u16(b, 2) as usize;
    let pkt_end = if total_len >= ihl && total_len <= b.len() {
        total_len
    } else {
        b.len()
    };
    let flags_frag = be_u16(b, 6);
    Some(Ipv4HeaderFields {
        src_ip: ipv4_at(b, 12),
        dst_ip: ipv4_at(b, 16),
        protocol: b[9],
        ttl: b[8],
        dscp: b[1] >> 2,
        ecn: b[1] & 0x03,
        ipid: be_u16(b, 4),
        df: (flags_frag & 0x4000) != 0,
        mf: (flags_frag & 0x2000) != 0,
        frag_offset: flags_frag & 0x1FFF,
        payload: &b[ihl..pkt_end],
    })
}
