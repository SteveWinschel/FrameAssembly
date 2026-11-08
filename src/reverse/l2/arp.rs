//! Address Resolution Protocol (ARP, RFC 826 / RFC 5227) Layer 2 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IPv4-over-Ethernet Address
//! Resolution Protocol (`ARP`, EtherType `0x0806`) frames in FrameAssembly. It extracts the 16-bit
//! operation code (`request` vs `reply`), sender and target hardware MAC addresses (`sendermac`,
//! `targetmac`), and sender and target IPv4 protocol addresses (`senderip`, `targetip`), detecting
//! RFC 5227 gratuitous ARP announcements (`gratuitous`) and populating host discovery IP hints.

use alloc::string::String;
use core::fmt::Write as _;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::topology::is_unicast_mac;
use crate::reverse::{ProtocolDissection, be_u16, ipv4_at, mac_at, push_mac_if, sd};

/// Decompiles an RFC 826 / RFC 5227 `ARP` frame (`0x0806`) into a [`ProtocolDissection`].
pub(crate) fn dissect_arp(
    b: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: &mut Option<IpAddr>,
    dst_ip: &mut Option<IpAddr>,
) -> ProtocolDissection {
    let (oper, sha, spa, tha, tpa) = (
        be_u16(b, 6),
        mac_at(b, 8),
        ipv4_at(b, 14),
        mac_at(b, 18),
        ipv4_at(b, 24),
    );
    *src_ip = Some(IpAddr::V4(spa));
    *dst_ip = Some(IpAddr::V4(tpa));
    let is_grat = spa == tpa && !spa.is_unspecified() && tha == [0; 6];
    let mut t = String::from(if oper == 2 {
        "arp reply"
    } else {
        "arp request"
    });
    if is_grat {
        t.push_str(" gratuitous");
    }
    push_mac_if(&mut t, "sendermac", sha, src_mac);
    if spa.is_unspecified() {
        t.push_str(" senderip 0.0.0.0");
    }
    let def_tha = if oper == 2 && !is_grat && is_unicast_mac(dst_mac) {
        dst_mac
    } else {
        [0; 6]
    };
    push_mac_if(&mut t, "targetmac", tha, def_tha);
    if (!is_grat && spa == tpa) || tpa.is_unspecified() || tpa.is_broadcast() || tpa.is_multicast()
    {
        let _ = write!(t, " targetip {tpa}");
    }
    sd(Protocol::Arp, t, b[28..].to_vec())
}
