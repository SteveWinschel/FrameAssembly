//! Layer 3 control, routing, overlay tunneling, redundancy, and security protocol PCAP-to-`.frasm` decompilers.
//!
//! This module implements the Layer 3 protocol decompilation stage for FrameAssembly's PCAP and
//! PCAPNG to `.frasm` decompiler across IPv4/IPv6 Layer 3 headers ([`ip`], [`ipv6`]), unified
//! `ICMPv6` dispatch ([`icmpv6`]), and all twenty supported Layer 3 network protocols:
//! - Direct IP-encapsulated protocols ([`dissect_l3_ip_protocol`]): `icmp` (`1` / `58`), `ndp`
//!   (`58`), `mld` (`58`), `igmp` (`2`), `gre` (`47`), `esp` / `ipsec` (`50`), `ah` (`51`), `ospf`
//!   (`89`), `pim` (`103`), and `vrrp` (`112`).
//! - TCP and UDP transport-encapsulated Layer 3 protocols ([`dissect_l3_over_l4`]): `bgp` (TCP
//!   `179`), `openflow` (TCP `6653` / `6633`), `vxlan` (UDP `4789`), `geneve` (UDP `6081`),
//!   `ikev2` (UDP `500` / `4500`), `wireguard` (UDP `51820`), `rip` (UDP `520` / `521`), `hsrp`
//!   (UDP `1985` / `2029`), and `bfd` (UDP `3784` / `4784`).

pub(crate) mod ah;
pub(crate) mod bfd;
pub(crate) mod bgp;
pub(crate) mod esp;
pub(crate) mod geneve;
pub(crate) mod gre;
pub(crate) mod hsrp;
pub(crate) mod icmp;
pub(crate) mod icmpv6;
pub(crate) mod igmp;
pub(crate) mod ikev2;
pub(crate) mod ip;
pub(crate) mod ipsec;
pub(crate) mod ipv6;
pub(crate) mod mld;
pub(crate) mod ndp;
pub(crate) mod openflow;
pub(crate) mod ospf;
pub(crate) mod pim;
pub(crate) mod rip;
pub(crate) mod vrrp;
pub(crate) mod vxlan;
pub(crate) mod wireguard;

use crate::reverse::ProtocolDissection;
use core::net::IpAddr;

/// Checks if an overlay tunnel inner frame matches FrameAssembly's 42-byte default inner frame.
pub(crate) fn is_default_overlay_inner(inner: &[u8]) -> bool {
    let l2_prefix = [0, 0, 0x5e, 0, 1, 1, 0, 0, 0x5e, 0, 1, 2];
    if inner.len() == 42
        && inner[0..12] == l2_prefix
        && inner[12..14] == [0x08, 0x00]
        && inner[20] == 0
        && inner[24..26] == [0, 0]
        && let Some(v4) = ip::extract_ipv4_l3(&inner[14..])
    {
        v4.is_zero_overlay_stub() && v4.payload == [0u8; 8]
    } else if inner.len() == 62
        && inner[0..12] == l2_prefix
        && inner[12..14] == [0x86, 0xdd]
        && let Some(v6) = ipv6::extract_ipv6_l3(&inner[14..])
    {
        v6.is_zero_overlay_stub() && v6.payload == [0u8; 8]
    } else {
        false
    }
}

/// Dispatches direct IP-encapsulated Layer 3 protocols by IPv4 protocol or IPv6 Next Header number.
pub(crate) fn dissect_l3_ip_protocol(
    ip_proto: u8,
    ip_body: &[u8],
    is_ipv6: bool,
    src_mac: [u8; 6],
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    match ip_proto {
        1 => Some(icmp::dissect_icmp(ip_body, false, src_ip)),
        58 => Some(icmpv6::dissect_icmpv6(ip_body, src_mac, src_ip, dst_ip)),
        2 => Some(igmp::dissect_igmp(ip_body)),
        47 => Some(gre::dissect_gre(ip_body)),
        50 => Some(ipsec::dissect_ipsec(ip_body)),
        51 => Some(ah::dissect_ah(ip_body)),
        89 => Some(ospf::dissect_ospf(ip_body, src_ip)),
        103 => Some(pim::dissect_pim(ip_body, src_ip)),
        112 => Some(vrrp::dissect_vrrp(ip_body, is_ipv6, src_ip)),
        _ => None,
    }
}

/// Dispatches Layer 3 routing, overlay tunnel, VPN, and SDN protocols encapsulated over TCP or UDP.
pub(crate) fn dissect_l3_over_l4(
    is_tcp: bool,
    sp: u16,
    dp: u16,
    p: &[u8],
    _is_ipv6: bool,
    src_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if p.is_empty() {
        return None;
    }
    if is_tcp {
        if (sp == 179 || dp == 179)
            && let Some(d) = bgp::dissect_bgp(p, src_ip)
        {
            return Some(d);
        }
        if (matches!(sp, 6653 | 6633) || matches!(dp, 6653 | 6633))
            && let Some(d) = openflow::dissect_openflow(p)
        {
            return Some(d);
        }
        None
    } else if sp == 4789 || dp == 4789 {
        vxlan::dissect_vxlan(p)
    } else if sp == 6081 || dp == 6081 {
        geneve::dissect_geneve(p)
    } else if matches!(sp, 500 | 4500) || matches!(dp, 500 | 4500) {
        ikev2::dissect_ikev2(p)
    } else if sp == 51820 || dp == 51820 {
        wireguard::dissect_wireguard(p)
    } else if matches!(sp, 520 | 521) || matches!(dp, 520 | 521) {
        rip::dissect_rip(p)
    } else if matches!(sp, 1985 | 2029) || matches!(dp, 1985 | 2029) {
        hsrp::dissect_hsrp(p, src_ip)
    } else if matches!(sp, 3784 | 4784) || matches!(dp, 3784 | 4784) {
        bfd::dissect_bfd(p)
    } else {
        None
    }
}
