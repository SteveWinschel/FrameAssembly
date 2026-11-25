//! Layer 3 control, routing, overlay tunneling, redundancy, and security protocol PCAP-to-`.frasm` decompilers.
//!
//! This module implements the Layer 3 protocol decompilation stage for FrameAssembly's PCAP and
//! PCAPNG to `.frasm` decompiler across IPv4/IPv6 Layer 3 headers ([`ip`], [`ipv6`]), unified
//! `ICMPv6` dispatch ([`icmpv6`]), and all 31 supported Layer 3 network protocols:
//! - Direct IP-encapsulated protocols ([`dissect_l3_ip_protocol`]): `icmp` (`1` / `58`), `ndp`
//!   (`58`), `mld` (`58`), `igmp` (`2`), `ipip` (`4` / `41`), `srv6` (`43` type `4`), `rsvp` (`46`),
//!   `erspan` (`47` GRE `0x88BE` / `0x22EB`), `gre` (`47`), `esp` / `ipsec` (`50`), `ah` (`51`),
//!   `ospf` (`89`), `pim` (`103`), `vrrp` (`112`), and `l2tp` (`115`).
//! - Transport-encapsulated Layer 3 protocols ([`dissect_l3_over_l4`]): `bgp` (TCP `179`),
//!   `openflow` (TCP `6653` / `6633`), `bmp` (TCP `1790`), `rpkirtr` (TCP `323`), `ldp` (TCP/UDP
//!   `646`), `vxlan` (UDP `4789`), `geneve` (UDP `6081`), `ikev2` (UDP `500` / `4500`), `wireguard`
//!   (UDP `51820`), `rip` (UDP `520` / `521`), `hsrp` (UDP `1985` / `2029`), `bfd` (UDP `3784` /
//!   `4784`), `l2tp` (UDP `1701`), `lisp` (UDP `4341` / `4342`), `glbp` (UDP `3222`), `gtpu` (UDP
//!   `2152`), plus L2-over-UDP tunnels (`profinet` `34964`, `ethercat` `34980`).

pub(crate) mod ah;
pub(crate) mod bfd;
pub(crate) mod bgp;
pub(crate) mod bmp;
pub(crate) mod erspan;
pub(crate) mod esp;
pub(crate) mod geneve;
pub(crate) mod glbp;
pub(crate) mod gre;
pub(crate) mod gtpu;
pub(crate) mod hsrp;
pub(crate) mod icmp;
pub(crate) mod icmpv6;
pub(crate) mod igmp;
pub(crate) mod ikev2;
pub(crate) mod ip;
pub(crate) mod ipip;
pub(crate) mod ipsec;
pub(crate) mod ipv6;
pub(crate) mod l2tp;
pub(crate) mod ldp;
pub(crate) mod lisp;
pub(crate) mod mld;
pub(crate) mod ndp;
pub(crate) mod openflow;
pub(crate) mod ospf;
pub(crate) mod pim;
pub(crate) mod rip;
pub(crate) mod rpkirtr;
pub(crate) mod rsvp;
pub(crate) mod srv6;
pub(crate) mod vrrp;
pub(crate) mod vxlan;
pub(crate) mod wireguard;

use crate::ast::TransportProto;
use crate::reverse::ProtocolDissection;
use core::net::IpAddr;

/// Checks if an overlay tunnel inner frame matches FrameAssembly's 42-byte default inner frame.
pub(crate) fn is_default_overlay_inner(inner: &[u8]) -> bool {
    if inner == crate::builders::l3::gre::default_overlay_inner_ethernet().as_slice() {
        return true;
    }
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
        1 => Some(icmp::dissect_icmp(ip_body, false, src_ip, dst_ip)),
        58 => Some(icmpv6::dissect_icmpv6(ip_body, src_mac, src_ip, dst_ip)),
        2 => Some(igmp::dissect_igmp(ip_body)),
        4 | 41 => Some(ipip::dissect_ipip(ip_body, ip_proto, is_ipv6)),
        43 => srv6::dissect_srv6(ip_body, src_ip, dst_ip),
        46 => Some(rsvp::dissect_rsvp(ip_body, src_ip, dst_ip)),
        47 => erspan::dissect_erspan(ip_body).or_else(|| Some(gre::dissect_gre(ip_body))),
        50 => Some(ipsec::dissect_ipsec(ip_body)),
        51 => Some(ah::dissect_ah(ip_body)),
        89 => Some(ospf::dissect_ospf(ip_body, src_ip)),
        103 => Some(pim::dissect_pim(ip_body, src_ip, dst_ip)),
        112 => Some(vrrp::dissect_vrrp(ip_body, is_ipv6, src_ip)),
        115 => l2tp::dissect_l2tp(ip_body, true),
        _ => None,
    }
}

/// Dispatches Layer 3 routing, overlay tunnel, VPN, and SDN protocols encapsulated over TCP, UDP, or SCTP.
pub(crate) fn dissect_l3_over_l4(
    transport: TransportProto,
    sp: u16,
    dp: u16,
    p: &[u8],
    is_ipv6: bool,
    src_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if p.is_empty() {
        return None;
    }
    match transport {
        TransportProto::Tcp => {
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
            if (sp == 1790 || dp == 1790)
                && let Some(d) = bmp::dissect_bmp(p, src_ip)
            {
                return Some(d);
            }
            if (sp == 323 || dp == 323)
                && let Some(d) = rpkirtr::dissect_rpkirtr(p)
            {
                return Some(d);
            }
            if (sp == 646 || dp == 646)
                && let Some(d) = ldp::dissect_ldp(TransportProto::Tcp, is_ipv6, p, src_ip)
            {
                return Some(d);
            }
            None
        }
        TransportProto::Udp => {
            if (sp == 4789 || dp == 4789)
                && let Some(d) = vxlan::dissect_vxlan(p)
            {
                return Some(d);
            }
            if (sp == 6081 || dp == 6081)
                && let Some(d) = geneve::dissect_geneve(p)
            {
                return Some(d);
            }
            if (matches!(sp, 500 | 4500) || matches!(dp, 500 | 4500))
                && let Some(d) = ikev2::dissect_ikev2(p)
            {
                return Some(d);
            }
            if (sp == 51820 || dp == 51820)
                && let Some(d) = wireguard::dissect_wireguard(p)
            {
                return Some(d);
            }
            if (matches!(sp, 520 | 521) || matches!(dp, 520 | 521))
                && let Some(d) = rip::dissect_rip(p, is_ipv6)
            {
                return Some(d);
            }
            if (matches!(sp, 1985 | 2029) || matches!(dp, 1985 | 2029))
                && let Some(d) = hsrp::dissect_hsrp(p, src_ip)
            {
                return Some(d);
            }
            if (matches!(sp, 3784 | 4784) || matches!(dp, 3784 | 4784))
                && let Some(d) = bfd::dissect_bfd(p)
            {
                return Some(d);
            }
            if (sp == 646 || dp == 646)
                && let Some(d) = ldp::dissect_ldp(TransportProto::Udp, is_ipv6, p, src_ip)
            {
                return Some(d);
            }
            if (sp == 1701 || dp == 1701)
                && let Some(d) = l2tp::dissect_l2tp(p, false)
            {
                return Some(d);
            }
            if (matches!(sp, 4341 | 4342) || matches!(dp, 4341 | 4342))
                && let Some(d) = lisp::dissect_lisp(p, sp, dp, src_ip)
            {
                return Some(d);
            }
            if (sp == 3222 || dp == 3222)
                && let Some(d) = glbp::dissect_glbp(p, src_ip)
            {
                return Some(d);
            }
            if (sp == 2152 || dp == 2152)
                && let Some(d) = gtpu::dissect_gtpu(p, src_ip)
            {
                return Some(d);
            }
            if (sp == 34964 || dp == 34964)
                && let Some(d) = crate::reverse::l2::profinet::dissect_profinet_udp(p)
            {
                return Some(d);
            }
            if (sp == 34980 || dp == 34980)
                && let Some(d) = crate::reverse::l2::ethercat::dissect_ethercat(p, true)
            {
                return Some(d);
            }
            None
        }
        TransportProto::Sctp => {
            if (sp == 646 || dp == 646)
                && let Some(d) = ldp::dissect_ldp(TransportProto::Sctp, is_ipv6, p, src_ip)
            {
                return Some(d);
            }
            None
        }
    }
}
