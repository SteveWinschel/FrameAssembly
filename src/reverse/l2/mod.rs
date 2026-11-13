//! Layer 2 data-link framing and protocol PCAP-to-`.frasm` decompilers.
//!
//! This module implements Stage 2 entry point ([`dissect_packet`]) and all eight Layer 2 protocol
//! decompilers for FrameAssembly's PCAP and PCAPNG to `.frasm` reverse decompiler:
//! - Outer tag & label stack peelers and standalone dissectors: [`vlan`] (IEEE 802.1Q `0x8100`),
//!   [`qinq`] (IEEE 802.1ad `0x88A8` / `0x9100`), and [`mpls`] (RFC 3032 `0x8847` / `0x8848`).
//! - Native Layer 2 control and discovery protocols: [`arp`] (RFC 826 / 5227 `0x0806`), [`lldp`]
//!   (IEEE 802.1AB `0x88CC`), [`stp`] (IEEE 802.1D / 802.1w BPDU over LLC `0x424203`), [`lacp`]
//!   (IEEE 802.3ad `0x8809`), and [`eapol`] (IEEE 802.1X `0x888E`).
//! - Delegates IPv4/IPv6 headers and payloads to [`crate::reverse::l3`], [`crate::reverse::l4`],
//!   and [`crate::reverse::l7`].

pub(crate) mod arp;
pub(crate) mod eapol;
pub(crate) mod lacp;
pub(crate) mod lldp;
pub(crate) mod mpls;
pub(crate) mod qinq;
pub(crate) mod stp;
pub(crate) mod vlan;

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;
use etherparse::{LaxSlicedPacket, SlicedPacket};

use crate::ast::{L2Modifiers, L3Modifiers, L4Modifiers, Protocol, TransportProto};
use crate::reverse::container::NormalizedFrame;
use crate::reverse::{DissectedPacket, ProtocolDissection};

#[allow(unused_imports)]
pub(crate) use crate::reverse::{
    be_u16, be_u32, be_u64, bytes_to_hex_lower, escape_fasm_string, format_mac_lower, ipv4_at,
    ipv6_at, le_u32, mac_at, push_hex, push_if, push_ip_if, push_mac_if, push_str_if, sd, sd_tp,
    src_v4_or,
};

/// Dissects a normalized Ethernet II frame across Layers 2, 3, 4, and 7.
pub(crate) fn dissect_packet(frame: NormalizedFrame) -> DissectedPacket {
    let b = &frame.eth_bytes;
    let _ = SlicedPacket::from_ethernet(b)
        .map(|_| true)
        .or_else(|_| LaxSlicedPacket::from_ethernet(b).map(|_| false));

    let dst_mac = if b.len() >= 6 { mac_at(b, 0) } else { [0; 6] };
    let src_mac = if b.len() >= 12 { mac_at(b, 6) } else { [0; 6] };
    let mut et = if b.len() >= 14 { be_u16(b, 12) } else { 0x88B5 };
    let mut off = 14usize.min(b.len());

    let mut l2 = L2Modifiers::default();

    // 1. Peel IEEE 802.1ad QinQ or single 802.1Q VLAN tag.
    let (qp, qd) = vlan::peel_vlan_or_qinq(b, &mut et, &mut off, &mut l2);

    // 2. Peel RFC 3032 MPLS shim header (`0x8847` unicast or `0x8848` multicast).
    mpls::peel_mpls(b, dst_mac, &mut et, &mut off, &mut l2);

    let inner_ethertype = et;
    let l2_payload = b[off..].to_vec();
    let (mut src_ip, mut dst_ip, mut has_ip_header, mut ip_proto) = (None, None, false, None);
    let (mut l3, mut l4) = (L3Modifiers::default(), L4Modifiers::default());
    let (mut seq, mut ack_num, mut win) = (None, None, None);
    let mut l4_payload: Vec<u8> = l2_payload.clone();
    let mut l3_body: Option<&[u8]> = None;

    // 3. Check IPv4 (0x0800) or IPv6 (0x86DD) L3 header.
    if et == 0x0800 && off + 20 <= b.len() && (b[off] >> 4) == 4 {
        let ihl = ((b[off] & 0x0f) as usize) * 4;
        if ihl >= 20 && off + ihl <= b.len() {
            has_ip_header = true;
            let (tos, ipid, ff) = (b[off + 1], be_u16(b, off + 4), be_u16(b, off + 6));
            let (dscp, ecn, fo) = (tos >> 2, tos & 0x03, ff & 0x1FFF);
            src_ip = Some(IpAddr::V4(ipv4_at(b, off + 12)));
            dst_ip = Some(IpAddr::V4(ipv4_at(b, off + 16)));
            ip_proto = Some(b[off + 9]);
            l3 = L3Modifiers {
                ttl: Some(b[off + 8]),
                dscp: (dscp != 0).then_some(dscp),
                ecn: (ecn != 0).then_some(ecn),
                flowlabel: None,
                ipid: (ipid != 0).then_some(ipid),
                df: (ff & 0x4000) != 0,
                mf: (ff & 0x2000) != 0,
                frag_offset: (fo != 0).then_some(fo),
            };
            l3_body = Some(&b[off + ihl..]);
        }
    } else if et == 0x86DD && off + 40 <= b.len() && (b[off] >> 4) == 6 {
        has_ip_header = true;
        let v_tc_fl = be_u32(b, off);
        let tc = ((v_tc_fl >> 20) & 0xFF) as u8;
        let (dscp, ecn, fl) = (tc >> 2, tc & 0x03, v_tc_fl & 0x000F_FFFF);
        src_ip = Some(IpAddr::V6(ipv6_at(b, off + 8)));
        dst_ip = Some(IpAddr::V6(ipv6_at(b, off + 24)));
        ip_proto = Some(b[off + 6]);
        l3 = L3Modifiers {
            ttl: Some(b[off + 7]),
            dscp: (dscp != 0).then_some(dscp),
            ecn: (ecn != 0).then_some(ecn),
            flowlabel: (fl != 0).then_some(fl),
            ipid: None,
            df: false,
            mf: false,
            frag_offset: None,
        };
        l3_body = Some(&b[off + 40..]);
    }

    let dissection = if let (true, Some(proto), Some(ip_body)) = (has_ip_header, ip_proto, l3_body)
    {
        let is_ipv6 = matches!(src_ip, Some(IpAddr::V6(_)));
        l4_payload = ip_body.to_vec();
        match proto {
            6 => {
                if let Some((sp, dp)) = crate::reverse::l4::tcp::dissect_tcp_header(
                    ip_body,
                    &mut l4,
                    &mut seq,
                    &mut ack_num,
                    &mut win,
                    &mut l4_payload,
                ) {
                    if !l4_payload.is_empty() {
                        crate::reverse::l3::dissect_l3_over_l4(
                            true,
                            sp,
                            dp,
                            &l4_payload,
                            is_ipv6,
                            src_ip,
                        )
                        .or_else(|| {
                            crate::reverse::l7::dissect_l7(
                                TransportProto::Tcp,
                                sp,
                                dp,
                                &l4_payload,
                                is_ipv6,
                                dst_ip,
                            )
                        })
                        .unwrap_or_else(|| crate::reverse::l4::tcp::dissect_tcp(&l4_payload))
                    } else {
                        crate::reverse::l4::tcp::dissect_tcp(&l4_payload)
                    }
                } else {
                    crate::reverse::l4::tcp::dissect_tcp(ip_body)
                }
            }
            17 => {
                if let Some((sp, dp)) = crate::reverse::l4::udp::dissect_udp_header(
                    ip_body,
                    &mut l4,
                    &mut l4_payload,
                ) {
                    if dp == 0 && (l2.qinq.is_some() || l2.mpls.is_some() || l2.vlan.is_some()) {
                        build_standalone_l2(&l2, qp, qd, l4_payload.clone())
                    } else if !l4_payload.is_empty() {
                        crate::reverse::l3::dissect_l3_over_l4(
                            false,
                            sp,
                            dp,
                            &l4_payload,
                            is_ipv6,
                            src_ip,
                        )
                        .or_else(|| {
                            crate::reverse::l7::dissect_l7(
                                TransportProto::Udp,
                                sp,
                                dp,
                                &l4_payload,
                                is_ipv6,
                                dst_ip,
                            )
                        })
                        .unwrap_or_else(|| crate::reverse::l4::udp::dissect_udp(&l4_payload))
                    } else {
                        crate::reverse::l4::udp::dissect_udp(&l4_payload)
                    }
                } else {
                    crate::reverse::l4::udp::dissect_udp(ip_body)
                }
            }
            132 => crate::reverse::l4::sctp::dissect_sctp(ip_body, &mut l4, &mut l4_payload),
            _ => crate::reverse::l3::dissect_l3_ip_protocol(
                proto, ip_body, is_ipv6, src_mac, src_ip, dst_ip,
            )
            .unwrap_or_else(|| sd(Protocol::Udp, String::from("udp"), ip_body.to_vec())),
        }
    } else if et == 0x0806 && l2_payload.len() >= 28 {
        arp::dissect_arp(&l2_payload, src_mac, dst_mac, &mut src_ip, &mut dst_ip)
    } else if et == 0x88CC {
        lldp::dissect_lldp(&l2_payload, src_mac)
    } else if et <= 1500 && l2_payload.len() >= 38 && l2_payload[0..3] == [0x42, 0x42, 0x03] {
        stp::dissect_stp(&l2_payload[3..], src_mac)
    } else if et == 0x8809 && l2_payload.len() >= 110 && l2_payload[0..2] == [0x01, 0x01] {
        lacp::dissect_lacp(&l2_payload, src_mac, dst_mac)
    } else if et == 0x888E && l2_payload.len() >= 4 {
        eapol::dissect_eapol(&l2_payload)
    } else {
        build_standalone_l2(&l2, qp, qd, l2_payload.clone())
    };

    DissectedPacket {
        timestamp_ns: frame.timestamp_ns,
        raw_eth_frame: frame.eth_bytes,
        is_l3_only: frame.is_l3_only,
        src_mac,
        dst_mac,
        l2,
        inner_ethertype,
        src_ip,
        dst_ip,
        has_ip_header,
        ip_proto,
        l3,
        l4,
        seq,
        ack_num,
        win,
        l4_payload,
        l2_payload,
        dissection,
    }
}

/// Formats a standalone `qinq`, `mpls`, or `vlan` [`ProtocolDissection`] from `l2`.
pub(crate) fn build_standalone_l2(
    l2: &L2Modifiers,
    qp: u8,
    qd: u8,
    res: Vec<u8>,
) -> ProtocolDissection {
    if let Some(q) = &l2.qinq {
        return qinq::dissect_qinq(q, qp, qd, res);
    }
    if let Some(m) = &l2.mpls {
        return mpls::dissect_mpls(m, res);
    }
    vlan::dissect_vlan(l2.vlan.as_ref(), res)
}
