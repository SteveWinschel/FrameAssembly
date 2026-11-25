//! Layer 2 data-link framing and protocol PCAP-to-`.frasm` decompilers.
//!
//! This module implements the Stage 2 entry point ([`dissect_packet`]) and all 18 Layer 2 protocol
//! decompilers for FrameAssembly's PCAP and PCAPNG to `.frasm` reverse decompiler:
//! - Outer tag, multi-label stack, 802.3 LLC/SNAP, and IEEE 802.3 FCS detectors: [`vlan`] (IEEE
//!   802.1Q `0x8100` / `0x9100`), [`qinq`] (IEEE 802.1ad `0x88A8`), and [`mpls`] (RFC 3032 multi-label
//!   `0x8847` / `0x8848` stacks and RFC 4448 EoMPLS control words).
//! - Native Layer 2 control, discovery, security, tunneling, and industrial protocols: [`arp`] (RFC
//!   826 / 5227 `0x0806`), [`lldp`] (IEEE 802.1AB `0x88CC`), [`stp`] (IEEE 802.1D / 802.1w BPDU over
//!   LLC `0x424203`), [`lacp`] (IEEE 802.3ad `0x8809`), [`eapol`] (IEEE 802.1X `0x888E`), [`cdp`]
//!   (IEEE 802.3 LLC/SNAP `0x00000C:0x2000`), [`isis`] (ISO/IEC 10589 over LLC `0xFEFE03`),
//!   [`macsec`] (IEEE 802.1AE `0x88E5`), [`pfc`] (IEEE 802.1Qbb `0x8808` opcode `0x0101`),
//!   [`pppoe`] (RFC 2516 `0x8863` / `0x8864`), [`nsh`] (RFC 8300 `0x894F`), [`profinet`] (IEC
//!   61158-6-10 `0x8892` + UDP `34964`), [`goose`] (IEC 61850 `0x88B8`), [`sv`] (IEC 61850-9-2
//!   `0x88BA`), and [`ethercat`] (IEC 61158 `0x88A4` + UDP `34980`).
//! - Guards fragmented IPv4/IPv6 packets (`frag_offset > 0`) against L4 dissection and delegates
//!   unfragmented IPv4/IPv6 headers and payloads to [`crate::reverse::l3`], [`crate::reverse::l4`],
//!   and [`crate::reverse::l7`].

pub(crate) mod arp;
pub(crate) mod cdp;
pub(crate) mod eapol;
pub(crate) mod ethercat;
pub(crate) mod goose;
pub(crate) mod isis;
pub(crate) mod lacp;
pub(crate) mod lldp;
pub(crate) mod macsec;
pub(crate) mod mpls;
pub(crate) mod nsh;
pub(crate) mod pfc;
pub(crate) mod pppoe;
pub(crate) mod profinet;
pub(crate) mod qinq;
pub(crate) mod stp;
pub(crate) mod sv;
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

/// Dissects a normalized Ethernet II / IEEE 802.3 frame across Layers 2, 3, 4, and 7.
pub(crate) fn dissect_packet(frame: NormalizedFrame) -> DissectedPacket {
    let raw = frame.eth_bytes.as_slice();
    let mut b = raw;
    let mut fcs = frame.fcs;
    let mut bad_fcs = frame.bad_fcs;
    if !frame.is_l3_only && !fcs && !bad_fcs && raw.len() >= 18 {
        let split = raw.len() - 4;
        let computed_crc = crate::packet::ieee8023_crc32(&raw[..split]);
        let trailing = le_u32(raw, split);
        if trailing == computed_crc {
            fcs = true;
            b = &raw[..split];
        } else if trailing == (computed_crc ^ 0xFFFF_FFFF) {
            bad_fcs = true;
            b = &raw[..split];
        }
    }

    let _ = SlicedPacket::from_ethernet(b)
        .map(|_| true)
        .or_else(|_| LaxSlicedPacket::from_ethernet(b).map(|_| false));

    let dst_mac = if b.len() >= 6 { mac_at(b, 0) } else { [0; 6] };
    let src_mac = if b.len() >= 12 { mac_at(b, 6) } else { [0; 6] };
    let mut et = if b.len() >= 14 { be_u16(b, 12) } else { 0x88B5 };
    let mut off = 14usize.min(b.len());

    let mut l2 = L2Modifiers {
        fcs,
        bad_fcs,
        ..L2Modifiers::default()
    };

    // 1. Peel stacked IEEE 802.1ad QinQ or 802.1Q VLAN tags.
    let (mut qp, mut qd) = vlan::peel_vlan_or_qinq(b, &mut et, &mut off, &mut l2);

    // 2. Peel RFC 3032 multi-label MPLS shim stack (`0x8847` / `0x8848`) and optional EoMPLS CW.
    mpls::peel_mpls(b, dst_mac, &mut et, &mut off, &mut l2);

    // 3. Handle IEEE 802.3 length framing and RFC 1042 802.2 LLC/SNAP headers.
    let mut l2_end = b.len();
    let mut is_cdp = false;
    let mut is_isis = false;
    if et <= 1500 {
        let end = off.saturating_add(usize::from(et)).min(b.len());
        l2_end = end;
        if end >= off + 8 && b[off..off + 8] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00] {
            is_cdp = true;
            off += 8;
        } else if end >= off + 3 && b[off..off + 3] == [0xFE, 0xFE, 0x03] {
            is_isis = true;
            off += 3;
        } else if end >= off + 8 && b[off..off + 6] == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00] {
            et = be_u16(b, off + 6);
            off += 8;
            if l2.vlan.is_none()
                && l2.qinq.is_none()
                && matches!(et, 0x88A8 | 0x8100 | 0x9100)
            {
                let (nqp, nqd) = vlan::peel_vlan_or_qinq(b, &mut et, &mut off, &mut l2);
                if qp == 0 && qd == 0 {
                    qp = nqp;
                    qd = nqd;
                }
            }
            if l2.mpls_stack.is_empty() && matches!(et, 0x8847 | 0x8848) {
                mpls::peel_mpls(b, dst_mac, &mut et, &mut off, &mut l2);
            }
        }
    }

    let inner_ethertype = et;
    let l2_slice = &b[off.min(l2_end)..l2_end];
    let l2_payload = l2_slice.to_vec();
    let (mut src_ip, mut dst_ip, mut has_ip_header, mut ip_proto) = (None, None, false, None);
    let (mut l3, mut l4) = (L3Modifiers::default(), L4Modifiers::default());
    let (mut seq, mut ack_num, mut win) = (None, None, None);
    let mut l4_payload: Vec<u8> = l2_payload.clone();
    let mut l3_body: Option<&[u8]> = None;

    // 4. Parse IPv4 (0x0800) or IPv6 (0x86DD) L3 header including options and extension chains.
    if et == 0x0800
        && let Some(v4) = crate::reverse::l3::ip::extract_ipv4_l3(l2_slice)
    {
        has_ip_header = true;
        src_ip = Some(IpAddr::V4(v4.src_ip));
        dst_ip = Some(IpAddr::V4(v4.dst_ip));
        ip_proto = Some(v4.protocol);
        l3 = L3Modifiers {
            ttl: Some(v4.ttl),
            dscp: (v4.dscp != 0).then_some(v4.dscp),
            ecn: (v4.ecn != 0).then_some(v4.ecn),
            flowlabel: None,
            ipid: (v4.ipid != 0).then_some(v4.ipid),
            df: v4.df,
            mf: v4.mf,
            frag_offset: (v4.frag_offset != 0).then_some(v4.frag_offset),
            router_alert: v4.router_alert,
            ..L3Modifiers::default()
        };
        l3_body = Some(v4.payload);
    } else if et == 0x86DD
        && let Some(v6) = crate::reverse::l3::ipv6::extract_ipv6_l3(l2_slice)
    {
        has_ip_header = true;
        src_ip = Some(IpAddr::V6(v6.src_ip));
        dst_ip = Some(IpAddr::V6(v6.dst_ip));
        ip_proto = Some(v6.next_header);
        l3 = L3Modifiers {
            ttl: Some(v6.ttl),
            dscp: (v6.dscp != 0).then_some(v6.dscp),
            ecn: (v6.ecn != 0).then_some(v6.ecn),
            flowlabel: (v6.flowlabel != 0).then_some(v6.flowlabel),
            ipid: v6.ipid,
            df: false,
            mf: v6.mf,
            frag_offset: (v6.frag_offset != 0).then_some(v6.frag_offset),
            router_alert: v6.router_alert,
            ..L3Modifiers::default()
        };
        l3_body = Some(v6.payload);
    }

    let dissection = if let (true, Some(proto), Some(ip_body)) = (has_ip_header, ip_proto, l3_body)
    {
        let is_ipv6 = matches!(src_ip, Some(IpAddr::V6(_)));
        l4_payload = ip_body.to_vec();
        if l3.frag_offset.unwrap_or(0) > 0 {
            // Guard non-initial IPv4/IPv6 fragments so L4/L3 headers are never fabricated.
            match proto {
                6 => crate::reverse::l4::tcp::dissect_tcp(ip_body),
                132 => sd(Protocol::Sctp, String::from("sctp"), ip_body.to_vec()),
                _ => crate::reverse::l4::udp::dissect_udp(ip_body),
            }
        } else {
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
                                TransportProto::Tcp,
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
                        if dp == 0
                            && (l2.qinq.is_some()
                                || l2.mpls.is_some()
                                || !l2.mpls_stack.is_empty()
                                || l2.vlan.is_some())
                        {
                            build_standalone_l2(&l2, qp, qd, l4_payload.clone())
                        } else if !l4_payload.is_empty() {
                            crate::reverse::l3::dissect_l3_over_l4(
                                TransportProto::Udp,
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
                132 => crate::reverse::l4::dissect_sctp_packet(
                    ip_body,
                    is_ipv6,
                    src_ip,
                    dst_ip,
                    &mut l4,
                    &mut l4_payload,
                ),
                _ => crate::reverse::l3::dissect_l3_ip_protocol(
                    proto, ip_body, is_ipv6, src_mac, src_ip, dst_ip,
                )
                .unwrap_or_else(|| sd(Protocol::Udp, String::from("udp"), ip_body.to_vec())),
            }
        }
    } else if is_cdp {
        cdp::dissect_cdp(&l2_payload)
    } else if is_isis {
        isis::dissect_isis(&l2_payload, src_mac)
    } else if et == 0x88E5 {
        macsec::dissect_macsec(&l2_payload, src_mac)
    } else if et == 0x8808 && l2_payload.len() >= 2 && l2_payload[0..2] == [0x01, 0x01] {
        pfc::dissect_pfc(&l2_payload)
    } else if matches!(et, 0x8863 | 0x8864) {
        pppoe::dissect_pppoe(&l2_payload, et)
    } else if et == 0x894F
        && let Some(d) = nsh::dissect_nsh(&l2_payload)
    {
        d
    } else if et == 0x8892
        && let Some(d) = profinet::dissect_profinet_l2(&l2_payload)
    {
        d
    } else if et == 0x88B8
        && let Some(d) = goose::dissect_goose(&l2_payload)
    {
        d
    } else if et == 0x88BA
        && let Some(d) = sv::dissect_sv(&l2_payload)
    {
        d
    } else if et == 0x88A4
        && let Some(d) = ethercat::dissect_ethercat(&l2_payload, false)
    {
        d
    } else if et == 0x0806 && l2_payload.len() >= 28 {
        arp::dissect_arp(&l2_payload, src_mac, dst_mac, &mut src_ip, &mut dst_ip)
    } else if et == 0x88CC {
        lldp::dissect_lldp(&l2_payload, src_mac)
    } else if et <= 1500 && l2_payload.len() >= 7 && l2_payload[0..3] == [0x42, 0x42, 0x03] {
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
    if !l2.mpls_stack.is_empty() {
        return mpls::dissect_mpls_stack(&l2.mpls_stack, res);
    }
    if let Some(m) = &l2.mpls {
        return mpls::dissect_mpls(m, res);
    }
    vlan::dissect_vlan(l2.vlan.as_ref(), res)
}
