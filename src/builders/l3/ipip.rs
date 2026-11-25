//! IP-in-IP Encapsulation (RFC 2003 / RFC 2473 / RFC 4213) Layer 3 wire builder.
//!
//! Serializes an [`IpipSpec`] into a complete inner IPv4 (RFC 791, outer IP protocol `4` per RFC
//! 2003) or IPv6 (RFC 8200, outer IP protocol `41` per RFC 4213 / RFC 2473) packet encapsulated
//! directly inside the outer IP header. When no explicit `payload` or `hexpayload` is supplied,
//! synthesizes a deterministic inner ICMP Echo (`1` / `58`), UDP (`17`), or TCP SYN (`6`) probe
//! with valid RFC 1071 IPv4 and pseudo-header checksums so network dissectors decode cleanly.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ipip [v4 | v6 | version <4|6>] [srcip <ip>] [dstip <ip>] [innerttl <u8>] [innerdscp <u8>] [proto <u8>] [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Builds a deterministic default inner transport/control payload for empty-payload `ipip` tunnels.
pub(crate) fn default_ipip_inner_stub(
    inner_v6: bool,
    inner_proto: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Vec<u8> {
    match inner_proto {
        1 if !inner_v6 => {
            let mut icmp = alloc::vec![0x08_u8, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
            let csum = internet_checksum(&[&icmp]);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());
            icmp
        }
        58 if inner_v6 => {
            let mut icmp6 = alloc::vec![0x80_u8, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
            if let (IpAddr::V6(s), IpAddr::V6(d)) = (src_ip, dst_ip) {
                let mut pseudo = [0u8; 40];
                pseudo[0..16].copy_from_slice(&s.octets());
                pseudo[16..32].copy_from_slice(&d.octets());
                pseudo[35] = 8;
                pseudo[39] = 58;
                let csum = internet_checksum(&[&pseudo, &icmp6]);
                icmp6[2..4].copy_from_slice(&csum.to_be_bytes());
            }
            icmp6
        }
        17 => {
            let mut udp = alloc::vec![
                0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
            ];
            let csum = match (src_ip, dst_ip) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    let mut pseudo = [0u8; 12];
                    pseudo[0..4].copy_from_slice(&s.octets());
                    pseudo[4..8].copy_from_slice(&d.octets());
                    pseudo[9] = 17;
                    pseudo[11] = 8;
                    internet_checksum(&[&pseudo, &udp])
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    let mut pseudo = [0u8; 40];
                    pseudo[0..16].copy_from_slice(&s.octets());
                    pseudo[16..32].copy_from_slice(&d.octets());
                    pseudo[35] = 8;
                    pseudo[39] = 17;
                    internet_checksum(&[&pseudo, &udp])
                }
                _ => 0,
            };
            let wire_csum = if csum == 0 { 0xFFFF } else { csum };
            udp[6..8].copy_from_slice(&wire_csum.to_be_bytes());
            udp
        }
        6 => {
            let mut tcp = alloc::vec![
                0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x50,
                0x02, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
            ];
            let csum = match (src_ip, dst_ip) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    let mut pseudo = [0u8; 12];
                    pseudo[0..4].copy_from_slice(&s.octets());
                    pseudo[4..8].copy_from_slice(&d.octets());
                    pseudo[9] = 6;
                    pseudo[11] = 20;
                    internet_checksum(&[&pseudo, &tcp])
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    let mut pseudo = [0u8; 40];
                    pseudo[0..16].copy_from_slice(&s.octets());
                    pseudo[16..32].copy_from_slice(&d.octets());
                    pseudo[35] = 20;
                    pseudo[39] = 6;
                    internet_checksum(&[&pseudo, &tcp])
                }
                _ => 0,
            };
            tcp[16..18].copy_from_slice(&csum.to_be_bytes());
            tcp
        }
        _ => Vec::new(),
    }
}

/// Builds an RFC 2003 / RFC 2473 / RFC 4213 IP-in-IP encapsulated packet and returns `(bytes, outer_proto)`.
pub fn build_ipip_payload(ctx: &WireContext, spec: &IpipSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let inner_v6 = match spec.version {
        Some(IpipVersion::V6) => true,
        Some(IpipVersion::V4) => false,
        None => match (spec.src_ip, spec.dst_ip) {
            (Some(IpAddr::V6(_)), _) | (_, Some(IpAddr::V6(_))) => true,
            (Some(IpAddr::V4(_)), _) | (_, Some(IpAddr::V4(_))) => false,
            _ => ctx.src_ip.is_ipv6(),
        },
    };

    let ttl = spec.ttl.unwrap_or(64);
    let dscp = spec.dscp.unwrap_or(0) & 0x3F;
    let inner_proto = spec.proto.unwrap_or(if payload.is_empty() {
        if inner_v6 { 58 } else { 1 }
    } else {
        253
    });

    if inner_v6 {
        let src_v6 = match spec.src_ip {
            Some(IpAddr::V6(v6)) => v6,
            _ => Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 1),
        };
        let dst_v6 = match spec.dst_ip {
            Some(IpAddr::V6(v6)) => v6,
            _ => Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 2),
        };
        let stub;
        let body = if payload.is_empty() {
            stub = default_ipip_inner_stub(true, inner_proto, IpAddr::V6(src_v6), IpAddr::V6(dst_v6));
            stub.as_slice()
        } else {
            &payload[..payload.len().min(usize::from(u16::MAX))]
        };
        let plen = body.len() as u16;
        let v_tc_fl: u32 = (0x6_u32 << 28) | ((u32::from(dscp) << 2) << 20);
        let mut pkt = Vec::with_capacity(40 + body.len());
        pkt.extend_from_slice(&v_tc_fl.to_be_bytes());
        pkt.extend_from_slice(&plen.to_be_bytes());
        pkt.push(inner_proto);
        pkt.push(ttl);
        pkt.extend_from_slice(&src_v6.octets());
        pkt.extend_from_slice(&dst_v6.octets());
        pkt.extend_from_slice(body);
        (pkt, 41)
    } else {
        let src_v4 = match spec.src_ip {
            Some(IpAddr::V4(v4)) => v4,
            _ => Ipv4Addr::new(198, 51, 100, 1),
        };
        let dst_v4 = match spec.dst_ip {
            Some(IpAddr::V4(v4)) => v4,
            _ => Ipv4Addr::new(198, 51, 100, 2),
        };
        let stub;
        let max_body = usize::from(u16::MAX) - 20;
        let body = if payload.is_empty() {
            stub = default_ipip_inner_stub(false, inner_proto, IpAddr::V4(src_v4), IpAddr::V4(dst_v4));
            &stub[..stub.len().min(max_body)]
        } else {
            &payload[..payload.len().min(max_body)]
        };
        let total_len = (20 + body.len()) as u16;
        let mut pkt = Vec::with_capacity(usize::from(total_len));
        pkt.push(0x45);
        pkt.push(dscp << 2);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&0_u16.to_be_bytes());
        pkt.extend_from_slice(&0_u16.to_be_bytes());
        pkt.push(ttl);
        pkt.push(inner_proto);
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&src_v4.octets());
        pkt.extend_from_slice(&dst_v4.octets());
        let csum = internet_checksum(&[&pkt[..20]]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt.extend_from_slice(body);
        (pkt, 4)
    }
}
