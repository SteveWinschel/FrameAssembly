//! Open Shortest Path First (OSPFv2 RFC 2328 / OSPFv3 RFC 5340) Layer 3 wire builder.
//!
//! Serializes an [`OspfSpec`] into an RFC 2328 OSPFv2 or RFC 5340 OSPFv3 packet encapsulated over
//! IP protocol `89` (`0x59`), defaulting unspecified destinations to AllSPFRouters (`224.0.0.5` /
//! `ff02::5`) while preserving explicit unicast or multicast peer addresses. Supports `hello`,
//! `dbd`, `lsr`, `lsu` (synthesizing a deterministic Router-LSA with Fletcher-16 checksum when empty),
//! and `lsack`, computing the IPv4 header-less checksum or OSPFv3 IPv6 pseudo-header checksum.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ospf [hello | dbd | lsr | lsu | lsack] [routerid <ipv4>] [areaid <u32>] [hellointerval <u16>] [deadinterval <u32>] [priority <u8>]`

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Computes the ISO 8473 / RFC 2328 §12.1.7 Fletcher-16 checksum over `lsa[2..]` and writes `lsa[16..18]`.
fn write_fletcher16_lsa_checksum(lsa: &mut [u8]) {
    if lsa.len() < 20 {
        return;
    }
    lsa[16] = 0;
    lsa[17] = 0;
    let mut c0: i32 = 0;
    let mut c1: i32 = 0;
    for &byte in &lsa[2..] {
        c0 = (c0 + i32::from(byte)) % 255;
        c1 = (c1 + c0) % 255;
    }
    let len = (lsa.len() - 2) as i32;
    let mut x = ((len - 15) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    lsa[16] = x as u8;
    lsa[17] = y as u8;
}

/// Builds a deterministic default Router-LSA payload (`# LSAs = 1` + LSA) for `OspfType::Lsu`
/// when no explicit `payload` octets are supplied (`40`B OSPFv2 or `44`B OSPFv3).
pub(crate) fn default_ospf_lsu_body(is_v3: bool, router_id: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(if is_v3 { 44 } else { 40 });
    out.extend_from_slice(&1_u32.to_be_bytes()); // # LSAs = 1
    if is_v3 {
        // 40-byte OSPFv3 Router-LSA (RFC 5340 §A.4.3): 20B LSA header + 4B flags/opts + 16B P2P link
        let mut lsa = [0u8; 40];
        lsa[0..2].copy_from_slice(&1_u16.to_be_bytes()); // LS Age = 1
        lsa[2..4].copy_from_slice(&0x2001_u16.to_be_bytes()); // LS Type: Router-LSA
        lsa[8..12].copy_from_slice(&router_id); // Advertising Router
        lsa[12..16].copy_from_slice(&0x8000_0001_u32.to_be_bytes()); // LS Sequence Number
        lsa[18..20].copy_from_slice(&40_u16.to_be_bytes()); // Length
        lsa[21..24].copy_from_slice(&[0x00, 0x00, 0x13]); // Options: V6 | E | R
        lsa[24] = 1; // Link Type: Point-to-Point
        lsa[26..28].copy_from_slice(&1_u16.to_be_bytes()); // Metric = 1
        lsa[28..32].copy_from_slice(&1_u32.to_be_bytes()); // Interface ID
        lsa[32..36].copy_from_slice(&1_u32.to_be_bytes()); // Neighbor Interface ID
        lsa[36..40].copy_from_slice(&router_id); // Neighbor Router ID
        write_fletcher16_lsa_checksum(&mut lsa);
        out.extend_from_slice(&lsa);
    } else {
        // 36-byte OSPFv2 Router-LSA (RFC 2328 §A.4.2): 20B LSA header + 4B #links + 12B Stub link
        let mut lsa = [0u8; 36];
        lsa[0..2].copy_from_slice(&1_u16.to_be_bytes()); // LS Age = 1
        lsa[2] = 0x02; // Options: E-bit
        lsa[3] = 1; // LS Type: Router-LSA
        lsa[4..8].copy_from_slice(&router_id); // Link State ID
        lsa[8..12].copy_from_slice(&router_id); // Advertising Router
        lsa[12..16].copy_from_slice(&0x8000_0001_u32.to_be_bytes()); // LS Sequence Number
        lsa[18..20].copy_from_slice(&36_u16.to_be_bytes()); // Length
        lsa[22..24].copy_from_slice(&1_u16.to_be_bytes()); // # Links = 1
        lsa[24..28].copy_from_slice(&[router_id[0], router_id[1], router_id[2], 0]); // Stub net
        lsa[28..32].copy_from_slice(&[255, 255, 255, 0]); // Netmask
        lsa[32] = 3; // Link Type 3: Stub Network
        lsa[34..36].copy_from_slice(&1_u16.to_be_bytes()); // Metric = 1
        write_fletcher16_lsa_checksum(&mut lsa);
        out.extend_from_slice(&lsa);
    }
    out
}

/// Builds an RFC 2328 (OSPFv2) or RFC 5340 (OSPFv3 over IPv6) OSPF payload over IP protocol `89`.
pub fn build_ospf_payload(ctx: &WireContext, spec: &OspfSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let router_id = match spec.router_id {
        Some(IpAddr::V4(r)) => r.octets(),
        _ => match ctx.src_ip {
            IpAddr::V4(s) => s.octets(),
            _ => [10, 0, 0, 1],
        },
    };

    let ospf_type = spec.ospf_type.unwrap_or(OspfType::Hello);
    let type_code = match ospf_type {
        OspfType::Hello => 1_u8,
        OspfType::Dbd => 2_u8,
        OspfType::Lsr => 3_u8,
        OspfType::Lsu => 4_u8,
        OspfType::LsAck => 5_u8,
    };

    let mut ospf = Vec::with_capacity(64 + payload.len());
    if let IpAddr::V6(src_v6) = ctx.src_ip {
        let dst_v6 = match ctx.dst_ip {
            IpAddr::V6(d) if !d.is_unspecified() => d,
            _ => core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5),
        };
        // 16-byte OSPFv3 Header (RFC 5340 §A.3.1)
        ospf.push(3); // Version 3
        ospf.push(type_code);
        ospf.extend_from_slice(&0_u16.to_be_bytes()); // Packet Length placeholder
        ospf.extend_from_slice(&router_id);
        ospf.extend_from_slice(&spec.area_id.unwrap_or(0).to_be_bytes());
        ospf.extend_from_slice(&[0, 0]); // Checksum placeholder
        ospf.push(0); // Instance ID
        ospf.push(0); // Reserved

        match ospf_type {
            OspfType::Hello => {
                // 20-byte OSPFv3 Hello Body (RFC 5340 §A.3.2)
                ospf.extend_from_slice(&0_u32.to_be_bytes()); // Interface ID
                ospf.push(spec.priority.unwrap_or(1)); // Rtr Priority
                ospf.extend_from_slice(&[0x00, 0x00, 0x13]); // Options: V6 | E | R
                ospf.extend_from_slice(&spec.hello_interval.unwrap_or(10).to_be_bytes());
                let dead16 = spec.dead_interval.unwrap_or(40).min(u32::from(u16::MAX)) as u16;
                ospf.extend_from_slice(&dead16.to_be_bytes());
                ospf.extend_from_slice(&[0u8; 4]); // Designated Router ID
                ospf.extend_from_slice(&[0u8; 4]); // Backup Designated Router ID
            }
            OspfType::Dbd => {
                // 12-byte OSPFv3 Database Description Body (RFC 5340 §A.3.3)
                ospf.push(0); // Reserved
                ospf.extend_from_slice(&[0x00, 0x00, 0x13]); // Options: V6 | E | R
                ospf.extend_from_slice(&1500_u16.to_be_bytes()); // Interface MTU
                ospf.push(0); // Reserved
                ospf.push(0x07); // Flags: Init | More | Master
                ospf.extend_from_slice(&spec.dead_interval.unwrap_or(1).to_be_bytes());
            }
            OspfType::Lsr => {
                // 12-byte OSPFv3 Link State Request Body (RFC 5340 §A.3.4)
                ospf.extend_from_slice(&0_u16.to_be_bytes()); // Reserved
                ospf.extend_from_slice(&0x2001_u16.to_be_bytes()); // LS Type: Router-LSA
                ospf.extend_from_slice(&0_u32.to_be_bytes()); // Link State ID
                ospf.extend_from_slice(&router_id); // Advertising Router
            }
            OspfType::Lsu => {
                if payload.is_empty() {
                    ospf.extend_from_slice(&default_ospf_lsu_body(true, router_id));
                } else {
                    let count = u32::from(payload.len() >= 20);
                    ospf.extend_from_slice(&count.to_be_bytes());
                }
            }
            OspfType::LsAck => {
                // 20-byte OSPFv3 LSA Header (RFC 5340 §A.4.2)
                let mut lsa = [0u8; 20];
                lsa[0..2].copy_from_slice(&spec.hello_interval.unwrap_or(1).to_be_bytes());
                lsa[2..4].copy_from_slice(&0x2001_u16.to_be_bytes()); // LS Type: Router-LSA
                lsa[8..12].copy_from_slice(&router_id);
                lsa[12..16].copy_from_slice(&0x8000_0001_u32.to_be_bytes());
                lsa[18..20].copy_from_slice(&20_u16.to_be_bytes());
                write_fletcher16_lsa_checksum(&mut lsa);
                ospf.extend_from_slice(&lsa);
            }
        }
        ospf.extend_from_slice(payload);

        let total_len = ospf.len().min(usize::from(u16::MAX)) as u16;
        ospf[2..4].copy_from_slice(&total_len.to_be_bytes());

        let ph_len = u32::try_from(ospf.len()).unwrap_or(u32::MAX).to_be_bytes();
        let next_hdr = [0_u8, 0, 0, 89];
        let cksum = internet_checksum(&[
            &src_v6.octets(),
            &dst_v6.octets(),
            &ph_len,
            &next_hdr,
            &ospf,
        ]);
        ospf[12..14].copy_from_slice(&cksum.to_be_bytes());
        return (ospf, IpAddr::V6(dst_v6), 89);
    }

    // 24-byte OSPFv2 Header (RFC 2328 §A.3.1)
    ospf.push(2); // Version 2
    ospf.push(type_code);
    ospf.extend_from_slice(&0_u16.to_be_bytes()); // Length placeholder
    ospf.extend_from_slice(&router_id);
    ospf.extend_from_slice(&spec.area_id.unwrap_or(0).to_be_bytes());
    ospf.extend_from_slice(&[0, 0]); // Checksum placeholder
    ospf.extend_from_slice(&0_u16.to_be_bytes()); // AuType 0
    ospf.extend_from_slice(&[0u8; 8]); // Authentication 8 bytes

    match ospf_type {
        OspfType::Hello => {
            // 20-byte Hello Body
            ospf.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
            ospf.extend_from_slice(&spec.hello_interval.unwrap_or(10).to_be_bytes());
            ospf.push(0x02); // Options: E-bit
            ospf.push(spec.priority.unwrap_or(1));
            ospf.extend_from_slice(&spec.dead_interval.unwrap_or(40).to_be_bytes());
            ospf.extend_from_slice(&[0u8; 4]); // Designated Router
            ospf.extend_from_slice(&[0u8; 4]); // Backup Designated Router
        }
        OspfType::Dbd => {
            // 8-byte Database Description Body (RFC 2328 §A.3.3)
            ospf.extend_from_slice(&1500_u16.to_be_bytes()); // Interface MTU
            ospf.push(0x02); // Options: E-bit
            ospf.push(0x07); // Flags: Init | More | Master
            ospf.extend_from_slice(&spec.dead_interval.unwrap_or(1).to_be_bytes()); // DD Sequence Number
        }
        OspfType::Lsr => {
            // 12-byte Link State Request Body (RFC 2328 §A.3.4)
            ospf.extend_from_slice(&1_u32.to_be_bytes()); // LS Type: Router-LSA
            ospf.extend_from_slice(&router_id); // Link State ID
            ospf.extend_from_slice(&router_id); // Advertising Router
        }
        OspfType::Lsu => {
            if payload.is_empty() {
                ospf.extend_from_slice(&default_ospf_lsu_body(false, router_id));
            } else {
                let count = u32::from(payload.len() >= 20);
                ospf.extend_from_slice(&count.to_be_bytes());
            }
        }
        OspfType::LsAck => {
            // 20-byte LSA Header Acknowledgment (RFC 2328 §A.3.6)
            let mut lsa = [0u8; 20];
            lsa[0..2].copy_from_slice(&spec.hello_interval.unwrap_or(1).to_be_bytes());
            lsa[2] = 0x02; // Options
            lsa[3] = 1; // LS Type: Router-LSA
            lsa[4..8].copy_from_slice(&router_id);
            lsa[8..12].copy_from_slice(&router_id);
            lsa[12..16].copy_from_slice(&0x8000_0001_u32.to_be_bytes());
            lsa[18..20].copy_from_slice(&20_u16.to_be_bytes());
            write_fletcher16_lsa_checksum(&mut lsa);
            ospf.extend_from_slice(&lsa);
        }
    }
    ospf.extend_from_slice(payload);

    let total_len = ospf.len().min(usize::from(u16::MAX)) as u16;
    ospf[2..4].copy_from_slice(&total_len.to_be_bytes());

    let cksum = internet_checksum(&[&ospf[..]]);
    ospf[12..14].copy_from_slice(&cksum.to_be_bytes());

    let dst_v4 = match ctx.dst_ip {
        IpAddr::V4(d) if !d.is_unspecified() => d,
        _ => core::net::Ipv4Addr::new(224, 0, 0, 5),
    };
    (ospf, IpAddr::V4(dst_v4), 89)
}

