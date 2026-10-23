//! OSPF Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 2328 / RFC 5340 OSPF Hello payload over IP proto 89.
pub fn build_ospf_payload(ctx: &WireContext, spec: &OspfSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let router_id = match spec.router_id {
        Some(IpAddr::V4(r)) => r.octets(),
        _ => match ctx.src_ip {
            IpAddr::V4(s) => s.octets(),
            _ => [10, 0, 0, 1],
        },
    };

    let total_len = (44 + payload.len()) as u16;
    let mut ospf = Vec::with_capacity(44 + payload.len());
    // 24-byte OSPF Header
    ospf.push(2); // Version 2
    ospf.push(1); // Type 1: Hello
    ospf.extend_from_slice(&total_len.to_be_bytes());
    ospf.extend_from_slice(&router_id);
    ospf.extend_from_slice(&spec.area_id.unwrap_or(0).to_be_bytes());
    ospf.extend_from_slice(&[0, 0]); // Checksum placeholder
    ospf.extend_from_slice(&0_u16.to_be_bytes()); // AuType 0
    ospf.extend_from_slice(&[0u8; 8]); // Authentication 8 bytes

    // 20-byte Hello Body
    ospf.extend_from_slice(&[255, 255, 255, 0]); // Network Mask
    ospf.extend_from_slice(&spec.hello_interval.unwrap_or(10).to_be_bytes());
    ospf.push(0x02); // Options: E-bit
    ospf.push(spec.priority.unwrap_or(1));
    ospf.extend_from_slice(&spec.dead_interval.unwrap_or(40).to_be_bytes());
    ospf.extend_from_slice(&[0u8; 4]); // Designated Router
    ospf.extend_from_slice(&[0u8; 4]); // Backup Designated Router
    ospf.extend_from_slice(payload);

    let cksum = internet_checksum(&[&ospf[..]]);
    ospf[12..14].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = match ctx.dst_ip {
        IpAddr::V6(_) => IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5)),
        _ => IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 5)),
    };

    (ospf, dst_ip, 89)
}
