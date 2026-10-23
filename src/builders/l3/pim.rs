//! PIM Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::internet_checksum;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 7761 PIM Hello payload over IP proto 103.
pub fn build_pim_payload(ctx: &WireContext, spec: &PimSpec, payload: &[u8]) -> (Vec<u8>, IpAddr, u8) {
    let mut pim = Vec::with_capacity(18 + payload.len());
    // PIM Header (4 bytes): Version 2, Type 0 Hello
    pim.push(0x20);
    pim.push(0); // Reserved
    pim.extend_from_slice(&[0, 0]); // Checksum placeholder

    // Option 1: Holdtime (Type 1, Length 2, Value 105)
    pim.extend_from_slice(&1_u16.to_be_bytes());
    pim.extend_from_slice(&2_u16.to_be_bytes());
    pim.extend_from_slice(&spec.holdtime.unwrap_or(105).to_be_bytes());

    // Option 19: DR Priority (Type 19, Length 4, Value 1)
    pim.extend_from_slice(&19_u16.to_be_bytes());
    pim.extend_from_slice(&4_u16.to_be_bytes());
    pim.extend_from_slice(&spec.dr_priority.unwrap_or(1).to_be_bytes());
    pim.extend_from_slice(payload);

    let cksum = internet_checksum(&[&pim]);
    pim[2..4].copy_from_slice(&cksum.to_be_bytes());

    let dst_ip = match ctx.dst_ip {
        IpAddr::V6(_) => IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0d)),
        _ => IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 13)),
    };

    (pim, dst_ip, 103)
}
