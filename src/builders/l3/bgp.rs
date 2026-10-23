//! BGP Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Builds an RFC 4271 BGP payload over TCP port 179.
pub fn build_bgp_payload(ctx: &WireContext, spec: &BgpSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let bgp_type = spec.bgp_type.unwrap_or(BgpType::Keepalive);
    let mut bgp = Vec::new();

    match bgp_type {
        BgpType::Keepalive => {
            bgp.reserve(19);
            bgp.extend_from_slice(&[0xFF; 16]); // Marker
            bgp.extend_from_slice(&19_u16.to_be_bytes()); // Length 19
            bgp.push(4); // Type 4: KEEPALIVE
        }
        BgpType::Open => {
            bgp.reserve(29);
            bgp.extend_from_slice(&[0xFF; 16]);
            bgp.extend_from_slice(&29_u16.to_be_bytes()); // Length 29
            bgp.push(1); // Type 1: OPEN
            bgp.push(4); // Version 4
            let asn = (spec.asn.unwrap_or(65001) & 0xFFFF) as u16;
            bgp.extend_from_slice(&asn.to_be_bytes());
            bgp.extend_from_slice(&spec.holdtime.unwrap_or(180).to_be_bytes());
            let bgpid = match spec.bgpid {
                Some(IpAddr::V4(b)) => b.octets(),
                _ => match ctx.src_ip {
                    IpAddr::V4(s) => s.octets(),
                    _ => [192, 0, 2, 1],
                },
            };
            bgp.extend_from_slice(&bgpid);
            bgp.push(0); // Opt Parm Len
        }
        BgpType::Update => {
            let total_len = (23 + payload.len()) as u16;
            bgp.reserve(total_len as usize);
            bgp.extend_from_slice(&[0xFF; 16]);
            bgp.extend_from_slice(&total_len.to_be_bytes());
            bgp.push(2); // Type 2: UPDATE
            bgp.extend_from_slice(&0_u16.to_be_bytes()); // Withdrawn Routes Len
            bgp.extend_from_slice(&0_u16.to_be_bytes()); // Path Attr Len
            bgp.extend_from_slice(payload);
        }
        BgpType::Notification => {
            let total_len = (21 + payload.len()) as u16;
            bgp.reserve(total_len as usize);
            bgp.extend_from_slice(&[0xFF; 16]);
            bgp.extend_from_slice(&total_len.to_be_bytes());
            bgp.push(3); // Type 3: NOTIFICATION
            bgp.push(6); // Cease
            bgp.push(0);
            bgp.extend_from_slice(payload);
        }
    }

    (bgp, 179)
}
