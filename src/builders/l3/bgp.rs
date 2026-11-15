//! Border Gateway Protocol v4 (BGP-4, RFC 4271) Layer 3 wire builder.
//!
//! Serializes a [`BgpSpec`] into an RFC 4271 BGP-4 protocol data unit encapsulated over TCP port
//! `179`. All BGP-4 messages begin with a 16-byte all-ones synchronization `Marker` (`0xFF..0xFF`),
//! a 16-bit big-endian total `Length`, and an 8-bit `Type` code:
//! - `open` (`Type = 1`, 29 bytes): Encodes Version `4`, 16-bit `My Autonomous System` (`asn`),
//!   16-bit `Hold Time` (`holdtime`), 32-bit IPv4 `BGP Identifier` (`bgpid`), and `Opt Parm Len = 0`.
//! - `update` (`Type = 2`, `23 + payload` bytes): Encodes Withdrawn Routes Length, Total Path
//!   Attribute Length, and NLRI payload bytes.
//! - `notification` (`Type = 3`, `21 + payload` bytes): Encodes Error Code `6` (`Cease`), Subcode `0`.
//! - `keepalive` (`Type = 4`, 19 bytes): Fixed 19-byte header-only heartbeat.
//!
//! Canonical `.frasm` syntax:
//! `a -> b bgp [open | update | notification | keepalive] [asn <u32>] [holdtime <u16>] [bgpid <ipv4>] [prefix "<cidr>"] [nexthop <ip>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Encodes a CIDR prefix string (e.g., `"10.1.0.0/16"`) into RFC 4271 NLRI `[bit_len, octets...]` format.
fn encode_bgp_nlri(prefix_str: &str) -> Vec<u8> {
    let s = prefix_str.trim();
    let (ip_str, len_opt) = match s.split_once('/') {
        Some((ip, l)) => (ip.trim(), l.trim().parse::<u8>().ok()),
        None => (s, None),
    };
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let plen = len_opt.unwrap_or(24).min(32);
                let byte_len = (plen as usize).div_ceil(8);
                let mut nlri = Vec::with_capacity(1 + byte_len);
                nlri.push(plen);
                nlri.extend_from_slice(&v4.octets()[..byte_len]);
                return nlri;
            }
            IpAddr::V6(v6) => {
                let plen = len_opt.unwrap_or(64).min(128);
                let byte_len = (plen as usize).div_ceil(8);
                let mut nlri = Vec::with_capacity(1 + byte_len);
                nlri.push(plen);
                nlri.extend_from_slice(&v6.octets()[..byte_len]);
                return nlri;
            }
        }
    }
    alloc::vec![24, 10, 0, 0]
}

/// Builds an RFC 4271 BGP-4 message payload and returns `(bytes, 179)` for TCP encapsulation.
pub fn build_bgp_payload(ctx: &WireContext, spec: &BgpSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let bgp_type = spec.bgp_type.unwrap_or(if spec.prefix.is_some() || spec.nexthop.is_some() {
        BgpType::Update
    } else {
        BgpType::Keepalive
    });
    let mut bgp = Vec::new();

    match bgp_type {
        BgpType::Keepalive => {
            bgp.reserve(19);
            bgp.extend_from_slice(&[0xFF; 16]); // Marker
            bgp.extend_from_slice(&19_u16.to_be_bytes()); // Length 19
            bgp.push(4); // Type 4: KEEPALIVE
        }
        BgpType::Open => {
            let asn32 = spec.asn.unwrap_or(65001);
            let cap_bytes = {
                let b = asn32.to_be_bytes();
                [2_u8, 6, 65, 4, b[0], b[1], b[2], b[3]]
            };
            let (asn16, opt_params): (u16, &[u8]) = if asn32 > 65535 {
                (23456_u16, &cap_bytes)
            } else {
                (asn32 as u16, &[])
            };
            let total_len = (29 + opt_params.len() + payload.len()).min(usize::from(u16::MAX)) as u16;
            bgp.reserve(total_len as usize);
            bgp.extend_from_slice(&[0xFF; 16]);
            bgp.extend_from_slice(&total_len.to_be_bytes());
            bgp.push(1); // Type 1: OPEN
            bgp.push(4); // Version 4
            bgp.extend_from_slice(&asn16.to_be_bytes());
            bgp.extend_from_slice(&spec.holdtime.unwrap_or(180).to_be_bytes());
            let bgpid = match spec.bgpid {
                Some(IpAddr::V4(b)) => b.octets(),
                _ => match ctx.src_ip {
                    IpAddr::V4(s) => s.octets(),
                    _ => [192, 0, 2, 1],
                },
            };
            bgp.extend_from_slice(&bgpid);
            bgp.push(opt_params.len() as u8); // Opt Parm Len
            bgp.extend_from_slice(opt_params);
            bgp.extend_from_slice(payload);
        }
        BgpType::Update => {
            let mut path_attrs = Vec::new();
            if spec.nexthop.is_some() || spec.prefix.is_some() || spec.asn.is_some() {
                // Attribute 1: ORIGIN (Transitive 0x40, Code 1, Len 1, IGP = 0)
                path_attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
                // Attribute 2: AS_PATH (Transitive 0x40, Code 2)
                if let Some(asn) = spec.asn {
                    let asn16 = if asn > 65535 { 23456_u16 } else { asn as u16 };
                    path_attrs.extend_from_slice(&[0x40, 0x02, 0x04, 0x02, 0x01]);
                    path_attrs.extend_from_slice(&asn16.to_be_bytes());
                } else {
                    path_attrs.extend_from_slice(&[0x40, 0x02, 0x00]);
                }
                // Attribute 3: NEXT_HOP (Transitive 0x40, Code 3, Len 4)
                let nh_octets = match spec.nexthop.unwrap_or(ctx.src_ip) {
                    IpAddr::V4(v4) => v4.octets(),
                    IpAddr::V6(v6) => {
                        let o = v6.octets();
                        [o[12], o[13], o[14], o[15]]
                    }
                };
                path_attrs.extend_from_slice(&[0x40, 0x03, 0x04]);
                path_attrs.extend_from_slice(&nh_octets);
                // Attribute 17: AS4_PATH (Optional Transitive 0xC0, Code 17, Len 6, RFC 6793)
                if let Some(asn) = spec.asn
                    && asn > 65535
                {
                    path_attrs.extend_from_slice(&[0xC0, 0x11, 0x06, 0x02, 0x01]);
                    path_attrs.extend_from_slice(&asn.to_be_bytes());
                }
            }

            let nlri = if let Some(prefix_str) = spec.prefix {
                encode_bgp_nlri(prefix_str)
            } else {
                Vec::new()
            };

            let total_len =
                (23 + path_attrs.len() + nlri.len() + payload.len()).min(usize::from(u16::MAX)) as u16;
            bgp.reserve(total_len as usize);
            bgp.extend_from_slice(&[0xFF; 16]);
            bgp.extend_from_slice(&total_len.to_be_bytes());
            bgp.push(2); // Type 2: UPDATE
            bgp.extend_from_slice(&0_u16.to_be_bytes()); // Withdrawn Routes Len
            bgp.extend_from_slice(&(path_attrs.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
            bgp.extend_from_slice(&path_attrs);
            bgp.extend_from_slice(&nlri);
            bgp.extend_from_slice(payload);
        }
        BgpType::Notification => {
            let total_len = (21 + payload.len()).min(usize::from(u16::MAX)) as u16;
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

