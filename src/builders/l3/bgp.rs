//! Border Gateway Protocol v4 (BGP-4, RFC 4271 / RFC 4760) Layer 3 wire builder.
//!
//! Serializes a [`BgpSpec`] into an RFC 4271 / RFC 4760 BGP-4 protocol data unit encapsulated over
//! TCP port `179`. All BGP-4 messages begin with a 16-byte all-ones synchronization `Marker`
//! (`0xFF..0xFF`), a 16-bit big-endian total `Length`, and an 8-bit `Type` code:
//! - `open` (`Type = 1`, `29+` bytes): Encodes Version `4`, 16-bit `My Autonomous System` (`asn`,
//!   or `23456` `AS_TRANS` with Capability `65`), `Hold Time`, `BGP Identifier`, and Optional
//!   Parameter `2` Capabilities (including RFC 4760 `AFI=2, SAFI=1` on IPv6 endpoints).
//! - `update` (`Type = 2`, `23+` bytes): Encodes IPv4 `NEXT_HOP` + NLRI or RFC 4760
//!   `MP_REACH_NLRI` (`Attr Type 14`) on IPv6 endpoints.
//! - `notification` (`Type = 3`, `21 + payload` bytes): Encodes Error Code `6` (`Cease`), Subcode `0`.
//! - `keepalive` (`Type = 4`, 19 bytes): Fixed 19-byte header-only heartbeat.
//!
//! Canonical `.frasm` syntax:
//! `a -> b bgp [open | update | notification | keepalive] [asn <u32>] [holdtime <u16>] [bgpid <ipv4>] [prefix "<cidr>"] [nexthop <ip>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;

/// Encodes a CIDR prefix string (e.g., `"10.1.0.0/16"` or `"2001:db8::/32"`) into RFC 4271 / RFC 4760
/// NLRI `[bit_len, octets...]` format, returning `(nlri_bytes, is_ipv6)`.
fn encode_bgp_nlri_with_family(prefix_str: &str, prefer_v6: bool) -> (Vec<u8>, bool) {
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
                return (nlri, false);
            }
            IpAddr::V6(v6) => {
                let plen = len_opt.unwrap_or(64).min(128);
                let byte_len = (plen as usize).div_ceil(8);
                let mut nlri = Vec::with_capacity(1 + byte_len);
                nlri.push(plen);
                nlri.extend_from_slice(&v6.octets()[..byte_len]);
                return (nlri, true);
            }
        }
    }
    if prefer_v6 {
        (alloc::vec![32, 0x20, 0x01, 0x0d, 0xb8], true)
    } else {
        (alloc::vec![24, 10, 0, 0], false)
    }
}

/// Builds an RFC 4271 / RFC 4760 BGP-4 message payload and returns `(bytes, 179)` for TCP encapsulation.
pub fn build_bgp_payload(ctx: &WireContext, spec: &BgpSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let ctx_is_v6 = ctx.src_ip.is_ipv6() || ctx.dst_ip.is_ipv6();
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
            let mut caps = Vec::with_capacity(12);
            if ctx_is_v6 {
                // RFC 4760 §8 Multiprotocol Extensions Capability (Code 1, Len 4, AFI=2 IPv6, Res=0, SAFI=1 Unicast)
                caps.extend_from_slice(&[1, 4, 0, 2, 0, 1]);
            }
            if asn32 > 65535 {
                // RFC 6793 4-Octet AS Capability (Code 65, Len 4)
                caps.extend_from_slice(&[65, 4]);
                caps.extend_from_slice(&asn32.to_be_bytes());
            }
            let asn16: u16 = if asn32 > 65535 { 23456 } else { asn32 as u16 };
            let mut opt_params = Vec::new();
            if !caps.is_empty() {
                opt_params.push(2); // Optional Parameter Type 2: Capabilities
                opt_params.push(caps.len() as u8);
                opt_params.extend_from_slice(&caps);
            }
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
            bgp.extend_from_slice(&opt_params);
            bgp.extend_from_slice(payload);
        }
        BgpType::Update => {
            let decoded_nlri = spec
                .prefix
                .map(|prefix_str| encode_bgp_nlri_with_family(prefix_str, ctx_is_v6));
            let nlri_is_v6 = decoded_nlri.as_ref().is_some_and(|(_, is_v6)| *is_v6);
            let is_mp_v6 = ctx_is_v6 || matches!(spec.nexthop, Some(IpAddr::V6(_))) || nlri_is_v6;

            let mut path_attrs = Vec::new();
            let mut v4_nlri = Vec::new();
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

                if is_mp_v6 {
                    // RFC 4760 §3 Attribute 14: MP_REACH_NLRI (Optional Non-Transitive 0x80, Code 14)
                    let nh_v6 = match spec.nexthop {
                        Some(IpAddr::V6(v6)) => v6.octets(),
                        _ => match ctx.src_ip {
                            IpAddr::V6(v6) => v6.octets(),
                            _ => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        },
                    };
                    let mut mp_val = Vec::with_capacity(32);
                    mp_val.extend_from_slice(&2_u16.to_be_bytes()); // AFI 2: IPv6
                    mp_val.push(1); // SAFI 1: Unicast
                    mp_val.push(16); // Next Hop Network Address Length
                    mp_val.extend_from_slice(&nh_v6);
                    mp_val.push(0); // Reserved
                    if let Some((nlri_bytes, is_v6)) = decoded_nlri {
                        if is_v6 {
                            mp_val.extend_from_slice(&nlri_bytes);
                        } else {
                            v4_nlri = nlri_bytes;
                        }
                    }
                    if mp_val.len() <= usize::from(u8::MAX) {
                        path_attrs.extend_from_slice(&[0x80, 14, mp_val.len() as u8]);
                    } else {
                        path_attrs.extend_from_slice(&[0x90, 14]);
                        path_attrs.extend_from_slice(&(mp_val.len() as u16).to_be_bytes());
                    }
                    path_attrs.extend_from_slice(&mp_val);
                } else {
                    // Attribute 3: IPv4 NEXT_HOP (Transitive 0x40, Code 3, Len 4)
                    let nh_octets = match spec.nexthop.unwrap_or(ctx.src_ip) {
                        IpAddr::V4(v4) => v4.octets(),
                        IpAddr::V6(v6) => {
                            let o = v6.octets();
                            [o[12], o[13], o[14], o[15]]
                        }
                    };
                    path_attrs.extend_from_slice(&[0x40, 0x03, 0x04]);
                    path_attrs.extend_from_slice(&nh_octets);
                    if let Some((nlri_bytes, _)) = decoded_nlri {
                        v4_nlri = nlri_bytes;
                    }
                }

                // Attribute 17: AS4_PATH (Optional Transitive 0xC0, Code 17, Len 6, RFC 6793)
                if let Some(asn) = spec.asn
                    && asn > 65535
                {
                    path_attrs.extend_from_slice(&[0xC0, 0x11, 0x06, 0x02, 0x01]);
                    path_attrs.extend_from_slice(&asn.to_be_bytes());
                }
            } else if let Some((nlri_bytes, _)) = decoded_nlri {
                v4_nlri = nlri_bytes;
            }

            let total_len =
                (23 + path_attrs.len() + v4_nlri.len() + payload.len()).min(usize::from(u16::MAX)) as u16;
            bgp.reserve(total_len as usize);
            bgp.extend_from_slice(&[0xFF; 16]);
            bgp.extend_from_slice(&total_len.to_be_bytes());
            bgp.push(2); // Type 2: UPDATE
            bgp.extend_from_slice(&0_u16.to_be_bytes()); // Withdrawn Routes Len
            bgp.extend_from_slice(&(path_attrs.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
            bgp.extend_from_slice(&path_attrs);
            bgp.extend_from_slice(&v4_nlri);
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

