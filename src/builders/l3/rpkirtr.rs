//! RPKI to Router Protocol (RPKI-RTR, RFC 6810 / RFC 8210) Layer 3 wire builder.
//!
//! Serializes an [`RpkirtrSpec`] into an RFC 6810 / RFC 8210 RPKI-RTR PDU encapsulated over TCP
//! destination port `323`. Supports all standard RPKI-RTR PDU types: `serialnotify` (`0`, 12B),
//! `serialquery` (`1`, 12B), `resetquery` (`2`, 8B), `cacheresponse` (`3`, 8B), `ipv4prefix` (`4`,
//! 20B), `ipv6prefix` (`6`, 32B), `endofdata` (`7`, 12B in v0 or 24B in v1 with `refresh`,
//! `retry`, and `expire`), `cachereset` (`8`, 8B), and `errorreport` (`10`, 16+B with `errcode` and
//! `errmsg`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b rpkirtr [serialnotify | serialquery | resetquery | cacheresponse | ipv4prefix | ipv6prefix | endofdata | cachereset | errorreport] [version <0|1>] [sessionid <u16>] [serial <u32>] [announce | withdraw | flags <u8>] [prefix "<cidr>"] [maxlen <u8>] [asn <u32>] [refresh <u32>] [retry <u32>] [expire <u32>] [errcode <u16>] [errmsg "<str>"]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parses an optional IPv4 CIDR string into `(ipv4_octets, prefix_len)` defaulting to `192.0.2.0/24`.
fn parse_v4_prefix(prefix: Option<&str>) -> ([u8; 4], u8) {
    if let Some(raw) = prefix {
        let s = raw.trim();
        let (ip_part, len_opt) = match s.split_once('/') {
            Some((ip, l)) => (ip.trim(), l.trim().parse::<u8>().ok()),
            None => (s, None),
        };
        if let Ok(IpAddr::V4(v4)) = ip_part.parse::<IpAddr>() {
            return (v4.octets(), len_opt.unwrap_or(24).min(32));
        }
    }
    ([192, 0, 2, 0], 24)
}

/// Parses an optional IPv6 CIDR string into `(ipv6_octets, prefix_len)` defaulting to `2001:db8::/32`.
fn parse_v6_prefix(prefix: Option<&str>) -> ([u8; 16], u8) {
    if let Some(raw) = prefix {
        let s = raw.trim();
        let (ip_part, len_opt) = match s.split_once('/') {
            Some((ip, l)) => (ip.trim(), l.trim().parse::<u8>().ok()),
            None => (s, None),
        };
        if let Ok(IpAddr::V6(v6)) = ip_part.parse::<IpAddr>() {
            return (v6.octets(), len_opt.unwrap_or(64).min(128));
        }
    }
    (
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0).octets(),
        32,
    )
}

/// Checks if a prefix string explicitly represents an IPv6 address or CIDR.
fn is_v6_prefix_str(prefix: Option<&str>) -> bool {
    prefix.is_some_and(|raw| {
        let ip_part = raw.trim().split('/').next().unwrap_or("").trim();
        matches!(ip_part.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
    })
}

/// Builds an RFC 6810 / RFC 8210 RPKI-RTR payload and returns `(bytes, 323)` for TCP encapsulation.
pub fn build_rpkirtr_payload(
    ctx: &WireContext,
    spec: &RpkirtrSpec,
    payload: &[u8],
) -> (Vec<u8>, u16) {
    let ver = spec.version.unwrap_or(1);
    let pdu_type = spec.pdu_type.unwrap_or_else(|| {
        if is_v6_prefix_str(spec.prefix) {
            RpkirtrType::Ipv6Prefix
        } else if spec.prefix.is_some()
            || spec.asn.is_some()
            || spec.max_len.is_some()
            || spec.flags.is_some()
        {
            if ctx.src_ip.is_ipv6() && spec.prefix.is_none() {
                RpkirtrType::Ipv6Prefix
            } else {
                RpkirtrType::Ipv4Prefix
            }
        } else if spec.err_code.is_some() || spec.err_msg.is_some() {
            RpkirtrType::ErrorReport
        } else if spec.refresh.is_some() || spec.retry.is_some() || spec.expire.is_some() {
            RpkirtrType::EndOfData
        } else if spec.serial.is_some() {
            RpkirtrType::SerialQuery
        } else if spec.session_id.is_some() {
            RpkirtrType::CacheResponse
        } else {
            RpkirtrType::ResetQuery
        }
    });

    let sid = spec.session_id.unwrap_or(1);
    let serial = spec.serial.unwrap_or(1);
    let flags = spec.flags.unwrap_or(1);
    let asn = spec.asn.unwrap_or(65001);
    let mut rtr = Vec::with_capacity(32 + payload.len());

    match pdu_type {
        RpkirtrType::SerialNotify => {
            rtr.extend_from_slice(&[ver, 0]);
            rtr.extend_from_slice(&sid.to_be_bytes());
            rtr.extend_from_slice(&12_u32.to_be_bytes());
            rtr.extend_from_slice(&serial.to_be_bytes());
        }
        RpkirtrType::SerialQuery => {
            rtr.extend_from_slice(&[ver, 1]);
            rtr.extend_from_slice(&sid.to_be_bytes());
            rtr.extend_from_slice(&12_u32.to_be_bytes());
            rtr.extend_from_slice(&serial.to_be_bytes());
        }
        RpkirtrType::ResetQuery => {
            rtr.extend_from_slice(&[ver, 2, 0, 0]);
            rtr.extend_from_slice(&8_u32.to_be_bytes());
        }
        RpkirtrType::CacheResponse => {
            rtr.extend_from_slice(&[ver, 3]);
            rtr.extend_from_slice(&sid.to_be_bytes());
            rtr.extend_from_slice(&8_u32.to_be_bytes());
        }
        RpkirtrType::Ipv4Prefix => {
            let (addr, plen) = parse_v4_prefix(spec.prefix);
            let max_len = spec.max_len.unwrap_or(plen).max(plen).min(32);
            rtr.extend_from_slice(&[ver, 4, 0, 0]);
            rtr.extend_from_slice(&20_u32.to_be_bytes());
            rtr.extend_from_slice(&[flags, plen, max_len, 0]);
            rtr.extend_from_slice(&addr);
            rtr.extend_from_slice(&asn.to_be_bytes());
            let _ = Ipv4Addr::from(addr);
        }
        RpkirtrType::Ipv6Prefix => {
            let (addr, plen) = parse_v6_prefix(spec.prefix);
            let max_len = spec.max_len.unwrap_or(plen).max(plen).min(128);
            rtr.extend_from_slice(&[ver, 6, 0, 0]);
            rtr.extend_from_slice(&32_u32.to_be_bytes());
            rtr.extend_from_slice(&[flags, plen, max_len, 0]);
            rtr.extend_from_slice(&addr);
            rtr.extend_from_slice(&asn.to_be_bytes());
        }
        RpkirtrType::EndOfData => {
            rtr.extend_from_slice(&[ver, 7]);
            rtr.extend_from_slice(&sid.to_be_bytes());
            if ver == 0 {
                rtr.extend_from_slice(&12_u32.to_be_bytes());
                rtr.extend_from_slice(&serial.to_be_bytes());
            } else {
                rtr.extend_from_slice(&24_u32.to_be_bytes());
                rtr.extend_from_slice(&serial.to_be_bytes());
                rtr.extend_from_slice(&spec.refresh.unwrap_or(3600).to_be_bytes());
                rtr.extend_from_slice(&spec.retry.unwrap_or(600).to_be_bytes());
                rtr.extend_from_slice(&spec.expire.unwrap_or(7200).to_be_bytes());
            }
        }
        RpkirtrType::CacheReset => {
            rtr.extend_from_slice(&[ver, 8, 0, 0]);
            rtr.extend_from_slice(&8_u32.to_be_bytes());
        }
        RpkirtrType::ErrorReport => {
            let err_bytes = spec.err_msg.unwrap_or("").as_bytes();
            let err_len = u32::try_from(err_bytes.len()).unwrap_or(u32::MAX);
            let pdu_len = 16_u32.saturating_add(err_len);
            rtr.extend_from_slice(&[ver, 10]);
            rtr.extend_from_slice(&spec.err_code.unwrap_or(2).to_be_bytes());
            rtr.extend_from_slice(&pdu_len.to_be_bytes());
            rtr.extend_from_slice(&0_u32.to_be_bytes()); // Length of Encapsulated PDU = 0
            rtr.extend_from_slice(&err_len.to_be_bytes());
            rtr.extend_from_slice(err_bytes);
        }
    }

    rtr.extend_from_slice(payload);
    (rtr, 323)
}
