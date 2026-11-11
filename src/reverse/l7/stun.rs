//! Session Traversal Utilities for NAT (`stun`, RFC 8489) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 8489 `stun` messages carried
//! over UDP ports `3478` and `19302` or identified by the 32-bit magic cookie `0x2112A442`. It
//! validates the 20-byte header and attribute length, decodes `bindingrequest`,
//! `bindingresponse`, and `bindingerror` message types, `txid`, `XOR-MAPPED-ADDRESS` (`0x0020`
//! -> `xormappedaddr` for IPv4 and IPv6), and `SOFTWARE` (`0x8022` -> `software`), and preserves
//! any remaining TLV attributes losslessly in `residual_payload`.

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, sd};

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Dissects an RFC 8489 STUN NAT binding packet on UDP port `3478`.
pub(crate) fn dissect_stun(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 20 || payload.get(4..8)? != [0x21, 0x12, 0xA4, 0x42] {
        return None;
    }
    let msg_type = checked_be_u16(payload, 0)?;
    let attr_len = checked_be_u16(payload, 2)? as usize;
    if 20usize.checked_add(attr_len)? != payload.len() {
        return None;
    }

    let type_kw = match msg_type {
        0x0001 => "bindingrequest",
        0x0101 => "bindingresponse",
        0x0111 => "bindingerror",
        _ => return None,
    };

    let txid = checked_be_u32(payload, 8)?;
    let mut tokens = format!("stun {type_kw}");
    if txid != 0x11223344 {
        let _ = write!(tokens, " txid 0x{txid:08x}");
    }

    let attrs = payload.get(20..20 + attr_len)?;
    let mut pos = 0usize;
    let mut residual = Vec::new();
    let (mut seen_xma, mut seen_sw) = (false, false);

    while pos + 4 <= attrs.len() {
        let atype = checked_be_u16(attrs, pos)?;
        let alen = checked_be_u16(attrs, pos + 2)? as usize;
        let padded_len = (alen + 3) & !3;
        let Some(aval) = attrs.get(pos + 4..pos.checked_add(4)?.checked_add(alen)?) else {
            residual = attrs.get(pos..)?.to_vec();
            break;
        };

        if atype == 0x0020 && !seen_xma && !seen_sw {
            let ip = if alen == 8 && aval.get(1) == Some(&1) {
                IpAddr::V4(Ipv4Addr::from(
                    (checked_be_u32(aval, 4)? ^ 0x2112A442).to_be_bytes(),
                ))
            } else if alen == 20 && aval.get(1) == Some(&2) {
                let mask = payload.get(4..20)?;
                IpAddr::V6(Ipv6Addr::from(core::array::from_fn(|i| {
                    aval[4 + i] ^ mask[i]
                })))
            } else {
                residual = attrs.get(pos..)?.to_vec();
                break;
            };
            let _ = write!(tokens, " xormappedaddr {ip}");
            seen_xma = true;
        } else if atype == 0x8022
            && !seen_sw
            && let Ok(sw_str) = core::str::from_utf8(aval)
            && is_valid_raw_string_body(sw_str)
        {
            push_str_mod(&mut tokens, "software", sw_str);
            seen_sw = true;
        } else {
            residual = attrs.get(pos..)?.to_vec();
            break;
        }
        pos = pos.checked_add(4)?.checked_add(padded_len)?;
    }

    Some(sd(Protocol::Stun, tokens, residual))
}
