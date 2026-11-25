//! RFC 2516 PPP over Ethernet (`pppoe`, `0x8863` / `0x8864`) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 2516 PPPoE Discovery
//! (`EtherType = 0x8863`: `padi`, `pado`, `padr`, `pads`, `padt`) and PPPoE Session (`EtherType =
//! 0x8864`: `session`) frames. It extracts `sessionid`, Discovery TLV tags (`servicename`,
//! `acname`, `hostuniq`, `accookie`), and Session PPP Protocol IDs (`pppproto`), while preserving
//! non-default PPP payloads and unknown tags cleanly.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::builders::l2::pppoe::{
    DEFAULT_PPPOE_IPCP_STUB, DEFAULT_PPPOE_IPV4_STUB, DEFAULT_PPPOE_LCP_STUB,
};
use crate::reverse::l7::{checked_be_u16, quote_raw_str};
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, push_hex, push_if, sd};

/// Decompiles an RFC 2516 PPPoE Discovery (`0x8863`) or Session (`0x8864`) payload.
pub(crate) fn dissect_pppoe(b: &[u8], ethertype: u16) -> ProtocolDissection {
    if b.len() < 6 || b[0] != 0x11 {
        return sd(Protocol::Pppoe, String::from("pppoe"), b.to_vec());
    }

    let code = b[1];
    let sid = checked_be_u16(b, 2).unwrap_or(0);
    let plen = usize::from(checked_be_u16(b, 4).unwrap_or(0));
    let body_end = 6usize.saturating_add(plen).min(b.len());
    let body = b.get(6..body_end).unwrap_or(&[]);
    let trailing = b.get(body_end..).unwrap_or(&[]);

    if ethertype == 0x8864 || code == 0x00 {
        let mut t = String::from("pppoe session");
        push_if(&mut t, "sessionid", sid, 1);
        if let Some(ppp_proto) = checked_be_u16(body, 0) {
            push_hex(&mut t, "pppproto", u64::from(ppp_proto), 0xC021, 4);
            let ppp_data = body.get(2..).unwrap_or(&[]);
            let is_default_stub = trailing.is_empty()
                && ((ppp_proto == 0xC021 && ppp_data == DEFAULT_PPPOE_LCP_STUB)
                    || (ppp_proto == 0x0021 && ppp_data == DEFAULT_PPPOE_IPV4_STUB)
                    || (ppp_proto == 0x8021 && ppp_data == DEFAULT_PPPOE_IPCP_STUB));
            let residual = if is_default_stub {
                Vec::new()
            } else {
                let mut res = Vec::with_capacity(ppp_data.len() + trailing.len());
                res.extend_from_slice(ppp_data);
                res.extend_from_slice(trailing);
                res
            };
            return sd(Protocol::Pppoe, t, residual);
        }
        let mut res = Vec::with_capacity(body.len() + trailing.len());
        res.extend_from_slice(body);
        res.extend_from_slice(trailing);
        return sd(Protocol::Pppoe, t, res);
    }

    let (stage_kw, def_sid): (&str, u16) = match code {
        0x09 => ("", 0),
        0x07 => ("pado", 0),
        0x19 => ("padr", 0),
        0x65 => ("pads", 1),
        0xA7 => ("padt", 1),
        _ => ("", 0),
    };

    let mut t = String::from("pppoe");
    if !stage_kw.is_empty() {
        let _ = write!(t, " {stage_kw}");
    }
    push_if(&mut t, "sessionid", sid, def_sid);

    let mut pos = 0usize;
    let mut ext = Vec::new();
    while pos + 4 <= body.len() {
        let Some(tag_type) = checked_be_u16(body, pos) else {
            break;
        };
        let Some(tag_len) = checked_be_u16(body, pos + 2) else {
            break;
        };
        let Some(end) = pos
            .checked_add(4)
            .and_then(|v| v.checked_add(usize::from(tag_len)))
        else {
            break;
        };
        let Some(val) = body.get(pos + 4..end) else {
            break;
        };
        let raw_tag = body.get(pos..end).unwrap_or(&[]);
        pos = end;

        match tag_type {
            0x0101 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    if code == 0xA7 || !s.is_empty() {
                        let _ = write!(t, " servicename \"{}\"", quote_raw_str(s));
                    }
                } else {
                    ext.extend_from_slice(raw_tag);
                }
            }
            0x0102 => {
                if let Ok(s) = core::str::from_utf8(val) {
                    if code != 0x07 || s != "ac01" {
                        let _ = write!(t, " acname \"{}\"", quote_raw_str(s));
                    }
                } else {
                    ext.extend_from_slice(raw_tag);
                }
            }
            0x0103 => {
                let _ = write!(t, " hostuniq \"{}\"", bytes_to_hex_lower(val));
            }
            0x0104 => {
                let _ = write!(t, " accookie \"{}\"", bytes_to_hex_lower(val));
            }
            _ => ext.extend_from_slice(raw_tag),
        }
    }

    if let Some(rem) = body.get(pos..) {
        ext.extend_from_slice(rem);
    }
    ext.extend_from_slice(trailing);

    sd(Protocol::Pppoe, t, ext)
}
