//! Remote Authentication Dial-In User Service (`radius`, RFC 2865 / RFC 2866) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 2865 Authentication and RFC 2866
//! Accounting `radius` packets carried over UDP ports `1812`, `1813`, `1645`, and `1646`. It
//! decodes the 20-byte RADIUS header (`accessrequest`, `accessaccept`, `accessreject`,
//! `accountingrequest`, `accountingresponse`, `accesschallenge`, and packet `id`) and standard
//! TLV attribute-value pairs (`user`, `nasip`, `servicetype`, `framedip`).

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, ipv4_at, ipv6_at, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_opt, push_str_if};

/// Dissects an RFC 2865 / RFC 2866 `radius` packet (20B header + TLV AVPs).
pub(crate) fn dissect_radius(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 20 {
        return None;
    }
    let rad_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if rad_len != payload.len() {
        return None;
    }
    let code_kw = match payload[0] {
        1 => "accessrequest",
        2 => "accessaccept",
        3 => "accessreject",
        4 => "accountingrequest",
        5 => "accountingresponse",
        11 => "accesschallenge",
        _ => return None,
    };

    let (mut user, mut nas_ip, mut service_type, mut framed_ip) = (None, None, None, None);
    let mut extra_avps: Vec<(u8, &[u8], &[u8])> = Vec::new();
    let mut malformed_tail: Option<&[u8]> = None;

    let mut idx = 20usize;
    while idx < payload.len() {
        let Some(hdr_end) = idx.checked_add(2) else {
            malformed_tail = Some(&payload[idx..]);
            break;
        };
        if hdr_end > payload.len() {
            malformed_tail = Some(&payload[idx..]);
            break;
        }
        let (attr_type, attr_len) = (payload[idx], usize::from(payload[idx + 1]));
        let Some(tlv_end) = idx.checked_add(attr_len) else {
            malformed_tail = Some(&payload[idx..]);
            break;
        };
        if attr_len < 2 || tlv_end > payload.len() {
            malformed_tail = Some(&payload[idx..]);
            break;
        }
        let raw_tlv = &payload[idx..tlv_end];
        let val = &payload[hdr_end..tlv_end];
        match attr_type {
            1 if user.is_none() => {
                if let Some(s) = is_printable_ascii_str(val) {
                    user = Some(s.to_string());
                } else {
                    extra_avps.push((attr_type, raw_tlv, val));
                }
            }
            4 if val.len() == 4 && nas_ip.is_none() && extra_avps.is_empty() => {
                nas_ip = Some(IpAddr::V4(ipv4_at(val, 0)))
            }
            95 if val.len() == 16 && nas_ip.is_none() && extra_avps.is_empty() => {
                nas_ip = Some(IpAddr::V6(ipv6_at(val, 0)))
            }
            6 if val.len() == 4 && service_type.is_none() && extra_avps.is_empty() => {
                service_type = Some(be_u32(val, 0))
            }
            8 if val.len() == 4 && framed_ip.is_none() && extra_avps.is_empty() => {
                framed_ip = Some(IpAddr::V4(ipv4_at(val, 0)))
            }
            168 if val.len() == 16 && framed_ip.is_none() && extra_avps.is_empty() => {
                framed_ip = Some(IpAddr::V6(ipv6_at(val, 0)))
            }
            _ => extra_avps.push((attr_type, raw_tlv, val)),
        }
        idx = tlv_end;
    }

    let mut residual_payload = Vec::new();
    if malformed_tail.is_none() && !extra_avps.is_empty() {
        let all_reply_msg = extra_avps.iter().enumerate().all(|(i, &(t, _, val))| {
            t == 18 && (i + 1 == extra_avps.len() || val.len() == 253)
        });
        if all_reply_msg {
            let mut unwrapped = Vec::new();
            for &(_, _, val) in &extra_avps {
                unwrapped.extend_from_slice(val);
            }
            if !unwrapped.is_empty() && !looks_like_radius_avps(&unwrapped) {
                residual_payload = unwrapped;
            } else {
                for &(_, raw_tlv, _) in &extra_avps {
                    residual_payload.extend_from_slice(raw_tlv);
                }
            }
        } else {
            for &(_, raw_tlv, _) in &extra_avps {
                residual_payload.extend_from_slice(raw_tlv);
            }
        }
    } else {
        for &(_, raw_tlv, _) in &extra_avps {
            residual_payload.extend_from_slice(raw_tlv);
        }
        if let Some(tail) = malformed_tail {
            residual_payload.extend_from_slice(tail);
        }
    }

    let mut tokens = format!("radius {code_kw}");
    push_if(&mut tokens, "id", payload[1], 1);
    if let Some(u) = user {
        push_str_if(&mut tokens, "user", &u, "user");
    }
    push_opt(&mut tokens, "nasip", nas_ip);
    push_opt(&mut tokens, "servicetype", service_type);
    push_opt(&mut tokens, "framedip", framed_ip);

    ok_dissect(Protocol::Radius, tokens, residual_payload)
}

/// Returns `true` when `buf` parses as valid RFC 2865 RADIUS AVP TLVs.
fn looks_like_radius_avps(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let mut pos = 0usize;
    while pos < buf.len() {
        let Some(&attr_type) = buf.get(pos) else {
            return false;
        };
        let Some(&len_u8) = buf.get(pos + 1) else {
            return false;
        };
        let attr_len = usize::from(len_u8);
        if attr_type == 0 || attr_len < 2 {
            return false;
        }
        let Some(next_pos) = pos.checked_add(attr_len) else {
            return false;
        };
        if next_pos > buf.len() {
            return false;
        }
        pos = next_pos;
    }
    pos == buf.len()
}
