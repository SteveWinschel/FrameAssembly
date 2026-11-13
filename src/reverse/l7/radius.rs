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
    let mut residual_payload = Vec::new();

    let mut idx = 20usize;
    while idx < payload.len() {
        if idx + 2 > payload.len() {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        }
        let (attr_type, attr_len) = (payload[idx], payload[idx + 1] as usize);
        if attr_len < 2 || idx + attr_len > payload.len() {
            residual_payload.extend_from_slice(&payload[idx..]);
            break;
        }
        let val = &payload[idx + 2..idx + attr_len];
        match attr_type {
            1 if user.is_none() => {
                if let Some(s) = is_printable_ascii_str(val) {
                    user = Some(s.to_string());
                } else {
                    residual_payload.extend_from_slice(&payload[idx..idx + attr_len]);
                }
            }
            4 if val.len() == 4 && nas_ip.is_none() => nas_ip = Some(IpAddr::V4(ipv4_at(val, 0))),
            95 if val.len() == 16 && nas_ip.is_none() => nas_ip = Some(IpAddr::V6(ipv6_at(val, 0))),
            6 if val.len() == 4 && service_type.is_none() => service_type = Some(be_u32(val, 0)),
            8 if val.len() == 4 && framed_ip.is_none() => {
                framed_ip = Some(IpAddr::V4(ipv4_at(val, 0)))
            }
            168 if val.len() == 16 && framed_ip.is_none() => {
                framed_ip = Some(IpAddr::V6(ipv6_at(val, 0)))
            }
            _ => residual_payload.extend_from_slice(&payload[idx..idx + attr_len]),
        }
        idx += attr_len;
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
