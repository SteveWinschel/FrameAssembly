//! Constrained Application Protocol (CoAP, RFC 7252) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `coap` v1 messages over UDP ports
//! `5683` and `5684`. It decodes message types (`con`, `non`, `ack`, `rst`), `"c.dd"` method and
//! response codes (`code`), 16-bit message IDs (`msgid`), 4-byte tokens (`token`), delta-encoded
//! `Uri-Path` (`11`, `uripath`) and `Content-Format` (`12`, `contentformat`) options, and the
//! `0xFF` payload marker.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Dissects a `coap` RFC 7252 UDP message over ports `5683` or `5684`.
pub(crate) fn dissect_coap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Udp)
        || !(matches!(dst_port, 5683 | 5684) || matches!(src_port, 5683 | 5684))
        || payload.len() < 4
        || (payload[0] >> 6) != 1
    {
        return None;
    }
    let type_val = (payload[0] >> 4) & 0x03;
    let tkl = (payload[0] & 0x0F) as usize;
    if tkl != 0 && tkl != 4 || payload.len() < 4 + tkl {
        return None;
    }
    let code_byte = payload[1];
    let c = code_byte >> 5;
    let d = code_byte & 0x1F;
    let msgid = u16::from_be_bytes([payload[2], payload[3]]);

    let mut tokens = String::from("coap");
    match type_val {
        0 => {}
        1 => tokens.push_str(" non"),
        2 => tokens.push_str(" ack"),
        3 => tokens.push_str(" rst"),
        _ => return None,
    }
    if !(c == 0 && d == 1) {
        tokens.push_str(&format!(" code \"{c}.{d:02}\""));
    }
    if msgid != 0x1234 {
        tokens.push_str(&format!(" msgid 0x{msgid:04x}"));
    }
    if tkl == 4 {
        let tok = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        tokens.push_str(&format!(" token 0x{tok:08x}"));
    }

    let mut idx = 4 + tkl;
    let mut opt_num = 0u16;
    let mut path_segs: Vec<&str> = Vec::new();
    let mut content_format: Option<u16> = None;

    while idx < payload.len() {
        if payload[idx] == 0xFF {
            idx += 1;
            break;
        }
        let delta = (payload[idx] >> 4) as u16;
        let olen_nib = (payload[idx] & 0x0F) as usize;
        if delta >= 13 || olen_nib >= 14 {
            return None;
        }
        idx += 1;
        let olen = if olen_nib == 13 {
            if idx >= payload.len() {
                return None;
            }
            let ext = payload[idx] as usize;
            idx += 1;
            13 + ext
        } else {
            olen_nib
        };
        if idx + olen > payload.len() {
            return None;
        }
        opt_num += delta;
        let oval = &payload[idx..idx + olen];
        idx += olen;
        match opt_num {
            11 => {
                let seg = core::str::from_utf8(oval).ok()?;
                if !is_valid_raw_str(seg) {
                    return None;
                }
                path_segs.push(seg);
            }
            12 => {
                let cf = match olen {
                    0 => 0u16,
                    1 => oval[0] as u16,
                    2 => u16::from_be_bytes([oval[0], oval[1]]),
                    _ => return None,
                };
                content_format = Some(cf);
            }
            _ => return None,
        }
    }

    if !path_segs.is_empty() {
        let joined = path_segs.join("/");
        tokens.push_str(&format!(" uripath \"{joined}\""));
    }
    if let Some(cf) = content_format {
        tokens.push_str(&format!(" contentformat {cf}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Coap,
        tokens,
        residual_payload: payload[idx..].to_vec(),
        explicit_transport: None,
    })
}
