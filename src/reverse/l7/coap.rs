//! Constrained Application Protocol (CoAP, RFC 7252) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `coap` v1 messages over UDP and SCTP
//! ports `5683` and `5684`. It decodes message types (`con`, `non`, `ack`, `rst`), `"c.dd"` method
//! and response codes (`code`), 16-bit message IDs (`msgid`), variable-length tokens (`0..=8`
//! bytes, `token`), 4-bit and extended `13`/`14` delta-encoded `Uri-Path` (`11`, `uripath`) and
//! `Content-Format` (`12`, `contentformat`) options, and the `0xFF` payload marker.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Checks whether `s` contains no control characters so it can safely be emitted inside quotes.
fn is_printable_coap_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

/// Decodes a 4-bit CoAP option nibble with RFC 7252 `13` (1B + `13`) and `14` (2B + `269`) extensions.
fn read_coap_opt_ext(nib: usize, payload: &[u8], idx: &mut usize) -> Option<usize> {
    match nib {
        0..=12 => Some(nib),
        13 => {
            let ext = *payload.get(*idx)? as usize;
            *idx += 1;
            Some(13 + ext)
        }
        14 => {
            if *idx + 2 > payload.len() {
                return None;
            }
            let ext = u16::from_be_bytes([payload[*idx], payload[*idx + 1]]) as usize;
            *idx += 2;
            Some(269 + ext)
        }
        _ => None,
    }
}

/// Dissects a `coap` RFC 7252 UDP or SCTP message over ports `5683` or `5684`.
pub(crate) fn dissect_coap(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Udp | TransportProto::Sctp)
        || !(matches!(dst_port, 5683 | 5684) || matches!(src_port, 5683 | 5684))
        || payload.len() < 4
        || (payload[0] >> 6) != 1
    {
        return None;
    }
    let type_val = (payload[0] >> 4) & 0x03;
    let tkl = (payload[0] & 0x0F) as usize;
    if tkl > 8 || payload.len() < 4 + tkl {
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
    if tkl > 0 {
        tokens.push_str(" token 0x");
        for &b in &payload[4..4 + tkl] {
            let _ = write!(tokens, "{b:02x}");
        }
    }

    let mut idx = 4 + tkl;
    let mut opt_num = 0u16;
    let mut path_segs: Vec<&str> = Vec::new();
    let mut content_format: Option<u16> = None;

    while idx < payload.len() {
        if payload[idx] == 0xFF {
            idx += 1;
            if idx == payload.len() {
                return None;
            }
            break;
        }
        let delta_nib = (payload[idx] >> 4) as usize;
        let olen_nib = (payload[idx] & 0x0F) as usize;
        if delta_nib >= 15 || olen_nib >= 15 {
            return None;
        }
        idx += 1;
        let delta = u16::try_from(read_coap_opt_ext(delta_nib, payload, &mut idx)?).ok()?;
        let olen = read_coap_opt_ext(olen_nib, payload, &mut idx)?;
        let val_end = idx.checked_add(olen)?;
        if val_end > payload.len() {
            return None;
        }
        opt_num = opt_num.checked_add(delta)?;
        let oval = &payload[idx..val_end];
        idx = val_end;
        match opt_num {
            11 => {
                let seg = core::str::from_utf8(oval).ok()?;
                if seg.is_empty() || seg.contains('/') || !is_printable_coap_str(seg) {
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
        tokens.push_str(&format!(" uripath \"{}\"", quote_raw_str(&joined)));
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
