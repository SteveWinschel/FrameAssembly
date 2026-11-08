//! Precision Time Protocol v2 (`PTP`, IEEE 1588-2008 / RFC 8173) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for IEEE 1588v2 Precision Time Protocol
//! (`PTP`) 44-byte event (`sync`, `delay_req` on UDP port `319`) and general (`follow_up`,
//! `delay_resp`, `announce` on UDP port `320`) messages. It decodes the PTP message type, domain
//! number (`domain`), sequence identifier (`seq_id`), and non-default ASCII `clock_id` strings
//! while preserving trailing TLVs as residual payload.

use alloc::format;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_str_if};

/// Dissects an IEEE 1588v2 `PTP` 44-byte header over UDP ports `319` or `320`.
pub(crate) fn dissect_ptp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 44 || (payload[1] & 0x0F) != 2 {
        return None;
    }
    let msg_kw = match payload[0] & 0x0F {
        0x00 => "sync",
        0x01 => "delay_req",
        0x08 => "follow_up",
        0x09 => "delay_resp",
        0x0B => "announce",
        _ => return None,
    };
    let clock_slice = &payload[20..28];
    let clock_id_str = if clock_slice[3] != 0xFF || clock_slice[4] != 0xFE {
        let len = clock_slice
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |p| p + 1);
        if len > 0 {
            Some(is_printable_ascii_str(&clock_slice[..len])?)
        } else {
            None
        }
    } else {
        None
    };

    let mut tokens = format!("ptp {msg_kw}");
    push_if(&mut tokens, "domain", payload[4], 0);
    push_if(&mut tokens, "seq_id", be_u16(payload, 30), 1);
    if let Some(cid) = clock_id_str {
        push_str_if(&mut tokens, "clock_id", cid, "");
    }

    ok_dissect(Protocol::Ptp, tokens, payload[44..].to_vec())
}
