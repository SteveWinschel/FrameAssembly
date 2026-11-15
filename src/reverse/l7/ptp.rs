//! Precision Time Protocol v2 (`ptp`, IEEE 1588-2008 / RFC 8173) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for IEEE 1588v2 Precision Time Protocol
//! (`ptp`) 44-byte event (`sync`, `delayreq` on UDP port `319`) and general (`followup`,
//! `delayresp`, `announce` on UDP port `320`) messages. It decodes the PTP message type, domain
//! number (`domain`), sequence identifier (`seqid`), and non-default ASCII `clockid` strings
//! while preserving trailing TLVs as residual payload.

use alloc::format;
use alloc::string::{String, ToString};

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, bytes_to_hex_lower, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_str_if};

/// Dissects an IEEE 1588v2 `ptp` message (`44B` Sync/Delay_Req/Follow_Up, `54B` Delay_Resp, `64B` Announce) over UDP ports `319` or `320`.
pub(crate) fn dissect_ptp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 44 || (payload[1] & 0x0F) != 2 {
        return None;
    }
    let (msg_kw, fixed_len) = match payload[0] & 0x0F {
        0x00 => ("sync", 44usize),
        0x01 => ("delayreq", 44usize),
        0x08 => ("followup", 44usize),
        0x09 => ("delayresp", 54usize),
        0x0B => ("announce", 64usize),
        _ => return None,
    };
    if payload.len() < fixed_len || usize::from(be_u16(payload, 2)) != payload.len() {
        return None;
    }
    let clock_slice = &payload[20..28];
    let clock_id_str: Option<String> = if clock_slice[3] != 0xFF || clock_slice[4] != 0xFE {
        let len = clock_slice
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |p| p + 1);
        if len == 0 {
            Some(String::from("0x0000000000000000"))
        } else if clock_slice[len..].iter().all(|&b| b == 0)
            && let Some(s) = is_printable_ascii_str(&clock_slice[..len])
            && !s.starts_with("0x")
            && !s.starts_with("0X")
        {
            Some(s.to_string())
        } else {
            Some(format!("0x{}", bytes_to_hex_lower(clock_slice)))
        }
    } else {
        None
    };

    let mut tokens = format!("ptp {msg_kw}");
    push_if(&mut tokens, "domain", payload[4], 0);
    push_if(&mut tokens, "seqid", be_u16(payload, 30), 1);
    if let Some(cid) = clock_id_str {
        push_str_if(&mut tokens, "clockid", &cid, "");
    }

    ok_dissect(Protocol::Ptp, tokens, payload[fixed_len..].to_vec())
}
