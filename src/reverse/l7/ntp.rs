//! Network Time Protocol v4 (`ntp`, RFC 5905) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 5905 Network Time Protocol
//! (`ntp`) 48-byte packets carried over UDP port `123`. It extracts leap indicator (`li`), version
//! number (`vn`), association mode (`mode`), clock stratum (`stratum`), poll exponent (`poll`),
//! signed 8-bit precision (`precision`), Kiss-o'-Death and reference ID (`refid`), and 64-bit
//! transmit timestamp (`txtimestamp`), eliding `DEFAULT_NTP_TX_TIMESTAMP` and server KoD defaults.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::builders::l7::ntp::DEFAULT_NTP_TX_TIMESTAMP;
use crate::reverse::{ProtocolDissection, be_u64, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_str_if};

/// Dissects an RFC 5905 `ntp` 48-byte header and optional extension bytes over UDP port `123`.
pub(crate) fn dissect_ntp(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 48 {
        return None;
    }
    let refid_slice = &payload[12..16];
    let trimmed_len = refid_slice
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |p| p + 1);
    let refid_str = if trimmed_len > 0 {
        Some(is_printable_ascii_str(&refid_slice[..trimmed_len])?)
    } else {
        None
    };

    let li = (payload[0] >> 6) & 0x03;
    let vn = (payload[0] >> 3) & 0x07;
    let mode = payload[0] & 0x07;
    let stratum = payload[1];
    let tx_ts = be_u64(payload, 40);

    let is_kod = stratum == 0 && (mode == 4 || refid_str.is_some());
    let default_li = if is_kod { 3u8 } else { 0u8 };

    let mut tokens = String::from("ntp");
    push_if(&mut tokens, "li", li, default_li);
    push_if(&mut tokens, "vn", vn, 4);
    push_if(&mut tokens, "mode", mode, 3);
    push_if(&mut tokens, "stratum", stratum, 0);
    push_if(&mut tokens, "poll", payload[2], 4);
    push_if(&mut tokens, "precision", payload[3] as i8, -6);

    if stratum == 0 && mode == 4 {
        match refid_str {
            None => tokens.push_str(" refid \"\""),
            Some("RATE") => {}
            Some(refid) => push_str_if(&mut tokens, "refid", refid, ""),
        }
    } else if let Some(refid) = refid_str {
        push_str_if(&mut tokens, "refid", refid, "");
    }

    if tx_ts != DEFAULT_NTP_TX_TIMESTAMP {
        let _ = write!(tokens, " txtimestamp 0x{tx_ts:016x}");
    }

    ok_dissect(Protocol::Ntp, tokens, payload[48..].to_vec())
}
