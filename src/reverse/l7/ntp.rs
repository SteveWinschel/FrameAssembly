//! Network Time Protocol v4 (`NTP`, RFC 5905) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 5905 Network Time Protocol
//! (`NTP`) 48-byte packets carried over UDP port `123`. It extracts leap indicator (`li`), version
//! number (`vn`), association mode (`mode`), clock stratum (`stratum`), poll exponent (`poll`),
//! precision (`precision`), ASCII reference identifier (`refid`), and 64-bit transmit timestamp
//! (`tx_timestamp`), preserving any trailing extension fields or MACs as residual payload.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u64, push_if};

use super::{is_printable_ascii_str, ok_dissect, push_str_if};

/// Dissects an RFC 5905 `NTP` 48-byte header and optional extension bytes over UDP port `123`.
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
    let tx_ts = be_u64(payload, 40);

    let mut tokens = String::from("ntp");
    push_if(&mut tokens, "li", (payload[0] >> 6) & 0x03, 0);
    push_if(&mut tokens, "vn", (payload[0] >> 3) & 0x07, 4);
    push_if(&mut tokens, "mode", payload[0] & 0x07, 3);
    push_if(&mut tokens, "stratum", payload[1], 0);
    push_if(&mut tokens, "poll", payload[2], 4);
    push_if(&mut tokens, "precision", payload[3] as i8, -6);
    if let Some(refid) = refid_str {
        push_str_if(&mut tokens, "refid", refid, "");
    }
    if tx_ts != 0xE500_0000_0000_0000 {
        let _ = write!(tokens, " tx_timestamp 0x{tx_ts:016x}");
    }

    ok_dissect(Protocol::Ntp, tokens, payload[48..].to_vec())
}
