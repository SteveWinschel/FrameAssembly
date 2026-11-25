//! Network Time Protocol v4 (NTPv4) (RFC 5905 / RFC 4330 (SNTP)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Network Time Protocol v4 (NTPv4) frames over UDP port 123.
//! The wire encoder constructs a 48-byte fixed NTP packet header with packed LI / VN / Mode, 8-bit Stratum
//! (including `stratum == 0` Kiss-o'-Death codes such as `"RATE"` or `"DENY"`), 8-bit Poll interval,
//! signed 8-bit Precision (`-128..=127`), deterministic non-zero Root Delay/Dispersion jitter, 32-bit
//! Reference ID, and four 64-bit fixed-point timestamps with deterministic non-zero fractional bits.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ntp [li <u8>] [vn <u8>] [mode <u8>] [stratum <u8>] [poll <u8>] [precision <i8>] [refid <str>] [txtimestamp <u64>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Default deterministic 64-bit NTP transmit timestamp carrying non-zero fractional seconds.
pub(crate) const DEFAULT_NTP_TX_TIMESTAMP: u64 = 0xE500_0000_4000_0001;

/// Builds an RFC 5905 NTPv4 packet payload.
/// Syntax mapping: `ntp [li <u8>] [vn <u8>] [mode <u8>] [stratum <u8>] [poll <u8>] [precision <i8>] [refid <str>] [txtimestamp <u64>]`
#[doc(alias = "NTP")]
#[doc(alias = "SNTP")]
#[doc(alias = "RFC5905")]
#[doc(alias = "STRATUM")]
#[doc(alias = "REFID")]
pub fn build_ntp_payload(
    _ctx: &WireContext,
    spec: &NtpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = [0u8; 48];
    let vn = (spec.vn.unwrap_or(4) & 0x07) << 3;
    let mode = spec.mode.unwrap_or(3) & 0x07; // 3 = Client
    let stratum = spec.stratum.unwrap_or(0);
    let is_kod = stratum == 0 && (mode == 4 || spec.refid.is_some());
    let li = (spec.li.unwrap_or(if is_kod { 3 } else { 0 }) & 0x03) << 6;
    pkt[0] = li | vn | mode;
    pkt[1] = stratum;
    pkt[2] = spec.poll.unwrap_or(4);
    pkt[3] = spec.precision.unwrap_or(-6) as u8;

    // Deterministic non-zero root delay & root dispersion jitter (16.16 fixed-point seconds).
    let (root_delay, root_dispersion): (u32, u32) = if stratum > 0 {
        (0x0000_0280, 0x0000_0420)
    } else {
        (0x0000_0040, 0x0000_0080)
    };
    pkt[4..8].copy_from_slice(&root_delay.to_be_bytes());
    pkt[8..12].copy_from_slice(&root_dispersion.to_be_bytes());

    if let Some(refid) = spec.refid {
        let bytes = refid.as_bytes();
        let len = bytes.len().min(4);
        pkt[12..12 + len].copy_from_slice(&bytes[..len]);
    } else if stratum == 0 && mode == 4 {
        // RFC 5905 §7.4 server Kiss-o'-Death default reference identifier ("RATE").
        pkt[12..16].copy_from_slice(b"RATE");
    }

    // Deterministic non-zero fractional timestamps (Reference / Origin / Receive / Transmit).
    let ref_ts: u64 = if stratum > 0 {
        0xE500_0000_2468_ACF1
    } else {
        0xE500_0000_0102_0304
    };
    pkt[16..24].copy_from_slice(&ref_ts.to_be_bytes());
    if mode == 4 {
        pkt[24..32].copy_from_slice(&0xE500_0000_4000_0001u64.to_be_bytes());
        pkt[32..40].copy_from_slice(&0xE500_0000_8000_1234u64.to_be_bytes());
    }

    let tx_ts = spec.tx_timestamp.unwrap_or(DEFAULT_NTP_TX_TIMESTAMP);
    pkt[40..48].copy_from_slice(&tx_ts.to_be_bytes());

    let mut result = pkt.to_vec();
    if !payload_bytes.is_empty() {
        result.extend_from_slice(payload_bytes);
    }
    result
}
