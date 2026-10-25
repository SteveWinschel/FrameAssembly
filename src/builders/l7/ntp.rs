//! Network Time Protocol v4 (NTPv4) (RFC 5905 / RFC 4330 (SNTP)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Network Time Protocol v4 (NTPv4) frames over UDP port 123.
//! The wire encoder constructs a 48-byte fixed NTP packet header starting with packed 8-bit LI (2 bits) / VN (3 bits) / Mode (3 bits) byte, 8-bit Stratum, 8-bit Poll interval (log2 seconds), signed 8-bit Precision, 32-bit Root Delay, 32-bit Root Dispersion, 32-bit Reference ID (ASCII kiss-code or IPv4), and four 64-bit fixed-point timestamps (Reference, Origin, Receive, Transmit). When optional fields in [`NtpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b NTP [LI <u8>] [VN <u8>] [MODE <u8>] [STRATUM <u8>] [POLL <u8>] [PRECISION <i8>] [REFID <str>] [TX_TIMESTAMP <u64>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5905 NTPv4 packet payload.
/// Syntax mapping: `NTP [LI <u8>] [VN <u8>] [MODE <u8>] [STRATUM <u8>] [POLL <u8>] [PRECISION <i8>] [REFID <str>] [TX_TIMESTAMP <u64>]`
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
    let li = (spec.li.unwrap_or(0) & 0x03) << 6;
    let vn = (spec.vn.unwrap_or(4) & 0x07) << 3;
    let mode = spec.mode.unwrap_or(3) & 0x07; // 3 = Client
    pkt[0] = li | vn | mode;
    pkt[1] = spec.stratum.unwrap_or(0);
    pkt[2] = spec.poll.unwrap_or(4);
    pkt[3] = spec.precision.unwrap_or(-6) as u8;

    if let Some(refid) = spec.refid {
        let bytes = refid.as_bytes();
        let len = bytes.len().min(4);
        pkt[12..12 + len].copy_from_slice(&bytes[..len]);
    }

    let tx_ts = spec.tx_timestamp.unwrap_or(0xE5000000_00000000);
    pkt[40..48].copy_from_slice(&tx_ts.to_be_bytes());

    let mut result = pkt.to_vec();
    if !payload_bytes.is_empty() {
        result.extend_from_slice(payload_bytes);
    }
    result
}
