//! NTP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 5905 NTPv4 packet payload.
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
