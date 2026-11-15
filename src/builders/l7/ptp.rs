//! Precision Time Protocol v2 (PTPv2) (IEEE 1588-2008 (PTPv2) / RFC 8173) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Precision Time Protocol v2 (PTPv2) frames over UDP port 319 (Event messages: SYNC, DELAY_REQ) and UDP port 320 (General messages: FOLLOW_UP, DELAY_RESP, ANNOUNCE).
//! The wire encoder constructs a 34-byte IEEE 1588v2 commonPTP header (4-bit transportSpecific + 4-bit messageType, 4-bit versionPTP = 2, 16-bit messageLength, 8-bit domainNumber, 8-bit reserved, 16-bit flagField, 64-bit correctionField, 32-bit reserved, 80-bit sourcePortIdentity containing 64-bit ClockIdentity + 16-bit PortNumber, 16-bit sequenceId, 8-bit controlField, 8-bit logMessageInterval) followed by 10-byte originTimestamp. When optional fields in [`PtpSpec`]
//! are omitted in the `.frasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ptp [sync | delayreq | followup | delayresp | announce | msgtype <str>] [domain <u8>] [seqid <u16>] [clockid <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Parses a `clockid` modifier into an 8-byte IEEE 1588 `ClockIdentity`.
///
/// Accepts `0x`-prefixed or 16-character hexadecimal strings (`0x001b19fffe123456`),
/// colon/hyphen-delimited 8-octet hex (`00:1b:19:ff:fe:12:34:56`), or up to 8 ASCII bytes.
fn parse_clock_id(clock_id: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let trimmed = clock_id.trim();
    let hex_cand = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    if let Some(hex) = hex_cand {
        if !hex.is_empty() && hex.len() <= 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let padded = format!("{hex:0>16}");
            for (i, pair) in padded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                if let Ok(s) = core::str::from_utf8(pair)
                    && let Ok(v) = u8::from_str_radix(s, 16)
                {
                    out[i] = v;
                }
            }
            return out;
        }
    } else if trimmed.len() == 16 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        for (i, pair) in trimmed.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            if let Ok(s) = core::str::from_utf8(pair)
                && let Ok(v) = u8::from_str_radix(s, 16)
            {
                out[i] = v;
            }
        }
        return out;
    }

    if trimmed.contains(':') || trimmed.contains('-') {
        let sep = if trimmed.contains(':') { ':' } else { '-' };
        let parts: Vec<&str> = trimmed.split(sep).collect();
        if parts.len() == 8 && parts.iter().all(|p| !p.is_empty() && p.len() <= 2) {
            let mut parsed_ok = true;
            for (i, p) in parts.iter().enumerate() {
                match u8::from_str_radix(p, 16) {
                    Ok(b) => out[i] = b,
                    Err(_) => {
                        parsed_ok = false;
                        break;
                    }
                }
            }
            if parsed_ok {
                return out;
            }
            out = [0u8; 8];
        }
    }

    let bytes = clock_id.as_bytes();
    let len = bytes.len().min(8);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Builds an IEEE 1588v2 PTP packet payload and returns payload and UDP port (319 or 320).
/// Syntax mapping: `ptp [sync | delayreq | followup | delayresp | announce | msgtype <str>] [domain <u8>] [seqid <u16>] [clockid <str>]`
#[doc(alias = "PTP")]
#[doc(alias = "IEEE1588")]
#[doc(alias = "PTPV2")]
#[doc(alias = "CLOCK_ID")]
pub fn build_ptp_payload(
    ctx: &WireContext,
    spec: &PtpSpec,
    payload_bytes: &[u8],
) -> (Vec<u8>, u16) {
    let msg_type_norm = spec
        .msg_type
        .unwrap_or("sync")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let (msg_type_code, dport, control_field, fixed_len) = match msg_type_norm.as_str() {
        "SYNC" => (0x00u8, 319u16, 0x00u8, 44usize),
        "DELAYREQ" => (0x01u8, 319u16, 0x01u8, 44usize),
        "FOLLOWUP" => (0x08u8, 320u16, 0x02u8, 44usize),
        "DELAYRESP" => (0x09u8, 320u16, 0x03u8, 54usize),
        "ANNOUNCE" => (0x0Bu8, 320u16, 0x05u8, 64usize),
        _ => (0x00u8, 319u16, 0x00u8, 44usize),
    };

    let clock_bytes = if let Some(clock_id) = spec.clock_id {
        parse_clock_id(clock_id)
    } else {
        [
            ctx.src_mac[0],
            ctx.src_mac[1],
            ctx.src_mac[2],
            0xFF,
            0xFE,
            ctx.src_mac[3],
            ctx.src_mac[4],
            ctx.src_mac[5],
        ]
    };

    let mut pkt = alloc::vec![0u8; fixed_len];
    let msg_len = fixed_len
        .saturating_add(payload_bytes.len())
        .min(usize::from(u16::MAX)) as u16;
    pkt[0] = msg_type_code & 0x0F;
    pkt[1] = 0x02; // versionPTP 2.0
    pkt[2..4].copy_from_slice(&msg_len.to_be_bytes()); // messageLength
    pkt[4] = spec.domain.unwrap_or(0); // domainNumber
    pkt[20..28].copy_from_slice(&clock_bytes);
    pkt[28..30].copy_from_slice(&1u16.to_be_bytes()); // sourcePortIdentity portNumber 1
    pkt[30..32].copy_from_slice(&spec.seq_id.unwrap_or(1).to_be_bytes()); // sequenceId
    pkt[32] = control_field;

    // IEEE 1588-2008 §13.5 Announce message body fields (bytes 44..64)
    if msg_type_code == 0x0B {
        pkt[44..46].copy_from_slice(&37u16.to_be_bytes()); // currentUtcOffset (TAI-UTC = 37s)
        pkt[46] = 0; // reserved
        pkt[47] = 128; // grandmasterPriority1
        pkt[48] = 248; // grandmasterClockClass (default class 248)
        pkt[49] = 0xFE; // grandmasterClockAccuracy (unknown)
        pkt[50..52].copy_from_slice(&0xFFFFu16.to_be_bytes()); // offsetScaledLogVariance
        pkt[52] = 128; // grandmasterPriority2
        pkt[53..61].copy_from_slice(&clock_bytes); // grandmasterIdentity
        pkt[61..63].copy_from_slice(&0u16.to_be_bytes()); // stepsRemoved
        pkt[63] = 0xA0; // timeSource (INTERNAL_OSCILLATOR)
    }

    if !payload_bytes.is_empty() {
        pkt.extend_from_slice(payload_bytes);
    }
    (pkt, dport)
}
