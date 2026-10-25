//! Precision Time Protocol v2 (PTPv2) (IEEE 1588-2008 (PTPv2) / RFC 8173) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Precision Time Protocol v2 (PTPv2) frames over UDP port 319 (Event messages: SYNC, DELAY_REQ) and UDP port 320 (General messages: FOLLOW_UP, DELAY_RESP, ANNOUNCE).
//! The wire encoder constructs a 34-byte IEEE 1588v2 commonPTP header (4-bit transportSpecific + 4-bit messageType, 4-bit versionPTP = 2, 16-bit messageLength, 8-bit domainNumber, 8-bit reserved, 16-bit flagField, 64-bit correctionField, 32-bit reserved, 80-bit sourcePortIdentity containing 64-bit ClockIdentity + 16-bit PortNumber, 16-bit sequenceId, 8-bit controlField, 8-bit logMessageInterval) followed by 10-byte originTimestamp. When optional fields in [`PtpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b PTP [SYNC | DELAY_REQ | FOLLOW_UP | DELAY_RESP | ANNOUNCE | MSG_TYPE <str>] [DOMAIN <u8>] [SEQ_ID <u16>] [CLOCK_ID <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an IEEE 1588v2 PTP packet payload and returns payload and UDP port (319 or 320).
/// Syntax mapping: `PTP [SYNC | DELAY_REQ | FOLLOW_UP | DELAY_RESP | ANNOUNCE | MSG_TYPE <str>] [DOMAIN <u8>] [SEQ_ID <u16>] [CLOCK_ID <str>]`
#[doc(alias = "PTP")]
#[doc(alias = "IEEE1588")]
#[doc(alias = "PTPV2")]
#[doc(alias = "CLOCK_ID")]
pub fn build_ptp_payload(
    ctx: &WireContext,
    spec: &PtpSpec,
    payload_bytes: &[u8],
) -> (Vec<u8>, u16) {
    let msg_type_str = spec.msg_type.unwrap_or("SYNC");
    let (msg_type_code, dport, control_field) = match msg_type_str.to_ascii_uppercase().as_str() {
        "SYNC" => (0x00u8, 319u16, 0x00u8),
        "DELAY_REQ" => (0x01u8, 319u16, 0x01u8),
        "FOLLOW_UP" => (0x08u8, 320u16, 0x02u8),
        "DELAY_RESP" => (0x09u8, 320u16, 0x03u8),
        "ANNOUNCE" => (0x0Bu8, 320u16, 0x05u8),
        _ => (0x00u8, 319u16, 0x00u8),
    };

    let mut pkt = [0u8; 44];
    let msg_len = (44 + payload_bytes.len()) as u16;
    pkt[0] = msg_type_code & 0x0F;
    pkt[1] = 0x02; // versionPTP 2.0
    pkt[2..4].copy_from_slice(&msg_len.to_be_bytes()); // messageLength
    pkt[4] = spec.domain.unwrap_or(0); // domainNumber
    pkt[30..32].copy_from_slice(&spec.seq_id.unwrap_or(1).to_be_bytes()); // sequenceId
    pkt[32] = control_field;

    // Clock identity: EUI-64 derived from source MAC
    if let Some(clock_id) = spec.clock_id {
        let bytes = clock_id.as_bytes();
        let len = bytes.len().min(8);
        pkt[20..20 + len].copy_from_slice(&bytes[..len]);
    } else {
        pkt[20] = ctx.src_mac[0];
        pkt[21] = ctx.src_mac[1];
        pkt[22] = ctx.src_mac[2];
        pkt[23] = 0xFF;
        pkt[24] = 0xFE;
        pkt[25] = ctx.src_mac[3];
        pkt[26] = ctx.src_mac[4];
        pkt[27] = ctx.src_mac[5];
    }
    pkt[28..30].copy_from_slice(&1u16.to_be_bytes()); // sourcePortIdentity portNumber 1

    let mut result = pkt.to_vec();
    if !payload_bytes.is_empty() {
        result.extend_from_slice(payload_bytes);
    }
    (result, dport)
}
