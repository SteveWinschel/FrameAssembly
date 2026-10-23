//! ETHERNETIP industrial OT protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an ODVA EtherNet/IP & CIP encapsulation packet payload.
pub fn build_ethernetip_payload(
    _ctx: &WireContext,
    spec: &EthernetipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cmd_code: u16 = match spec.cmd.unwrap_or("LIST_IDENTITY").to_ascii_uppercase().as_str() {
        "NOP" => 0x0000,
        "LIST_SERVICES" => 0x0004,
        "LIST_IDENTITY" => 0x0063,
        "LIST_INTERFACES" => 0x0064,
        "REGISTER_SESSION" => 0x0065,
        "UNREGISTER_SESSION" => 0x0066,
        "SEND_RR_DATA" => 0x006F,
        "SEND_UNIT_DATA" => 0x0070,
        _ => 0x0063,
    };

    let session_handle = spec.session_handle.unwrap_or(0);
    let status = spec.status.unwrap_or(0);
    let context = spec.context.unwrap_or(0);

    let mut body = Vec::new();
    if cmd_code == 0x0065 {
        // Register Session command data (4 bytes)
        body.extend_from_slice(&1u16.to_le_bytes()); // Protocol Version: 1
        body.extend_from_slice(&0u16.to_le_bytes()); // Options: 0
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let length = body.len() as u16;
    let mut pkt = Vec::with_capacity(24 + body.len());
    pkt.extend_from_slice(&cmd_code.to_le_bytes()); // Command
    pkt.extend_from_slice(&length.to_le_bytes()); // Length
    pkt.extend_from_slice(&session_handle.to_le_bytes()); // Session Handle
    pkt.extend_from_slice(&status.to_le_bytes()); // Status
    pkt.extend_from_slice(&context.to_le_bytes()); // Sender Context (8 bytes)
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Options
    pkt.extend_from_slice(&body);
    pkt
}
