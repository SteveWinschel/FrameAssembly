//! ODVA EtherNet/IP and Common Industrial Protocol (CIP) wire payload builder.
//!
//! This module implements [`build_ethernetip_payload`], which serializes an
//! [`EthernetipSpec`] AST specification into an ODVA
//! EtherNet/IP encapsulation packet over TCP port 44818 or UDP port 2222. It constructs the 24-byte
//! little-endian Encapsulation Header (`Command` code `0x0000..=0x0070`, payload `Length`,
//! `SessionHandle`, `Status`, 64-bit `SenderContext`, and `Options`) and encodes command-specific
//! bodies including `RegisterSession` protocol version/flags and `SendRRData` / `SendUnitData`
//! Common Packet Format (CPF) items with EPATH Class/Instance/Attribute segments.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an ODVA EtherNet/IP & CIP encapsulation packet payload.
pub fn build_ethernetip_payload(
    _ctx: &WireContext,
    spec: &EthernetipSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let has_cip = spec.cip_service.is_some()
        || spec.cip_class.is_some()
        || spec.cip_instance.is_some()
        || spec.cip_attr.is_some();

    let default_cmd = if has_cip {
        "SEND_RR_DATA"
    } else {
        "LIST_IDENTITY"
    };
    let cmd_code: u16 = match spec.cmd.unwrap_or(default_cmd).to_ascii_uppercase().as_str() {
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
    } else if (cmd_code == 0x006F || cmd_code == 0x0070 || has_cip) && payload_bytes.is_empty() {
        // Synthesize CIP Common Packet Format (CPF) body
        let mut cip = Vec::new();
        cip.push(spec.cip_service.unwrap_or(0x0E)); // Get_Attribute_Single (0x0E)
        let path_words: u8 = if spec.cip_attr.is_some() { 3 } else { 2 };
        cip.push(path_words);
        cip.push(0x20); // 8-bit Class segment
        cip.push(spec.cip_class.unwrap_or(1) as u8);
        cip.push(0x24); // 8-bit Instance segment
        cip.push(spec.cip_instance.unwrap_or(1) as u8);
        if let Some(attr) = spec.cip_attr {
            cip.push(0x30); // 8-bit Attribute segment
            cip.push(attr as u8);
        }

        body.extend_from_slice(&0u32.to_le_bytes()); // Interface Handle: CIP (0)
        body.extend_from_slice(&0u16.to_le_bytes()); // Timeout: 0
        body.extend_from_slice(&2u16.to_le_bytes()); // Item Count: 2
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // Null Address Item (0x0000)
        body.extend_from_slice(&0u16.to_le_bytes()); // Address Length: 0
        body.extend_from_slice(&0x00B2u16.to_le_bytes()); // Unconnected Data Item (0x00B2)
        body.extend_from_slice(&(cip.len() as u16).to_le_bytes());
        body.extend_from_slice(&cip);
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
