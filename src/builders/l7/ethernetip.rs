//! ODVA EtherNet/IP and Common Industrial Protocol (CIP) wire payload builder.
//!
//! This module implements [`build_ethernetip_payload`], which serializes an
//! [`EthernetipSpec`] AST specification into an ODVA EtherNet/IP encapsulation packet over TCP
//! port 44818 or UDP port 2222. It constructs the 24-byte little-endian Encapsulation Header
//! (`NOP`, `ListServices` `0x0004`, `ListIdentity` `0x0063`, `ListInterfaces` `0x0064`,
//! `RegisterSession` `0x0065`, `UnregisterSession` `0x0066`, `SendRRData` `0x006F`, and
//! `SendUnitData` `0x0070`) and encodes 8-bit (`0x20`/`0x24`/`0x30`) or 16-bit padded
//! (`0x21`/`0x25`/`0x31`) CIP EPATH segments inside Common Packet Format (CPF) items.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Parses an EtherNet/IP encapsulation command string or numeric code into a 16-bit command ID.
fn parse_enip_cmd(raw: &str) -> u16 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "NOP" => 0x0000,
        "LISTSERVICES" => 0x0004,
        "LISTIDENTITY" => 0x0063,
        "LISTINTERFACES" => 0x0064,
        "REGISTERSESSION" => 0x0065,
        "UNREGISTERSESSION" => 0x0066,
        "SENDRRDATA" => 0x006F,
        "SENDUNITDATA" => 0x0070,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u16::from_str_radix(hex, 16).unwrap_or(0x0063)
            } else {
                norm.parse::<u16>().unwrap_or(0x0063)
            }
        }
    }
}

/// Appends an 8-bit (`val <= 255`) or 16-bit padded (`val > 255`) ODVA CIP logical EPATH segment.
fn push_cip_logical_segment(epath: &mut Vec<u8>, seg_8bit: u8, seg_16bit: u8, val: u16) {
    if val <= 0xFF {
        epath.push(seg_8bit);
        epath.push(val as u8);
    } else {
        epath.push(seg_16bit);
        epath.push(0x00); // Padded EPATH alignment octet (ODVA CIP Vol. 1 Appendix C)
        epath.extend_from_slice(&val.to_le_bytes());
    }
}

/// Builds a CIP Message Router Request with padded 8-bit or 16-bit Class/Instance/Attribute EPATH.
fn build_cip_request(spec: &EthernetipSpec) -> Vec<u8> {
    let mut epath = Vec::with_capacity(12);
    push_cip_logical_segment(&mut epath, 0x20, 0x21, spec.cip_class.unwrap_or(1));
    push_cip_logical_segment(&mut epath, 0x24, 0x25, spec.cip_instance.unwrap_or(1));
    if let Some(attr) = spec.cip_attr {
        push_cip_logical_segment(&mut epath, 0x30, 0x31, attr);
    }

    let mut cip = Vec::with_capacity(2 + epath.len());
    cip.push(spec.cip_service.unwrap_or(0x0E)); // Default: Get_Attribute_Single (0x0E)
    cip.push((epath.len() / 2) as u8); // Path size in 16-bit words
    cip.extend_from_slice(&epath);
    cip
}

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
        "sendrrdata"
    } else {
        "listidentity"
    };
    let cmd_code = parse_enip_cmd(spec.cmd.unwrap_or(default_cmd));

    let session_handle = spec.session_handle.unwrap_or(0);
    let status = spec.status.unwrap_or(0);
    let context = spec.context.unwrap_or(0);

    let mut body = Vec::new();
    if cmd_code == 0x0065 {
        // RegisterSession command data (4 bytes: Protocol Version 1, Options Flags 0)
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
    } else if cmd_code == 0x006F && payload_bytes.is_empty() {
        // SendRRData: Unconnected CIP CPF (Null Address Item 0x0000 + Unconnected Data Item 0x00B2)
        let cip = build_cip_request(spec);
        let cip_len = u16::try_from(cip.len()).unwrap_or(u16::MAX);
        body.extend_from_slice(&0u32.to_le_bytes()); // Interface Handle: CIP (0)
        body.extend_from_slice(&0u16.to_le_bytes()); // Timeout: 0
        body.extend_from_slice(&2u16.to_le_bytes()); // Item Count: 2
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // Null Address Item (0x0000)
        body.extend_from_slice(&0u16.to_le_bytes()); // Address Length: 0
        body.extend_from_slice(&0x00B2u16.to_le_bytes()); // Unconnected Data Item (0x00B2)
        body.extend_from_slice(&cip_len.to_le_bytes());
        body.extend_from_slice(&cip);
    } else if cmd_code == 0x0070 && payload_bytes.is_empty() {
        // SendUnitData: Connected CIP CPF (Connected Address Item 0x00A1 + Connected Data Item 0x00B1)
        let cip = build_cip_request(spec);
        let data_item_len = u16::try_from(2usize.saturating_add(cip.len())).unwrap_or(u16::MAX);
        body.extend_from_slice(&0u32.to_le_bytes()); // Interface Handle: CIP (0)
        body.extend_from_slice(&0u16.to_le_bytes()); // Timeout: 0
        body.extend_from_slice(&2u16.to_le_bytes()); // Item Count: 2
        body.extend_from_slice(&0x00A1u16.to_le_bytes()); // Connected Address Item (0x00A1)
        body.extend_from_slice(&4u16.to_le_bytes()); // Address Length: 4
        body.extend_from_slice(&1u32.to_le_bytes()); // Connection Identifier
        body.extend_from_slice(&0x00B1u16.to_le_bytes()); // Connected Data Item (0x00B1)
        body.extend_from_slice(&data_item_len.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // CIP Sequence Count
        body.extend_from_slice(&cip);
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let length = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(24 + body.len());
    pkt.extend_from_slice(&cmd_code.to_le_bytes());
    pkt.extend_from_slice(&length.to_le_bytes());
    pkt.extend_from_slice(&session_handle.to_le_bytes());
    pkt.extend_from_slice(&status.to_le_bytes());
    pkt.extend_from_slice(&context.to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Options
    pkt.extend_from_slice(&body);
    pkt
}
