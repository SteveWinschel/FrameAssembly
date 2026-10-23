//! SMB protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an MS-SMB2 Server Message Block packet payload.
pub fn build_smb_payload(
    _ctx: &WireContext,
    spec: &SmbSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cmd_code: u16 = match spec.command.unwrap_or("NEGOTIATE").to_ascii_uppercase().as_str() {
        "NEGOTIATE" => 0x0000,
        "SESSION_SETUP" => 0x0001,
        "LOGOFF" => 0x0002,
        "TREE_CONNECT" => 0x0003,
        "TREE_DISCONNECT" => 0x0004,
        "CREATE" => 0x0005,
        "CLOSE" => 0x0006,
        "READ" => 0x0008,
        "WRITE" => 0x0009,
        _ => 0x0000,
    };

    let mut smb_hdr = [0u8; 64];
    smb_hdr[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']); // Magic
    smb_hdr[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize 64
    smb_hdr[12..14].copy_from_slice(&cmd_code.to_le_bytes()); // Command
    smb_hdr[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditsRequested
    smb_hdr[24..32].copy_from_slice(&spec.msgid.unwrap_or(0).to_le_bytes()); // MessageId
    smb_hdr[36..40].copy_from_slice(&spec.tree_id.unwrap_or(0).to_le_bytes()); // TreeId
    smb_hdr[40..48].copy_from_slice(&spec.session_id.unwrap_or(0).to_le_bytes()); // SessionId

    let mut body = smb_hdr.to_vec();
    if cmd_code == 0 {
        // Negotiate body (36 bytes)
        body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize 36
        body.extend_from_slice(&1u16.to_le_bytes()); // DialectCount 1
        body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode 1
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        body.extend_from_slice(&0x7Fu32.to_le_bytes()); // Capabilities
        body.extend_from_slice(&[0u8; 16]); // ClientGuid
        body.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
        body.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        body.extend_from_slice(&0x0202u16.to_le_bytes()); // Dialect 0x0202 (SMB 2.0.2)
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    // Direct TCP NetBIOS Transport header (4 bytes: 0x00 + 3-byte length)
    let length = body.len() as u32;
    let mut pkt = Vec::with_capacity(4 + body.len());
    pkt.push(0);
    pkt.push((length >> 16) as u8);
    pkt.push((length >> 8) as u8);
    pkt.push(length as u8);
    pkt.extend_from_slice(&body);
    pkt
}
