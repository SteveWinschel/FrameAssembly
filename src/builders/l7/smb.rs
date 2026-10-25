//! Server Message Block v2/v3 (SMB2/SMB3, MS-SMB2) wire payload builder.
//!
//! This module implements [`build_smb_payload`], which constructs a Microsoft `[MS-SMB2]` packet
//! encapsulated in a 4-byte big-endian NetBIOS Session Service stream header over TCP port 445
//! (or port 139). It populates the 64-byte little-endian SMB2 header (`\xFESMB` protocol magic,
//! `StructureSize = 64`, `Status`, `Command` opcode `0x0000..=0x0009`, `Flags`, `MessageId`,
//! `TreeId`, and `SessionId`) and appends command-specific request/response structures plus UTF-16LE
//! encoded `SHARE` or `FILENAME` buffers.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an MS-SMB2 Server Message Block packet payload.
pub fn build_smb_payload(
    _ctx: &WireContext,
    spec: &SmbSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let default_cmd = if spec.share.is_some() {
        "TREE_CONNECT"
    } else if spec.filename.is_some() {
        "CREATE"
    } else {
        "NEGOTIATE"
    };
    let cmd_code: u16 = match spec.command.unwrap_or(default_cmd).to_ascii_uppercase().as_str() {
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
    smb_hdr[8..12].copy_from_slice(&spec.status.unwrap_or(0).to_le_bytes()); // NTStatus
    smb_hdr[12..14].copy_from_slice(&cmd_code.to_le_bytes()); // Command
    smb_hdr[14..16].copy_from_slice(&1u16.to_le_bytes()); // CreditsRequested
    smb_hdr[24..32].copy_from_slice(&spec.msgid.unwrap_or(0).to_le_bytes()); // MessageId
    smb_hdr[36..40].copy_from_slice(&spec.tree_id.unwrap_or(0).to_le_bytes()); // TreeId
    smb_hdr[40..48].copy_from_slice(&spec.session_id.unwrap_or(0).to_le_bytes()); // SessionId

    let mut body = smb_hdr.to_vec();
    if cmd_code == 0x0000 {
        // Negotiate body (36 bytes + 2B dialect)
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
    } else if cmd_code == 0x0003 {
        // TREE_CONNECT Request (StructureSize 9)
        let share_str = spec.share.unwrap_or("\\\\localhost\\IPC$");
        let utf16: Vec<u8> = share_str
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize 9
        body.extend_from_slice(&0u16.to_le_bytes()); // Flags/Reserved
        body.extend_from_slice(&72u16.to_le_bytes()); // PathOffset (64 + 8)
        body.extend_from_slice(&(utf16.len() as u16).to_le_bytes()); // PathLength
        if utf16.is_empty() {
            body.extend_from_slice(&[0, 0]);
        } else {
            body.extend_from_slice(&utf16);
        }
    } else if cmd_code == 0x0005 {
        // CREATE Request (StructureSize 57)
        let fname = spec.filename.unwrap_or("file.txt");
        let utf16: Vec<u8> = fname.encode_utf16().flat_map(u16::to_le_bytes).collect();
        body.extend_from_slice(&57u16.to_le_bytes()); // StructureSize 57
        body.push(0); // SecurityFlags
        body.push(0); // RequestedOplockLevel
        body.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel (Impersonation)
        body.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
        body.extend_from_slice(&0u64.to_le_bytes()); // Reserved
        body.extend_from_slice(&0x0012_0089u32.to_le_bytes()); // DesiredAccess (Generic Read)
        body.extend_from_slice(&0x0000_0080u32.to_le_bytes()); // FileAttributes (Normal)
        body.extend_from_slice(&0x0000_0007u32.to_le_bytes()); // ShareAccess (R/W/D)
        body.extend_from_slice(&1u32.to_le_bytes()); // CreateDisposition (FILE_OPEN)
        body.extend_from_slice(&0x0000_0040u32.to_le_bytes()); // CreateOptions (Non-Directory)
        body.extend_from_slice(&120u16.to_le_bytes()); // NameOffset (64 + 56)
        body.extend_from_slice(&(utf16.len() as u16).to_le_bytes()); // NameLength
        body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        if utf16.is_empty() {
            body.extend_from_slice(&[0, 0]);
        } else {
            body.extend_from_slice(&utf16);
        }
    }

    if cmd_code != 0x0003
        && let Some(share_str) = spec.share
    {
        let utf16: Vec<u8> = share_str
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        body.extend_from_slice(&utf16);
    }
    if cmd_code != 0x0005
        && let Some(fname) = spec.filename
    {
        let utf16: Vec<u8> = fname.encode_utf16().flat_map(u16::to_le_bytes).collect();
        body.extend_from_slice(&utf16);
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
