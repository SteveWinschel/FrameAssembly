//! Server Message Block v2/v3 (SMB2, MS-SMB2) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `smb` packets encapsulated inside
//! 4-byte NetBIOS Session Service headers (`\x00...\xFESMB`) over TCP (ports `445`, `139`, and
//! custom ports matching the 64-byte SMB2 header signature). It decodes `negotiate`,
//! `sessionsetup`, `"logoff"`, `treeconnect` (with UTF-16LE `share`), `treedisconnect`, `create`
//! (with UTF-16LE `filename`), `"close"`, `"read"`, and `"write"` commands into canonical `.frasm` tokens.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Decodes a UTF-16LE byte slice into a UTF-8 `String`.
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Reads a little-endian `u16` from `b[off..off + 2]`.
fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// Reads a little-endian `u32` from `b[off..off + 4]`.
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Reads a little-endian `u64` from `b[off..off + 8]`.
fn le_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// Dissects an `SMB2` packet encapsulated in a 4-byte NetBIOS Session Service header over TCP.
pub(crate) fn dissect_smb(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp)
        || payload.len() < 68
        || payload[0] != 0x00
        || &payload[4..8] != b"\xFESMB"
    {
        return None;
    }
    let hdr = &payload[4..68];
    if le_u16(hdr, 4) != 64 {
        return None;
    }
    let status = le_u32(hdr, 8);
    let cmd_code = le_u16(hdr, 12);
    let msgid = le_u64(hdr, 24);
    let tree_id = le_u32(hdr, 36);
    let session_id = le_u64(hdr, 40);

    let body = &payload[68..];
    let mut tokens = String::from("smb");
    let mut share_opt: Option<String> = None;
    let mut file_opt: Option<String> = None;
    let residual: &[u8];

    match cmd_code {
        0x0000 => {
            if body.len() < 38 || le_u16(body, 0) != 36 {
                return None;
            }
            residual = &body[38..];
        }
        0x0001 => {
            tokens.push_str(" sessionsetup");
            residual = body;
        }
        0x0002 => {
            tokens.push_str(" command \"logoff\"");
            residual = body;
        }
        0x0003 => {
            if body.len() < 8 || le_u16(body, 0) != 9 {
                return None;
            }
            tokens.push_str(" treeconnect");
            let path_len = le_u16(body, 6) as usize;
            let consumed = if path_len == 0 { 2usize } else { path_len };
            if body.len() < 8 + consumed {
                return None;
            }
            let s = if path_len == 0 {
                String::new()
            } else {
                decode_utf16le(&body[8..8 + path_len])?
            };
            if !is_valid_raw_str(&s) {
                return None;
            }
            share_opt = Some(s);
            residual = &body[8 + consumed..];
        }
        0x0004 => {
            tokens.push_str(" treedisconnect");
            residual = body;
        }
        0x0005 => {
            if body.len() < 56 || le_u16(body, 0) != 57 {
                return None;
            }
            tokens.push_str(" create");
            let name_len = le_u16(body, 48) as usize;
            let consumed = if name_len == 0 { 2usize } else { name_len };
            if body.len() < 56 + consumed {
                return None;
            }
            let f = if name_len == 0 {
                String::new()
            } else {
                decode_utf16le(&body[56..56 + name_len])?
            };
            if !is_valid_raw_str(&f) {
                return None;
            }
            file_opt = Some(f);
            residual = &body[56 + consumed..];
        }
        0x0006 => {
            tokens.push_str(" command \"close\"");
            residual = body;
        }
        0x0008 => {
            tokens.push_str(" command \"read\"");
            residual = body;
        }
        0x0009 => {
            tokens.push_str(" command \"write\"");
            residual = body;
        }
        _ => return None,
    }

    if status != 0 {
        tokens.push_str(&format!(" status 0x{status:08x}"));
    }
    if session_id != 0 {
        tokens.push_str(&format!(" sessionid 0x{session_id:x}"));
    }
    if tree_id != 0 {
        tokens.push_str(&format!(" treeid {tree_id}"));
    }
    if msgid != 0 {
        tokens.push_str(&format!(" msgid {msgid}"));
    }
    if let Some(sh) = share_opt.as_deref()
        && sh != "\\\\localhost\\IPC$"
    {
        tokens.push_str(&format!(" share \"{sh}\""));
    }
    if let Some(fl) = file_opt.as_deref()
        && fl != "file.txt"
    {
        tokens.push_str(&format!(" filename \"{fl}\""));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Smb,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
