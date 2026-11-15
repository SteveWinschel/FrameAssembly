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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
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
    let nb_len =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | (payload[3] as usize);
    if 4usize.checked_add(nb_len)? != payload.len() {
        return None;
    }
    let hdr = &payload[4..68];
    if le_u16(hdr, 4) != 64 {
        return None;
    }
    let status = le_u32(hdr, 8);
    let cmd_code = le_u16(hdr, 12);
    let flags = le_u32(hdr, 16);
    if flags > 1 || (status != 0 && flags != 1) {
        return None;
    }
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
            if flags == 1 {
                let expected_resp = [9u8, 0, 0, 0, 72, 0, 0, 0, 0];
                residual = body.strip_prefix(&expected_resp)?;
            } else {
                let expected_req = [
                    25u8, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ];
                residual = body.strip_prefix(&expected_req)?;
            }
        }
        0x0002 => {
            tokens.push_str(" command \"logoff\"");
            residual = body.strip_prefix(&[0x04, 0x00, 0x00, 0x00])?;
        }
        0x0003 => {
            if body.len() < 8 || le_u16(body, 0) != 9 {
                return None;
            }
            tokens.push_str(" treeconnect");
            let path_len = le_u16(body, 6) as usize;
            let consumed = if path_len == 0 { 2usize } else { path_len };
            let end_off = 8usize.checked_add(consumed)?;
            if body.len() < end_off {
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
            residual = &body[end_off..];
        }
        0x0004 => {
            tokens.push_str(" treedisconnect");
            residual = body.strip_prefix(&[0x04, 0x00, 0x00, 0x00])?;
        }
        0x0005 => {
            if body.len() < 56 || le_u16(body, 0) != 57 {
                return None;
            }
            tokens.push_str(" create");
            let name_len = le_u16(body, 48) as usize;
            let consumed = if name_len == 0 { 2usize } else { name_len };
            let end_off = 56usize.checked_add(consumed)?;
            if body.len() < end_off {
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
            residual = &body[end_off..];
        }
        0x0006 => {
            if body.len() < 24 || le_u16(body, 0) != 24 || body[2..24].iter().any(|&b| b != 0) {
                return None;
            }
            tokens.push_str(" command \"close\"");
            residual = &body[24..];
        }
        0x0008 => {
            if body.len() < 49
                || &body[0..8] != b"\x31\x00\x50\x00\x00\x10\x00\x00"
                || body[8..49].iter().any(|&b| b != 0)
            {
                return None;
            }
            tokens.push_str(" command \"read\"");
            residual = &body[49..];
        }
        0x0009 => {
            if body.len() < 49
                || &body[0..4] != b"\x31\x00\x70\x00"
                || body[4..49].iter().any(|&b| b != 0)
            {
                return None;
            }
            tokens.push_str(" command \"write\"");
            residual = &body[49..];
        }
        _ => return None,
    }

    if status != 0 {
        tokens.push_str(&format!(" status 0x{status:08x}"));
    } else if flags == 1 {
        tokens.push_str(" status 0");
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
