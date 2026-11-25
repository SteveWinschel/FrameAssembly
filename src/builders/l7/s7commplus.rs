//! Siemens S7 Communication Plus (S7commPlus, `0x72` over ISO-on-TCP) wire payload builder.
//!
//! This module implements [`build_s7commplus_payload`], which serializes an [`S7commplusSpec`]
//! AST specification into a Siemens TIA Portal S7-1200/S7-1500 S7commPlus frame over TCP
//! port 102. It emits the 4-byte RFC 1006 TPKT header (`0x03 0x00`), 3-byte ISO 8073 COTP DT
//! header (`0x02 0xF0 0x80`), 4-byte `0x72` S7commPlus header (`0x72`, `version`, big-endian
//! `data_len`), 18-byte S7commPlus PDU body (`opcode`, `func`, `seqnum`, `sessionid`, `flags`,
//! and `object_id`) plus optional trailing payload, and the 4-byte `[0x72, version, 0x00, 0x00]`
//! frame trailer.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Parses an S7commPlus function name or decimal/hexadecimal code into a 16-bit function ID.
fn parse_s7plus_func(raw: &str) -> u16 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(v) = u16::from_str_radix(hex, 16)
    {
        return v;
    }
    if let Ok(v) = trimmed.parse::<u16>() {
        return v;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "EXPLORE" => 0x04BB,
        "CREATEOBJECT" => 0x04CA,
        "DELETEOBJECT" => 0x04D4,
        "SETVARIABLE" => 0x04F2,
        "GETLINK" => 0x0506,
        "BEGINSEQUENCE" => 0x0524,
        "ENDSEQUENCE" => 0x052E,
        "INVOKE" => 0x0542,
        "GETMULTIVARIABLES" => 0x054C,
        "SETMULTIVARIABLES" => 0x0556,
        "GETVARSUBSTREAMED" => 0x057C,
        "SETVARSUBSTREAMED" => 0x0586,
        _ => 0x04CA,
    }
}

/// Builds a Siemens S7commPlus (`0x72` magic) payload encapsulated in TPKT + COTP DT.
pub fn build_s7commplus_payload(
    _ctx: &WireContext,
    spec: &S7commplusSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let ver = spec.version.unwrap_or(1).clamp(1, 3);
    let opcode = spec
        .opcode
        .unwrap_or(if spec.is_response { 0x32 } else { 0x31 });
    let func_code = parse_s7plus_func(spec.func.unwrap_or("createobject"));
    let seq_num = spec.seq_num.unwrap_or(1);
    let session_id = spec.session_id.unwrap_or(0);
    let flags = spec
        .flags
        .unwrap_or(if opcode == 0x32 { 0x00 } else { 0x36 });
    let object_id = spec.object_id.unwrap_or(0);

    let mut body = Vec::with_capacity(18 + payload_bytes.len());
    body.push(opcode);
    body.extend_from_slice(&0u16.to_be_bytes()); // Reserved1
    body.extend_from_slice(&func_code.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // Reserved2
    body.extend_from_slice(&seq_num.to_be_bytes());
    body.extend_from_slice(&session_id.to_be_bytes());
    body.push(flags);
    body.extend_from_slice(&object_id.to_be_bytes());
    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let data_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let total_len = u16::try_from(4 + 3 + 4 + body.len() + 4).unwrap_or(u16::MAX);

    let mut pkt = Vec::with_capacity(usize::from(total_len));
    // TPKT (4B) + COTP DT (3B)
    pkt.extend_from_slice(&[0x03, 0x00]);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x02, 0xF0, 0x80]);

    // S7commPlus Header (4B) + Body + Trailer (4B)
    pkt.push(0x72);
    pkt.push(ver);
    pkt.extend_from_slice(&data_len.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt.extend_from_slice(&[0x72, ver, 0x00, 0x00]);
    pkt
}
