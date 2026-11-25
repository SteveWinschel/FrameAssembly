//! Siemens S7 Communication Plus (S7commPlus, `0x72` over ISO-on-TCP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `s7commplus` frames encapsulated
//! in RFC 1006 TPKT (`0x03 0x00`), ISO 8073 COTP DT (`0x02 0xF0 0x80`), and the `0x72`
//! S7commPlus protocol header and trailer over TCP and SCTP port `102` (plus NAT gateway custom
//! ports). It decodes `version`, `opcode` / `isresponse`, `func` names (`explore`,
//! `createobject`, `deleteobject`, `setvariable`, `getlink`, `invoke`, `getmultivariables`,
//! `setmultivariables`), `seqnum`, `sessionid`, `flags`, object `id`, and trailing payload data.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32};

/// Formats an S7commPlus 16-bit function code as a canonical lowercase `.frasm` `func` modifier.
fn push_s7plus_func_token(tokens: &mut String, func: u16) {
    match func {
        0x04BB => tokens.push_str(" func \"explore\""),
        0x04CA => {}
        0x04D4 => tokens.push_str(" func \"deleteobject\""),
        0x04F2 => tokens.push_str(" func \"setvariable\""),
        0x0506 => tokens.push_str(" func \"getlink\""),
        0x0524 => tokens.push_str(" func \"beginsequence\""),
        0x052E => tokens.push_str(" func \"endsequence\""),
        0x0542 => tokens.push_str(" func \"invoke\""),
        0x054C => tokens.push_str(" func \"getmultivariables\""),
        0x0556 => tokens.push_str(" func \"setmultivariables\""),
        0x057C => tokens.push_str(" func \"getvarsubstreamed\""),
        0x0586 => tokens.push_str(" func \"setvarsubstreamed\""),
        other => tokens.push_str(&format!(" func \"0x{other:04x}\"")),
    }
}

/// Dissects a Siemens `s7commplus` TPKT + COTP + `0x72` PDU frame over TCP or SCTP.
pub(crate) fn dissect_s7commplus(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || payload.len() < 33
        || &payload[0..2] != b"\x03\x00"
        || usize::from(be_u16(payload, 2)) != payload.len()
        || &payload[4..8] != b"\x02\xF0\x80\x72"
    {
        return None;
    }

    let version = payload[8];
    if !(1..=3).contains(&version) {
        return None;
    }
    let data_len = usize::from(be_u16(payload, 9));
    let body_end = 11usize.checked_add(data_len)?;
    if data_len < 18
        || body_end.checked_add(4)? != payload.len()
        || payload[body_end..] != [0x72, version, 0x00, 0x00]
    {
        return None;
    }

    let body = &payload[11..body_end];
    if body[1..3] != [0x00, 0x00] || body[5..7] != [0x00, 0x00] {
        return None;
    }

    let opcode = body[0];
    let func_code = be_u16(body, 3);
    let seq_num = be_u16(body, 7);
    let session_id = be_u32(body, 9);
    let flags = body[13];
    let object_id = be_u32(body, 14);

    let mut tokens = String::from("s7commplus");
    if version != 1 {
        tokens.push_str(&format!(" version {version}"));
    }
    let default_flags = if opcode == 0x32 {
        tokens.push_str(" isresponse");
        0x00u8
    } else {
        if opcode != 0x31 {
            tokens.push_str(&format!(" opcode 0x{opcode:02x}"));
        }
        0x36u8
    };
    push_s7plus_func_token(&mut tokens, func_code);
    if seq_num != 1 {
        tokens.push_str(&format!(" seqnum {seq_num}"));
    }
    if session_id != 0 {
        tokens.push_str(&format!(" sessionid 0x{session_id:08x}"));
    }
    if object_id != 0 {
        tokens.push_str(&format!(" id 0x{object_id:08x}"));
    }
    if flags != default_flags {
        tokens.push_str(&format!(" flags 0x{flags:02x}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::S7commplus,
        tokens,
        residual_payload: body[18..].to_vec(),
        explicit_transport: None,
    })
}
