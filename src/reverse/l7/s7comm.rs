//! Siemens S7 Communication (S7comm over RFC 1006 TPKT + ISO 8073 COTP) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `s7comm` frames encapsulated in
//! RFC 1006 TPKT (`\x03\x00`), ISO 8073 COTP DT (`\x02\xF0\x80`), and the `0x32` S7 protocol magic
//! byte over TCP (port `102` and NAT gateway custom ports). It decodes `rosctr` (`"job"`, `"ack"`,
//! `"ackdata"`, `"userdata"`), `pduref`, `setupcomm`, `plccontrol`, `readvar`, and `writevar`
//! (with `area`, `dbnum`, byte `offset`, and `count`).

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a Siemens `s7comm` TPKT + COTP + `0x32` PDU frame over TCP.
pub(crate) fn dissect_s7comm(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp)
        || payload.len() < 17
        || &payload[0..2] != b"\x03\x00"
        || u16::from_be_bytes([payload[2], payload[3]]) as usize != payload.len()
        || &payload[4..8] != b"\x02\xF0\x80\x32"
    {
        return None;
    }
    let rosctr = payload[8];
    let pdu_ref = u16::from_be_bytes([payload[11], payload[12]]);
    let param_len = u16::from_be_bytes([payload[13], payload[14]]) as usize;
    let data_len = u16::from_be_bytes([payload[15], payload[16]]) as usize;
    let hdr_len = if rosctr == 2 || rosctr == 3 {
        12usize
    } else {
        10usize
    };

    if payload.len() != 7 + hdr_len + param_len + data_len
        || ((rosctr == 2 || rosctr == 3) && &payload[17..19] != b"\x00\x00")
    {
        return None;
    }
    let param = &payload[7 + hdr_len..7 + hdr_len + param_len];
    let data = &payload[7 + hdr_len + param_len..];

    let mut tokens = String::from("s7comm");
    match rosctr {
        1 => {}
        2 => tokens.push_str(" rosctr \"ack\""),
        3 => tokens.push_str(" rosctr \"ackdata\""),
        7 => tokens.push_str(" rosctr \"userdata\""),
        _ => return None,
    }
    if pdu_ref != 1 {
        tokens.push_str(&format!(" pduref {pdu_ref}"));
    }

    if param == [0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0] {
        tokens.push_str(" setupcomm");
    } else if param == [0x28, 0x00] {
        tokens.push_str(" plccontrol");
    } else if param.len() == 14
        && matches!(param[0], 0x04 | 0x05)
        && &param[1..6] == b"\x01\x12\x0A\x10\x02"
    {
        if param[0] == 0x04 {
            tokens.push_str(" readvar");
        } else {
            tokens.push_str(" writevar");
        }
        let count = u16::from_be_bytes([param[6], param[7]]);
        let db_num = u16::from_be_bytes([param[8], param[9]]);
        let area = param[10];
        let bit_off = ((param[11] as u32) << 16) | ((param[12] as u32) << 8) | (param[13] as u32);
        if (bit_off & 0x07) != 0 {
            return None;
        }
        let offset = bit_off >> 3;
        if area != 0x84 {
            tokens.push_str(&format!(" area 0x{area:02x}"));
        }
        if db_num != 1 {
            tokens.push_str(&format!(" dbnum {db_num}"));
        }
        if offset != 0 {
            tokens.push_str(&format!(" offset {offset}"));
        }
        if count != 1 {
            tokens.push_str(&format!(" count {count}"));
        }
    } else {
        return None;
    }

    Some(ProtocolDissection {
        protocol: Protocol::S7comm,
        tokens,
        residual_payload: data.to_vec(),
        explicit_transport: None,
    })
}
