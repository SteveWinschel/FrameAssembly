//! Siemens S7 Communication (S7comm over RFC 1006 TPKT + ISO 8073 COTP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `s7comm` frames encapsulated in
//! RFC 1006 TPKT (`\x03\x00`), ISO 8073 COTP DT (`\x02\xF0\x80`), and the `0x32` S7 protocol magic
//! byte over TCP or SCTP (port `102` and NAT gateway custom ports). It decodes `rosctr` (`"ack"`,
//! `"ackdata"`), `pduref`, `setupcomm`, `plccontrol`, `readvar`, `writevar`, and `szl` (`Userdata`
//! System Status List request and `ackdata` response frames) with `area`, `dbnum`, byte `offset`,
//! and `count`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Valid S7 PLC memory area codes accepted by the `s7comm` forward builder without rewriting to `0x84`.
fn is_valid_s7_area_byte(area: u8) -> bool {
    matches!(area, 0x03 | 0x05..=0x07 | 0x1C..=0x1F | 0x80..=0x87)
}

/// Canonical 8-byte `Userdata` parameter block for an S7comm `SZL` request.
const SZL_REQ_PARAM: [u8; 8] = [0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00];

/// Canonical 12-byte `Userdata` parameter block for an S7comm `SZL` `ACK_DATA` response.
const SZL_RESP_PARAM: [u8; 12] = [
    0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Dissects a Siemens `s7comm` TPKT + COTP + `0x32` PDU frame over TCP or SCTP.
pub(crate) fn dissect_s7comm(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
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

    let expected_len = 7usize
        .checked_add(hdr_len)?
        .checked_add(param_len)?
        .checked_add(data_len)?;
    if payload.len() != expected_len
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
        7 => {}
        _ => return None,
    }
    if pdu_ref != 1 {
        tokens.push_str(&format!(" pduref {pdu_ref}"));
    }

    let residual: Vec<u8>;
    if rosctr == 7 {
        if param == SZL_REQ_PARAM {
            tokens.push_str(" szl");
        } else if param == SZL_RESP_PARAM {
            tokens.push_str(" rosctr \"ackdata\" szl");
        } else {
            return None;
        }
        if data.len() < 4
            || data[0] != 0xFF
            || data[1] != 0x09
            || u16::from_be_bytes([data[2], data[3]]) as usize != data.len() - 4
        {
            return None;
        }
        let body = &data[4..];
        residual = if body == b"\x00\x11\x00\x00" {
            Vec::new()
        } else {
            body.to_vec()
        };
    } else if param == [0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0] {
        tokens.push_str(" setupcomm");
        residual = data.to_vec();
    } else if param == [0x28, 0x00] {
        tokens.push_str(" plccontrol");
        residual = data.to_vec();
    } else if rosctr == 3 && param == [0x04, 0x01] {
        if data.len() < 5
            || data[0] != 0xFF
            || !matches!(data[1], 0x03 | 0x04 | 0x05 | 0x07 | 0x09)
        {
            return None;
        }
        tokens.push_str(" readvar");
        let byte_len = data.len() - 4;
        if data[1] == 0x04
            && (1..=4096).contains(&byte_len)
            && u16::from_be_bytes([data[2], data[3]]) as usize == byte_len * 8
            && data[4..].iter().all(|&b| b == 0)
        {
            if byte_len != 1 {
                tokens.push_str(&format!(" count {byte_len}"));
            }
            residual = Vec::new();
        } else {
            residual = data.to_vec();
        }
    } else if rosctr == 3 && param == [0x05, 0x01] {
        if data.is_empty() {
            return None;
        }
        tokens.push_str(" writevar");
        residual = if data == [0xFF] {
            Vec::new()
        } else {
            data.to_vec()
        };
    } else if rosctr != 3
        && param.len() == 14
        && matches!(param[0], 0x04 | 0x05)
        && &param[1..6] == b"\x01\x12\x0A\x10\x02"
    {
        let count = u16::from_be_bytes([param[6], param[7]]);
        if count == 0 {
            return None;
        }
        let db_num = u16::from_be_bytes([param[8], param[9]]);
        let area = param[10];
        if !is_valid_s7_area_byte(area) {
            return None;
        }
        let bit_off = ((param[11] as u32) << 16) | ((param[12] as u32) << 8) | (param[13] as u32);
        if (bit_off & 0x07) != 0 {
            return None;
        }
        let offset = bit_off >> 3;
        if param[0] == 0x04 {
            tokens.push_str(" readvar");
            residual = data.to_vec();
        } else {
            if data.len() < 5
                || data[0] != 0xFF
                || data[1] != 0x04
                || u16::from_be_bytes([data[2], data[3]]) as usize != (data.len() - 4) * 8
            {
                return None;
            }
            tokens.push_str(" writevar");
            let raw_val = &data[4..];
            if raw_val.len() == usize::from(count).min(4096) && raw_val.iter().all(|&b| b == 0) {
                residual = Vec::new();
            } else {
                residual = raw_val.to_vec();
            }
        }
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
        residual_payload: residual,
        explicit_transport: None,
    })
}
