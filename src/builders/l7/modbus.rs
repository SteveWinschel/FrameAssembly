//! Modbus TCP Application Protocol v1.1b3 (MBAP + PDU) wire payload builder.
//!
//! This module implements [`build_modbus_payload`], which serializes a [`ModbusSpec`]
//! AST node into a Modbus TCP Application Data Unit (ADU) over TCP or UDP port 502. It constructs
//! the 7-byte MBAP header (16-bit Transaction ID, 16-bit Protocol ID `0x0000`, 16-bit Length, and
//! 8-bit Unit ID) followed by the 1-byte Function Code (named or numeric `0x01..=0x7F`, or
//! exception `func | 0x80` + 1-byte exception code), and either a 4-byte request body
//! (`addr`, `count_or_val`), RFC byte-counted FC `0x0F`/`0x10` write framing, or a byte-counted
//! response body when `isresponse` is set.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Parses a Modbus function name or decimal/hexadecimal code string into an 8-bit function code.
fn parse_modbus_func(raw: &str) -> u8 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(val) = u8::from_str_radix(hex, 16)
    {
        return val;
    }
    if let Ok(val) = trimmed.parse::<u8>() {
        return val;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "READCOILS" => 1,
        "READDISCRETEINPUTS" => 2,
        "READHOLDINGREGISTERS" => 3,
        "READINPUTREGISTERS" => 4,
        "WRITESINGLECOIL" => 5,
        "WRITESINGLEREGISTER" => 6,
        "READEXCEPTIONSTATUS" => 7,
        "DIAGNOSTICS" => 8,
        "GETCOMMEVENTCOUNTER" => 11,
        "GETCOMMEVENTLOG" => 12,
        "WRITEMULTIPLECOILS" => 15,
        "WRITEMULTIPLEREGISTERS" => 16,
        "REPORTSERVERID" => 17,
        "READFILERECORD" => 20,
        "WRITEFILERECORD" => 21,
        "MASKWRITEREGISTER" => 22,
        "READWRITEMULTIPLEREGISTERS" => 23,
        "READFIFOQUEUE" => 24,
        "ENCAPSULATEDINTERFACETRANSPORT" | "MEI" => 43,
        _ => 3,
    }
}

/// Builds a Modbus TCP/UDP packet payload with 7-byte MBAP header.
pub fn build_modbus_payload(
    _ctx: &WireContext,
    spec: &ModbusSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let txid = spec.txid.unwrap_or(1);
    let proto_id = spec.proto_id.unwrap_or(0);
    let unit_id = spec.unitid.unwrap_or(1);

    let raw_func_code = parse_modbus_func(spec.func.unwrap_or("readholdingregisters"));
    let is_exception = spec.exception_code.is_some() || (raw_func_code & 0x80) != 0;
    let func_code = raw_func_code & 0x7F;

    let mut pdu = Vec::new();
    let mut consumed_payload = false;

    if is_exception {
        pdu.push(func_code | 0x80);
        if let Some(exc_code) = spec.exception_code {
            pdu.push(exc_code);
        } else {
            pdu.push(payload_bytes.first().copied().unwrap_or(1));
            if payload_bytes.len() > 1 {
                pdu.extend_from_slice(&payload_bytes[1..]);
            }
            consumed_payload = true;
        }
    } else if spec.is_response {
        pdu.push(func_code);
        match func_code {
            1 | 2 => {
                let coil_count = usize::from(spec.count.unwrap_or(1)).clamp(1, 2000);
                let byte_count = coil_count.div_ceil(8) as u8;
                let fill = (spec.value.unwrap_or(0) & 0xFF) as u8;
                pdu.push(byte_count);
                pdu.resize(pdu.len() + usize::from(byte_count), fill);
            }
            5 | 6 => {
                pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
                pdu.extend_from_slice(&spec.value.unwrap_or(0).to_be_bytes());
            }
            15 | 16 => {
                pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
                pdu.extend_from_slice(&spec.count.unwrap_or(1).to_be_bytes());
            }
            3 | 4 => {
                let reg_count = usize::from(spec.count.unwrap_or(1)).clamp(1, 125);
                let byte_count = (reg_count * 2) as u8;
                let reg_bytes = spec.value.unwrap_or(0).to_be_bytes();
                pdu.push(byte_count);
                for _ in 0..reg_count {
                    pdu.extend_from_slice(&reg_bytes);
                }
            }
            43 => {
                if payload_bytes.is_empty() {
                    pdu.extend_from_slice(&[0x0E, 0x01, 0x81, 0x00, 0x00, 0x00]);
                }
            }
            _ => {
                if payload_bytes.is_empty() {
                    let reg_count = usize::from(spec.count.unwrap_or(1)).clamp(1, 125);
                    let byte_count = (reg_count * 2) as u8;
                    let reg_bytes = spec.value.unwrap_or(0).to_be_bytes();
                    pdu.push(byte_count);
                    for _ in 0..reg_count {
                        pdu.extend_from_slice(&reg_bytes);
                    }
                }
            }
        }
    } else if matches!(func_code, 1..=4) {
        // Read function: Starting Address (2B) + Quantity of Coils/Registers (2B)
        pdu.push(func_code);
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        pdu.extend_from_slice(&spec.count.unwrap_or(1).to_be_bytes());
    } else if matches!(func_code, 5 | 6) {
        // Write Single: Address (2B) + Value (2B)
        pdu.push(func_code);
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        pdu.extend_from_slice(&spec.value.unwrap_or(0).to_be_bytes());
    } else if func_code == 15 {
        // Write Multiple Coils: Address (2B) + Quantity (2B) + Byte Count (1B) + Coil Bytes
        pdu.push(func_code);
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        if !payload_bytes.is_empty() {
            let chunk = &payload_bytes[..payload_bytes.len().min(250)];
            let byte_count = u8::try_from(chunk.len()).unwrap_or(250);
            let default_coils = u16::try_from(chunk.len() * 8)
                .unwrap_or(1968)
                .clamp(1, 1968);
            let coil_count = spec.count.unwrap_or(default_coils).clamp(1, 1968);
            pdu.extend_from_slice(&coil_count.to_be_bytes());
            pdu.push(byte_count);
            pdu.extend_from_slice(chunk);
            consumed_payload = true;
        } else {
            let coil_count = spec.count.unwrap_or(1).clamp(1, 1968);
            let byte_count = usize::from(coil_count).div_ceil(8) as u8;
            let fill = (spec.value.unwrap_or(0) & 0xFF) as u8;
            pdu.extend_from_slice(&coil_count.to_be_bytes());
            pdu.push(byte_count);
            pdu.resize(pdu.len() + usize::from(byte_count), fill);
        }
    } else if func_code == 16 {
        // Write Multiple Registers (FC 16): Address (2B) + Quantity (2B) + Byte Count (1B) + Registers
        pdu.push(func_code);
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        if !payload_bytes.is_empty() {
            let mut reg_data = payload_bytes[..payload_bytes.len().min(250)].to_vec();
            if (reg_data.len() & 1) != 0 && reg_data.len() < 250 {
                reg_data.push(0);
            }
            let byte_count = u8::try_from(reg_data.len()).unwrap_or(250);
            let default_regs = u16::try_from(reg_data.len().div_ceil(2))
                .unwrap_or(125)
                .clamp(1, 125);
            let reg_count = spec.count.unwrap_or(default_regs).clamp(1, 125);
            pdu.extend_from_slice(&reg_count.to_be_bytes());
            pdu.push(byte_count);
            pdu.extend_from_slice(&reg_data);
            consumed_payload = true;
        } else {
            let reg_count = spec.count.unwrap_or(1).clamp(1, 125);
            let byte_count = (usize::from(reg_count) * 2) as u8;
            let reg_bytes = spec.value.unwrap_or(0).to_be_bytes();
            pdu.extend_from_slice(&reg_count.to_be_bytes());
            pdu.push(byte_count);
            for _ in 0..reg_count {
                pdu.extend_from_slice(&reg_bytes);
            }
        }
    } else if matches!(func_code, 7 | 11 | 12 | 17) {
        pdu.push(func_code);
    } else if func_code == 8 {
        pdu.push(func_code);
        if payload_bytes.is_empty() {
            pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
            pdu.extend_from_slice(&spec.value.unwrap_or(0).to_be_bytes());
        }
    } else if func_code == 22 {
        pdu.push(func_code);
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        pdu.extend_from_slice(&spec.value.unwrap_or(0xFFFF).to_be_bytes());
        pdu.extend_from_slice(&spec.count.unwrap_or(0).to_be_bytes());
    } else if func_code == 43 {
        pdu.push(func_code);
        if payload_bytes.is_empty() {
            pdu.extend_from_slice(&[0x0E, 0x01, 0x00]); // MEI Read Device ID (Basic, Object 0)
        }
    } else {
        pdu.push(func_code);
        if payload_bytes.is_empty() {
            pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
            pdu.extend_from_slice(&spec.count.unwrap_or(1).to_be_bytes());
        }
    }

    if !consumed_payload && !payload_bytes.is_empty() {
        pdu.extend_from_slice(payload_bytes);
    }

    let length = u16::try_from(1 + pdu.len()).unwrap_or(u16::MAX); // unit_id (1B) + PDU length
    let mut pkt = Vec::with_capacity(7 + pdu.len());
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&proto_id.to_be_bytes());
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.push(unit_id);
    pkt.extend_from_slice(&pdu);
    pkt
}
