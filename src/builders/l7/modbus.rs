//! Modbus TCP Application Protocol v1.1b3 (MBAP + PDU) wire payload builder.
//!
//! This module implements [`build_modbus_payload`], which serializes a [`ModbusSpec`]
//! AST node into a Modbus TCP Application Data Unit (ADU) over TCP or UDP port 502. It constructs
//! the 7-byte MBAP header (16-bit Transaction ID, 16-bit Protocol ID `0x0000`, 16-bit Length, and
//! 8-bit Unit ID) followed by the 1-byte Function Code (`0x01..=0x06`, `0x10`) and either a 4-byte
//! request body (`addr`, `count_or_val`) or a byte-counted response body when `IS_RESPONSE` is set.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a Modbus TCP/UDP packet payload with 7-byte MBAP header.
pub fn build_modbus_payload(
    _ctx: &WireContext,
    spec: &ModbusSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let txid = spec.txid.unwrap_or(1);
    let proto_id = spec.proto_id.unwrap_or(0);
    let unit_id = spec.unitid.unwrap_or(1);

    let func_code: u8 = match spec.func.unwrap_or("READ_HOLDING_REGISTERS").to_ascii_uppercase().as_str() {
        "READ_COILS" => 1,
        "READ_DISCRETE_INPUTS" => 2,
        "READ_HOLDING_REGISTERS" => 3,
        "READ_INPUT_REGISTERS" => 4,
        "WRITE_SINGLE_COIL" => 5,
        "WRITE_SINGLE_REGISTER" => 6,
        "WRITE_MULTIPLE_REGISTERS" => 16,
        _ => 3,
    };

    let mut pdu = Vec::new();
    pdu.push(func_code);

    if spec.is_response {
        let count = spec.count.unwrap_or(1);
        let byte_count = (count * 2) as u8;
        pdu.push(byte_count);
        for _ in 0..count {
            pdu.extend_from_slice(&spec.value.unwrap_or(0).to_be_bytes());
        }
    } else if func_code == 1 || func_code == 2 || func_code == 3 || func_code == 4 {
        // Read function: Starting Address (2B) + Quantity of Registers (2B)
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        pdu.extend_from_slice(&spec.count.unwrap_or(1).to_be_bytes());
    } else if func_code == 5 || func_code == 6 {
        // Write Single: Address (2B) + Value (2B)
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        pdu.extend_from_slice(&spec.value.unwrap_or(0).to_be_bytes());
    } else {
        let count = spec.count.unwrap_or(1);
        pdu.extend_from_slice(&spec.addr.unwrap_or(0).to_be_bytes());
        pdu.extend_from_slice(&count.to_be_bytes());
        if let Some(val) = spec.value {
            pdu.push((count * 2) as u8);
            for _ in 0..count {
                pdu.extend_from_slice(&val.to_be_bytes());
            }
        }
    }

    if !payload_bytes.is_empty() {
        pdu.extend_from_slice(payload_bytes);
    }

    let length = (1 + pdu.len()) as u16; // unit_id (1B) + PDU length
    let mut pkt = Vec::with_capacity(7 + pdu.len());
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&proto_id.to_be_bytes());
    pkt.extend_from_slice(&length.to_be_bytes());
    pkt.push(unit_id);
    pkt.extend_from_slice(&pdu);
    pkt
}
