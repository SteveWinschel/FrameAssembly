//! Siemens S7 Communication (S7comm, ISO-on-TCP RFC 1006) wire payload builder.
//!
//! This module implements [`build_s7comm_payload`], which serializes an [`S7commSpec`]
//! AST specification into a Siemens SIMATIC S7comm frame encapsulated in ISO-on-TCP (RFC 1006) over
//! TCP port 102. It builds the S7 parameter and data blocks for `Setup_Communication` (`0xF0`),
//! `Read_Var` (`0x04` with `S7ANY` 10-byte item address specification), `Write_Var` (`0x05`), or
//! `PLC_Control` (`0x28`), prepends the 10-byte S7 header (`0x32` magic, `ROSCTR`, `PDU_REF`,
//! parameter/data lengths), and wraps the result in a 3-byte COTP DT Data PDU and 4-byte TPKT header.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds a Siemens S7comm packet payload on ISO-on-TCP (TPKT + COTP).
pub fn build_s7comm_payload(
    _ctx: &WireContext,
    spec: &S7commSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let rosctr = match spec.rosctr.unwrap_or("JOB").to_ascii_uppercase().as_str() {
        "JOB" => 0x01u8,
        "ACK" => 0x02u8,
        "ACK_DATA" => 0x03u8,
        "USERDATA" => 0x07u8,
        _ => 0x01u8,
    };

    let func_code = match spec.func.unwrap_or("SETUP_COMM").to_ascii_uppercase().as_str() {
        "SETUP_COMM" => 0xF0u8,
        "READ_VAR" => 0x04u8,
        "WRITE_VAR" => 0x05u8,
        "PLC_CONTROL" => 0x28u8,
        _ => 0xF0u8,
    };

    let pdu_ref = spec.pdu_ref.unwrap_or(1);
    let mut param = Vec::new();

    if func_code == 0xF0 {
        // Setup Communication parameter (8 bytes)
        param.push(0xF0); // Function: Setup Communication
        param.push(0x00); // Reserved
        param.extend_from_slice(&1u16.to_be_bytes()); // Max AMQ Calling: 1
        param.extend_from_slice(&1u16.to_be_bytes()); // Max AMQ Called: 1
        param.extend_from_slice(&480u16.to_be_bytes()); // PDU Length: 480
    } else if func_code == 0x04 || func_code == 0x05 {
        // Read/Write Var parameter (14 bytes)
        param.push(func_code); // Function: Read Var (0x04) or Write Var (0x05)
        param.push(0x01); // Item count: 1
        param.push(0x12); // Variable spec syntax ID
        param.push(0x0A); // Length of item spec (10 bytes)
        param.push(0x10); // Syntax ID: S7ANY
        param.push(0x02); // Transport size: BYTE
        param.extend_from_slice(&spec.count.unwrap_or(1).to_be_bytes()); // Length
        param.extend_from_slice(&spec.db_num.unwrap_or(1).to_be_bytes()); // DB Number
        param.push(spec.area.unwrap_or(0x84)); // Area: DB (0x84)
        let offset = spec.offset.unwrap_or(0) << 3; // Bit address offset
        param.push((offset >> 16) as u8);
        param.push((offset >> 8) as u8);
        param.push(offset as u8);
    } else {
        param.push(func_code);
        param.push(0x00);
    }

    let mut data = Vec::new();
    if !payload_bytes.is_empty() {
        data.extend_from_slice(payload_bytes);
    }

    let param_len = param.len() as u16;
    let data_len = data.len() as u16;

    // S7 Header (10 bytes for JOB/USERDATA, 12 bytes for ACK/ACK_DATA)
    let mut s7_hdr = Vec::with_capacity(12);
    s7_hdr.push(0x32); // Protocol ID: S7 (0x32)
    s7_hdr.push(rosctr);
    s7_hdr.extend_from_slice(&0u16.to_be_bytes()); // Redundancy Identification
    s7_hdr.extend_from_slice(&pdu_ref.to_be_bytes()); // PDU Reference
    s7_hdr.extend_from_slice(&param_len.to_be_bytes());
    s7_hdr.extend_from_slice(&data_len.to_be_bytes());
    if rosctr == 0x02 || rosctr == 0x03 {
        s7_hdr.push(0x00); // Error Class
        s7_hdr.push(0x00); // Error Code
    }

    // COTP DT Data PDU (3 bytes)
    let cotp = [0x02, 0xF0, 0x80]; // Length 2, PDU Type 0xF0 (DT Data), TPDU-NR / EOT 0x80

    // TPKT (4 bytes)
    let total_len = (4 + cotp.len() + s7_hdr.len() + param.len() + data.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.push(3); // TPKT Version 3
    pkt.push(0); // Reserved
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&cotp);
    pkt.extend_from_slice(&s7_hdr);
    pkt.extend_from_slice(&param);
    pkt.extend_from_slice(&data);
    pkt
}
