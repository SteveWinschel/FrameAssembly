//! Siemens S7 Communication (S7comm, ISO-on-TCP RFC 1006) wire payload builder.
//!
//! This module implements [`build_s7comm_payload`], which serializes an [`S7commSpec`]
//! AST specification into a Siemens SIMATIC S7comm frame encapsulated in ISO-on-TCP (RFC 1006) over
//! TCP port 102. It builds the S7 parameter and data blocks for `Setup_Communication` (`0xF0`),
//! `Read_Var` (`0x04` with `S7ANY` 10-byte item address specification), `Write_Var` (`0x05`),
//! `PLC_Control` (`0x28`), or `SZL` Userdata (`0x07`) parameters, prepends the 10-byte S7 header
//! (`0x32` magic, `rosctr`, `pduref`, parameter/data lengths), and wraps the result in a 3-byte
//! COTP DT Data PDU and 4-byte TPKT header.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Validates and normalizes an S7ANY memory area code, defaulting unknown codes to Data Block (`0x84`).
fn normalize_s7_area(area: Option<u8>) -> u8 {
    match area {
        Some(code @ (0x03 | 0x05..=0x07 | 0x1C..=0x1F | 0x80..=0x87)) => code,
        Some(_) | None => 0x84,
    }
}

/// Builds a Siemens S7comm packet payload on ISO-on-TCP (TPKT + COTP).
pub fn build_s7comm_payload(
    _ctx: &WireContext,
    spec: &S7commSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let rosctr_norm = spec
        .rosctr
        .unwrap_or("job")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let mut rosctr = match rosctr_norm.as_str() {
        "JOB" => 0x01u8,
        "ACK" => 0x02u8,
        "ACKDATA" | "RESPONSE" => 0x03u8,
        "USERDATA" => 0x07u8,
        _ => 0x01u8,
    };

    let default_func = if rosctr == 0x07 { "szl" } else { "setupcomm" };
    let func_norm = spec
        .func
        .unwrap_or(default_func)
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let is_userdata_szl = matches!(func_norm.as_str(), "SZL" | "USERDATA")
        || (rosctr == 0x07 && spec.func.is_none());
    let is_userdata_resp = rosctr == 0x02 || rosctr == 0x03;
    if is_userdata_szl {
        rosctr = 0x07;
    }

    let func_code = match func_norm.as_str() {
        "SETUPCOMM" => 0xF0u8,
        "READVAR" => 0x04u8,
        "WRITEVAR" => 0x05u8,
        "PLCCONTROL" => 0x28u8,
        "SZL" | "USERDATA" => 0x00u8,
        _ => 0xF0u8,
    };

    let pdu_ref = spec.pdu_ref.unwrap_or(1);
    let mut param = Vec::new();
    let mut data = Vec::new();

    if is_userdata_szl {
        // S7comm Userdata Read SZL parameter (8B request, 12B response) + 0xFF/0x09 data block
        if is_userdata_resp {
            param.extend_from_slice(&[
                0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
        } else {
            param.extend_from_slice(&[0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00]);
        }
        if payload_bytes.len() >= 4 && payload_bytes[0] == 0xFF && payload_bytes[1] == 0x09 {
            data.extend_from_slice(payload_bytes);
        } else {
            let default_szl = [0x00, 0x11, 0x00, 0x00]; // SZL-ID 0x0011 (Module Identification), Index 0
            let body = if payload_bytes.is_empty() {
                default_szl.as_slice()
            } else {
                payload_bytes
            };
            let byte_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
            data.push(0xFF); // Return code: Success
            data.push(0x09); // Transport size: Octet string (length in bytes)
            data.extend_from_slice(&byte_len.to_be_bytes());
            data.extend_from_slice(&body[..usize::from(byte_len)]);
        }
    } else if func_code == 0xF0 {
        // Setup Communication parameter (8 bytes)
        param.push(0xF0); // Function: Setup Communication
        param.push(0x00); // Reserved
        param.extend_from_slice(&1u16.to_be_bytes()); // Max AMQ Calling: 1
        param.extend_from_slice(&1u16.to_be_bytes()); // Max AMQ Called: 1
        param.extend_from_slice(&480u16.to_be_bytes()); // PDU Length: 480
        if !payload_bytes.is_empty() {
            data.extend_from_slice(payload_bytes);
        }
    } else if (func_code == 0x04 || func_code == 0x05) && rosctr == 0x03 {
        // Read/Write Var Ack_Data parameter (2 bytes: Function + Item count 1)
        param.push(func_code);
        param.push(0x01);
        if func_code == 0x04 {
            if payload_bytes.is_empty() {
                let byte_len = usize::from(spec.count.unwrap_or(1).max(1)).min(4096);
                let bit_len = u16::try_from(byte_len * 8).unwrap_or(u16::MAX);
                data.push(0xFF); // Return code: Success
                data.push(0x04); // Transport size: BYTE/WORD/DWORD (bits)
                data.extend_from_slice(&bit_len.to_be_bytes());
                data.resize(data.len() + byte_len, 0);
            } else if payload_bytes.len() >= 5
                && payload_bytes[0] == 0xFF
                && matches!(payload_bytes[1], 0x03 | 0x04 | 0x05 | 0x07 | 0x09)
            {
                data.extend_from_slice(payload_bytes);
            } else {
                let max_bytes = usize::from(u16::MAX / 8);
                let chunk = &payload_bytes[..payload_bytes.len().min(max_bytes)];
                let bit_len = u16::try_from(chunk.len() * 8).unwrap_or(u16::MAX);
                data.push(0xFF);
                data.push(0x04);
                data.extend_from_slice(&bit_len.to_be_bytes());
                data.extend_from_slice(chunk);
            }
        } else if payload_bytes.is_empty() {
            data.push(0xFF); // Write Var Ack_Data Item Return code: Success
        } else {
            data.extend_from_slice(payload_bytes);
        }
    } else if func_code == 0x04 || func_code == 0x05 {
        // Read/Write Var Job parameter (14 bytes)
        let item_count = spec.count.unwrap_or(1).max(1);
        param.push(func_code); // Function: Read Var (0x04) or Write Var (0x05)
        param.push(0x01); // Item count: 1
        param.push(0x12); // Variable spec syntax ID
        param.push(0x0A); // Length of item spec (10 bytes)
        param.push(0x10); // Syntax ID: S7ANY
        param.push(0x02); // Transport size: BYTE
        param.extend_from_slice(&item_count.to_be_bytes()); // Length
        param.extend_from_slice(&spec.db_num.unwrap_or(1).to_be_bytes()); // DB Number
        param.push(normalize_s7_area(spec.area)); // Validated S7ANY memory area
        let offset = spec.offset.unwrap_or(0) << 3; // Bit address offset
        param.push((offset >> 16) as u8);
        param.push((offset >> 8) as u8);
        param.push(offset as u8);

        if func_code == 0x05 {
            if payload_bytes.is_empty() {
                let byte_len = usize::from(item_count).min(4096);
                let bit_len = u16::try_from(byte_len * 8).unwrap_or(u16::MAX);
                data.push(0xFF);
                data.push(0x04);
                data.extend_from_slice(&bit_len.to_be_bytes());
                data.resize(data.len() + byte_len, 0);
            } else {
                let max_bytes = usize::from(u16::MAX / 8);
                let chunk = &payload_bytes[..payload_bytes.len().min(max_bytes)];
                let bit_len = u16::try_from(chunk.len() * 8).unwrap_or(u16::MAX);
                data.push(0xFF);
                data.push(0x04);
                data.extend_from_slice(&bit_len.to_be_bytes());
                data.extend_from_slice(chunk);
            }
        } else if !payload_bytes.is_empty() {
            data.extend_from_slice(payload_bytes);
        }
    } else {
        param.push(func_code);
        param.push(0x00);
        if !payload_bytes.is_empty() {
            data.extend_from_slice(payload_bytes);
        }
    }

    let param_len = u16::try_from(param.len()).unwrap_or(u16::MAX);
    let data_len = u16::try_from(data.len()).unwrap_or(u16::MAX);

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
    let total_len =
        u16::try_from(4 + cotp.len() + s7_hdr.len() + param.len() + data.len()).unwrap_or(u16::MAX);
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
