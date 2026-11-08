//! OPC Unified Architecture Binary TCP Protocol (OPC UA, IEC 62541-6) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `OPCUA` binary TCP conversation
//! messages (`HEL`, `ACK`, `OPN`, `CLO`, `MSG`, `ERR`) with chunk types (`'F'`, `'C'`, `'A'`) over
//! TCP (port `4840` and custom OPC UA server ports matching the 8-byte message header and exact
//! frame length). It decodes `endpoint_url`, `secure_channel_id`, `token_id`, `seq_num`, `reqid`,
//! and string `node_id` fields.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Dissects an `OPCUA` binary TCP conversation message (`HEL`, `ACK`, `OPN`, `CLO`, `MSG`, `ERR`).
pub(crate) fn dissect_opcua(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp)
        || payload.len() < 24
        || !matches!(payload[3], b'F' | b'C' | b'A')
    {
        return None;
    }
    let total_len = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if total_len != payload.len() {
        return None;
    }
    let msg_type = &payload[0..3];
    let chunk = payload[3] as char;
    let body = &payload[8..];
    let mut tokens = String::from("opcua");

    match msg_type {
        b"HEL" => {}
        b"ACK" => tokens.push_str(" msg_type \"ACK\""),
        b"OPN" => tokens.push_str(" msg_type \"OPN\""),
        b"CLO" => tokens.push_str(" msg_type \"CLO\""),
        b"MSG" => {}
        b"ERR" => tokens.push_str(" msg_type \"ERR\""),
        _ => return None,
    }
    if chunk != 'F' {
        tokens.push_str(&format!(" chunk_type \"{chunk}\""));
    }

    let residual = match msg_type {
        b"HEL" => {
            let fixed = [
                0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 136, 19, 0, 0,
            ];
            if body.len() < 24 || body[0..20] != fixed {
                return None;
            }
            let ulen = u32::from_le_bytes([body[20], body[21], body[22], body[23]]) as usize;
            if body.len() < 24 + ulen {
                return None;
            }
            if ulen > 0 {
                let url = core::str::from_utf8(&body[24..24 + ulen]).ok()?;
                if !is_valid_raw_str(url) {
                    return None;
                }
                tokens.push_str(&format!(" endpoint_url \"{url}\""));
            }
            &body[24 + ulen..]
        }
        b"ACK" => {
            let fixed = [
                0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 136, 19, 0, 0,
            ];
            if body.len() < 20 || body[0..20] != fixed {
                return None;
            }
            &body[20..]
        }
        _ => {
            if body.len() < 16 {
                return None;
            }
            let sc_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let tok_id = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let seq = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
            let req = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
            if sc_id != 1 {
                tokens.push_str(&format!(" secure_channel_id {sc_id}"));
            }
            if tok_id != 1 {
                tokens.push_str(&format!(" token_id {tok_id}"));
            }
            if seq != 1 {
                tokens.push_str(&format!(" seq_num {seq}"));
            }
            if req != 1 {
                tokens.push_str(&format!(" reqid {req}"));
            }
            let after_hdr = &body[16..];
            if after_hdr.len() >= 6 && &after_hdr[0..2] == b"\x03\x00" {
                let nlen =
                    u32::from_le_bytes([after_hdr[2], after_hdr[3], after_hdr[4], after_hdr[5]])
                        as usize;
                if after_hdr.len() >= 6 + nlen
                    && let Ok(nid) = core::str::from_utf8(&after_hdr[6..6 + nlen])
                    && is_valid_raw_str(nid)
                {
                    tokens.push_str(&format!(" node_id \"{nid}\""));
                    &after_hdr[6 + nlen..]
                } else {
                    if msg_type == b"MSG" {
                        tokens.push_str(" msg_type \"MSG\"");
                    }
                    after_hdr
                }
            } else {
                if msg_type == b"MSG" {
                    tokens.push_str(" msg_type \"MSG\"");
                }
                after_hdr
            }
        }
    };

    Some(ProtocolDissection {
        protocol: Protocol::Opcua,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
