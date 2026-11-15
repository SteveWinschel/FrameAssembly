//! OPC Unified Architecture Binary TCP Protocol (OPC UA, IEC 62541-6) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `opcua` binary TCP conversation
//! messages (`HEL`, `ACK`, `OPN`, `CLO`, `MSG`, `ERR`) with chunk types (`'F'`, `'C'`, `'A'`) over
//! TCP (port `4840` and custom OPC UA server ports matching the 8-byte message header and exact
//! frame length). It decodes `endpointurl`, `securechannelid`, `tokenid`, `seqnum`, `reqid`,
//! and string `nodeid` fields.

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

/// Canonical 59-byte OPC UA `AsymmetricAlgorithmSecurityHeader` for `SecurityPolicy#None` with null certificates.
const ASYM_SEC_HDR_NONE: &[u8; 59] = b"\x2f\x00\x00\x00http://opcfoundation.org/UA/SecurityPolicy#None\xff\xff\xff\xff\xff\xff\xff\xff";

/// Parses an optional `[0x03, 0x00, len_le(4B), utf8...]` String `NodeId` suffix and appends `nodeid` to `tokens`.
fn parse_optional_node_id<'a>(
    after_hdr: &'a [u8],
    is_msg: bool,
    tokens: &mut String,
) -> &'a [u8] {
    if after_hdr.len() >= 6 && &after_hdr[0..2] == b"\x03\x00" {
        let raw_nlen = u32::from_le_bytes([after_hdr[2], after_hdr[3], after_hdr[4], after_hdr[5]]);
        if raw_nlen != 0xFFFF_FFFF
            && let Some(nid_end) = 6usize.checked_add(raw_nlen as usize)
            && after_hdr.len() >= nid_end
            && let Ok(nid) = core::str::from_utf8(&after_hdr[6..nid_end])
            && is_valid_raw_str(nid)
        {
            tokens.push_str(&format!(" nodeid \"{nid}\""));
            return &after_hdr[nid_end..];
        }
    }
    if is_msg {
        tokens.push_str(" msgtype \"msg\"");
    }
    after_hdr
}

/// Dissects an `opcua` binary TCP conversation message (`HEL`, `ACK`, `OPN`, `CLO`, `MSG`, `ERR`).
pub(crate) fn dissect_opcua(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp)
        || payload.len() < 16
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
        b"ACK" => tokens.push_str(" msgtype \"ack\""),
        b"OPN" => tokens.push_str(" msgtype \"opn\""),
        b"CLO" => tokens.push_str(" msgtype \"clo\""),
        b"MSG" => {}
        b"ERR" => tokens.push_str(" msgtype \"err\""),
        _ => return None,
    }
    if chunk != 'F' {
        tokens.push_str(&format!(" chunktype \"{}\"", chunk.to_ascii_lowercase()));
    }

    let residual = match msg_type {
        b"HEL" => {
            let fixed = [
                0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 136, 19, 0, 0,
            ];
            if body.len() < 24 || body[0..20] != fixed {
                return None;
            }
            let raw_ulen = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
            if raw_ulen == 0xFFFF_FFFF {
                return None;
            }
            let url_end = 24usize.checked_add(raw_ulen as usize)?;
            if body.len() < url_end {
                return None;
            }
            if raw_ulen > 0 {
                let url = core::str::from_utf8(&body[24..url_end]).ok()?;
                if !is_valid_raw_str(url) {
                    return None;
                }
                tokens.push_str(&format!(" endpointurl \"{url}\""));
            }
            &body[url_end..]
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
        b"ERR" => body.strip_prefix(&[0x00, 0x00, 0x01, 0x80, 0xFF, 0xFF, 0xFF, 0xFF])?,
        b"OPN" => {
            if body.len() < 71 || &body[4..63] != ASYM_SEC_HDR_NONE {
                return None;
            }
            let sc_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let seq = u32::from_le_bytes([body[63], body[64], body[65], body[66]]);
            let req = u32::from_le_bytes([body[67], body[68], body[69], body[70]]);
            if sc_id != 1 {
                tokens.push_str(&format!(" securechannelid {sc_id}"));
            }
            if seq != 1 {
                tokens.push_str(&format!(" seqnum {seq}"));
            }
            if req != 1 {
                tokens.push_str(&format!(" reqid {req}"));
            }
            parse_optional_node_id(&body[71..], false, &mut tokens)
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
                tokens.push_str(&format!(" securechannelid {sc_id}"));
            }
            if tok_id != 1 {
                tokens.push_str(&format!(" tokenid {tok_id}"));
            }
            if seq != 1 {
                tokens.push_str(&format!(" seqnum {seq}"));
            }
            if req != 1 {
                tokens.push_str(&format!(" reqid {req}"));
            }
            parse_optional_node_id(&body[16..], msg_type == b"MSG", &mut tokens)
        }
    };

    Some(ProtocolDissection {
        protocol: Protocol::Opcua,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
