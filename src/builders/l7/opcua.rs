//! OPC Unified Architecture (OPC UA, IEC 62541-6) Binary Protocol wire payload builder.
//!
//! This module implements [`build_opcua_payload`], which serializes an [`OpcuaSpec`]
//! AST node into an IEC 62541-6 OPC UA Connection Protocol (`UACP`) binary frame over TCP port
//! 4840. Every packet begins with the 8-byte UACP header (3-byte ASCII `MessageType` `HEL`/`ACK`/
//! `OPN`/`CLO`/`MSG`/`ERR`, 1-byte `ChunkType` `'F'`/`'C'`/`'A'`, and 32-bit little-endian
//! `MessageSize`) followed by connection buffer parameters (`EndpointUrl`) or `SecureChannelId`,
//! `TokenId`, `SequenceNumber`, `RequestId`, and `NodeId` service body fields.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an OPC UA Binary Protocol packet payload.
pub fn build_opcua_payload(
    _ctx: &WireContext,
    spec: &OpcuaSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let default_msg = if spec.node_id.is_some() && spec.endpoint_url.is_none() {
        "MSG"
    } else {
        "HEL"
    };
    let msg_type_str = spec.msg_type.unwrap_or(default_msg).to_ascii_uppercase();
    let msg_bytes = match msg_type_str.as_str() {
        "HEL" => *b"HEL",
        "ACK" => *b"ACK",
        "OPN" => *b"OPN",
        "CLO" => *b"CLO",
        "MSG" => *b"MSG",
        "ERR" => *b"ERR",
        _ => *b"HEL",
    };

    let chunk_type = spec.chunk_type.unwrap_or('F') as u8;

    let mut body = Vec::new();
    if msg_bytes == *b"HEL" {
        // Hello Message Body (20-byte buffer sizes + 4-byte length + EndpointUrl)
        body.extend_from_slice(&0u32.to_le_bytes()); // Version 0
        body.extend_from_slice(&65536u32.to_le_bytes()); // ReceiveBufferSize
        body.extend_from_slice(&65536u32.to_le_bytes()); // SendBufferSize
        body.extend_from_slice(&16777216u32.to_le_bytes()); // MaxMessageSize (16MB)
        body.extend_from_slice(&5000u32.to_le_bytes()); // MaxChunkCount
        if let Some(url) = spec.endpoint_url {
            let url_bytes = url.as_bytes();
            body.extend_from_slice(&(url_bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(url_bytes);
        } else {
            body.extend_from_slice(&0u32.to_le_bytes()); // EndpointUrl length 0
        }
        if let Some(node_id) = spec.node_id {
            let nid_bytes = node_id.as_bytes();
            body.extend_from_slice(&(nid_bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(nid_bytes);
        }
    } else if msg_bytes == *b"ACK" {
        // Acknowledge Message Body (20 bytes)
        body.extend_from_slice(&0u32.to_le_bytes()); // Version 0
        body.extend_from_slice(&65536u32.to_le_bytes()); // ReceiveBufferSize
        body.extend_from_slice(&65536u32.to_le_bytes()); // SendBufferSize
        body.extend_from_slice(&16777216u32.to_le_bytes()); // MaxMessageSize
        body.extend_from_slice(&5000u32.to_le_bytes()); // MaxChunkCount
    } else {
        // Message / OpenSecureChannel Body
        body.extend_from_slice(&spec.secure_channel_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.token_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.seq_num.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.req_id.unwrap_or(1).to_le_bytes());
        if let Some(node_id) = spec.node_id {
            let nid_bytes = node_id.as_bytes();
            body.push(0x03); // String NodeId encoding mask
            body.push(0x00); // Namespace index 0
            body.extend_from_slice(&(nid_bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(nid_bytes);
        }
        if let Some(url) = spec.endpoint_url {
            let url_bytes = url.as_bytes();
            body.extend_from_slice(&(url_bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(url_bytes);
        }
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let total_size = (8 + body.len()) as u32;
    let mut pkt = Vec::with_capacity(total_size as usize);
    pkt.extend_from_slice(&msg_bytes);
    pkt.push(chunk_type);
    pkt.extend_from_slice(&total_size.to_le_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
