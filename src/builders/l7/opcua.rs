//! OPC Unified Architecture (OPC UA, IEC 62541-6) Binary Protocol wire payload builder.
//!
//! This module implements [`build_opcua_payload`], which serializes an [`OpcuaSpec`] AST node into
//! an IEC 62541-6 OPC UA Connection Protocol (`UACP`) binary frame over TCP port 4840. Every packet
//! begins with the 8-byte UACP header (`HEL`/`ACK`/`OPN`/`CLO`/`MSG`/`ERR`, `ChunkType`, and
//! `MessageSize`), followed by buffer parameters, the `OPN` asymmetric security header, or
//! symmetric channel/sequence headers plus Service `ExpandedNodeId` (`OpenSecureChannelRequest`,
//! `CloseSecureChannelRequest`, `ReadRequest = 631`) and `RequestHeader`.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Encodes a 4-byte OPC UA FourByte `ExpandedNodeId` in namespace `0` (IEC 62541-6 §5.2.2.10).
fn push_service_node_id(out: &mut Vec<u8>, id: u16) {
    out.push(0x01); // FourByte NodeId encoding mask
    out.push(0x00); // Namespace index 0
    out.extend_from_slice(&id.to_le_bytes());
}

/// Encodes a minimal 29-byte OPC UA `RequestHeader` (IEC 62541-4 §7.28).
fn push_request_header(out: &mut Vec<u8>, req_handle: u32) {
    out.extend_from_slice(&[0x00, 0x00]); // AuthenticationToken: TwoByte NodeId(0)
    out.extend_from_slice(&0i64.to_le_bytes()); // Timestamp: DateTime(0)
    out.extend_from_slice(&req_handle.to_le_bytes()); // RequestHandle
    out.extend_from_slice(&0u32.to_le_bytes()); // ReturnDiagnostics: 0
    out.extend_from_slice(&(-1i32).to_le_bytes()); // AuditEntryId: null String
    out.extend_from_slice(&10_000u32.to_le_bytes()); // TimeoutHint: 10000 ms
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // AdditionalHeader: null ExtensionObject
}

/// Encodes an IEC 62541-6 String `NodeId` (`0x03`, 2-byte LE namespace index, 4-byte length, UTF-8).
fn push_string_node_id(out: &mut Vec<u8>, ns: u16, identifier: &str) {
    let id_bytes = identifier.as_bytes();
    out.push(0x03); // String NodeId encoding mask
    out.extend_from_slice(&ns.to_le_bytes());
    out.extend_from_slice(&u32::try_from(id_bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(id_bytes);
}

/// Builds an OPC UA Binary Protocol packet payload.
pub fn build_opcua_payload(
    _ctx: &WireContext,
    spec: &OpcuaSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let default_msg = if spec.node_id.is_some() && spec.endpoint_url.is_none() {
        "msg"
    } else {
        "hel"
    };
    let msg_type_str = spec
        .msg_type
        .unwrap_or(default_msg)
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let msg_bytes = match msg_type_str.as_str() {
        "HEL" => *b"HEL",
        "ACK" => *b"ACK",
        "OPN" => *b"OPN",
        "CLO" => *b"CLO",
        "MSG" => *b"MSG",
        "ERR" => *b"ERR",
        _ => *b"HEL",
    };

    let chunk_type = spec.chunk_type.unwrap_or('F').to_ascii_uppercase() as u8;
    let req_id = spec.req_id.unwrap_or(1);

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
            body.extend_from_slice(&u32::try_from(url_bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
            body.extend_from_slice(url_bytes);
        } else {
            body.extend_from_slice(&0u32.to_le_bytes()); // EndpointUrl length 0
        }
        if let Some(node_id) = spec.node_id {
            let nid_bytes = node_id.as_bytes();
            body.extend_from_slice(&u32::try_from(nid_bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
            body.extend_from_slice(nid_bytes);
        }
    } else if msg_bytes == *b"ACK" {
        // Acknowledge Message Body (20 bytes)
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&16777216u32.to_le_bytes());
        body.extend_from_slice(&5000u32.to_le_bytes());
    } else if msg_bytes == *b"ERR" {
        // Error Message Body (BadUnexpectedError 0x80010000 + null Reason string -1i32)
        body.extend_from_slice(&0x8001_0000u32.to_le_bytes());
        body.extend_from_slice(&(-1i32).to_le_bytes());
    } else if msg_bytes == *b"OPN" {
        // OpenSecureChannel: SecureChannelId + AsymmetricAlgorithmSecurityHeader + SequenceHeader
        let policy = b"http://opcfoundation.org/UA/SecurityPolicy#None";
        body.extend_from_slice(&spec.secure_channel_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&(policy.len() as u32).to_le_bytes());
        body.extend_from_slice(policy);
        body.extend_from_slice(&(-1i32).to_le_bytes()); // SenderCertificate: null ByteString
        body.extend_from_slice(&(-1i32).to_le_bytes()); // ReceiverCertificateThumbprint: null ByteString
        body.extend_from_slice(&spec.seq_num.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&req_id.to_le_bytes());

        if payload_bytes.is_empty() {
            push_service_node_id(&mut body, 446); // OpenSecureChannelRequest (446)
            push_request_header(&mut body, req_id);
            body.extend_from_slice(&0u32.to_le_bytes()); // ClientProtocolVersion: 0
            body.extend_from_slice(&0i32.to_le_bytes()); // RequestType: Issue (0)
            body.extend_from_slice(&1i32.to_le_bytes()); // SecurityMode: None (1)
            body.extend_from_slice(&(-1i32).to_le_bytes()); // ClientNonce: null ByteString
            body.extend_from_slice(&3_600_000u32.to_le_bytes()); // RequestedLifetime: 3600000 ms
        }
    } else if msg_bytes == *b"CLO" {
        // CloseSecureChannel: SymmetricSecurityHeader + SequenceHeader + CloseSecureChannelRequest (452)
        body.extend_from_slice(&spec.secure_channel_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.token_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.seq_num.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&req_id.to_le_bytes());

        if payload_bytes.is_empty() {
            push_service_node_id(&mut body, 452); // CloseSecureChannelRequest (452)
            push_request_header(&mut body, req_id);
        }
    } else {
        // MSG: SymmetricSecurityHeader + SequenceHeader + ReadRequest (631) + RequestHeader
        body.extend_from_slice(&spec.secure_channel_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.token_id.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&spec.seq_num.unwrap_or(1).to_le_bytes());
        body.extend_from_slice(&req_id.to_le_bytes());

        if payload_bytes.is_empty() {
            push_service_node_id(&mut body, 631); // ReadRequest (631)
            push_request_header(&mut body, req_id);
            body.extend_from_slice(&0.0f64.to_le_bytes()); // MaxAge: 0.0
            body.extend_from_slice(&2i32.to_le_bytes()); // TimestampsToReturn: Both (2)
            if let Some(node_id) = spec.node_id {
                body.extend_from_slice(&1i32.to_le_bytes()); // NodesToRead array length: 1
                push_string_node_id(&mut body, 0, node_id);
                body.extend_from_slice(&13u32.to_le_bytes()); // AttributeId: Value (13)
                body.extend_from_slice(&(-1i32).to_le_bytes()); // IndexRange: null String
                body.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]); // DataEncoding: null QualifiedName
            } else {
                body.extend_from_slice(&0i32.to_le_bytes()); // NodesToRead array length: 0
            }
        }
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let total_size = u32::try_from(8usize.saturating_add(body.len())).unwrap_or(u32::MAX);
    let mut pkt = Vec::with_capacity(8 + body.len());
    pkt.extend_from_slice(&msg_bytes);
    pkt.push(chunk_type);
    pkt.extend_from_slice(&total_size.to_le_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
