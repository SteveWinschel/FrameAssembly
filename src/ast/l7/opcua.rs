//! OPC Unified Architecture (OPC UA, IEC 62541-6) Binary Protocol AST definitions.
//!
//! This module defines [`OpcuaSpec`], the zero-copy AST representation of an IEC 62541-6 OPC
//! Unified Architecture (OPC UA) Connection Protocol (`UACP`) binary frame over TCP port 4840.
//! On the wire, an OPC UA frame starts with a 3-byte ASCII MessageType (`HEL`, `ACK`, `ERR`,
//! `OPN`, `CLO`, or `MSG`), a 1-byte ChunkType (`'F'` Final, `'C'` Intermediate, `'A'` Aborted),
//! and a 32-bit little-endian MessageSize, followed by either connection parameters (`EndpointUrl`)
//! or SecureChannel/Sequence headers (`SecureChannelId`, `TokenId`, `SequenceNumber`, `RequestId`)
//! and an ExpandedNodeId service body. Canonical `.fasm` syntax:
//! `OPCUA [MSG_TYPE <str>] [CHUNK_TYPE <str>] [SECURE_CHANNEL_ID <u32>] [TOKEN_ID <u32>] [SEQ_NUM <u32>] [REQID <u32>] [ENDPOINT_URL <str>] [NODE_ID <str>]`.

/// IEC 62541-6 OPC Unified Architecture (OPC UA) Binary Protocol specification.
///
/// Syntax mapping: `OPCUA [MSG_TYPE <str>] [CHUNK_TYPE <str>] [SECURE_CHANNEL_ID <u32>] [TOKEN_ID <u32>] [SEQ_NUM <u32>] [REQID <u32>] [ENDPOINT_URL <str>] [NODE_ID <str>]`
#[doc(alias = "OPCUA")]
#[doc(alias = "OPC UA")]
#[doc(alias = "IEC 62541")]
#[doc(alias = "4840")]
#[doc(alias = "MSG_TYPE")]
#[doc(alias = "CHUNK_TYPE")]
#[doc(alias = "SECURE_CHANNEL_ID")]
#[doc(alias = "TOKEN_ID")]
#[doc(alias = "SEQ_NUM")]
#[doc(alias = "REQID")]
#[doc(alias = "ENDPOINT_URL")]
#[doc(alias = "NODE_ID")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpcuaSpec<'a> {
    /// 3-character UACP message type (`MSG_TYPE <str>`, e.g., `"HEL"`, `"ACK"`, `"OPN"`, `"CLO"`, `"MSG"`, `"ERR"`).
    pub msg_type: Option<&'a str>,
    /// Single-character chunking indicator (`CHUNK_TYPE <str>`, `'F'`, `'C'`, or `'A'`, default `'F'`).
    pub chunk_type: Option<char>,
    /// 32-bit SecureChannel identifier (`SECURE_CHANNEL_ID <u32>`, default `1`).
    pub secure_channel_id: Option<u32>,
    /// 32-bit Security Token identifier (`TOKEN_ID <u32>`, default `1`).
    pub token_id: Option<u32>,
    /// 32-bit chunk Sequence Number (`SEQ_NUM <u32>`, default `1`).
    pub seq_num: Option<u32>,
    /// 32-bit service call Request ID (`REQID <u32>`, default `1`).
    pub req_id: Option<u32>,
    /// Server discovery URL for `HEL` messages (`ENDPOINT_URL <str>`, default `"opc.tcp://localhost:4840"`).
    pub endpoint_url: Option<&'a str>,
    /// Target NodeId string for `MSG` service requests (`NODE_ID <str>`).
    pub node_id: Option<&'a str>,
}
