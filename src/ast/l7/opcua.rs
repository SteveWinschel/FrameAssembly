//! OPC Unified Architecture (OPC UA, IEC 62541-6) Binary Protocol AST definitions.
//!
//! This module defines [`OpcuaSpec`], the zero-copy AST representation of an IEC 62541-6 OPC
//! Unified Architecture (OPC UA) Connection Protocol (`UACP`) binary frame over TCP port 4840.
//! On the wire, an OPC UA frame starts with a 3-byte ASCII MessageType (`HEL`, `ack`, `err`,
//! `OPN`, `CLO`, or `msg`), a 1-byte ChunkType (`'F'` Final, `'C'` Intermediate, `'A'` Aborted),
//! and a 32-bit little-endian MessageSize, followed by either connection parameters (`EndpointUrl`)
//! or SecureChannel/Sequence headers (`SecureChannelId`, `TokenId`, `SequenceNumber`, `RequestId`)
//! and an ExpandedNodeId service body. Canonical `.frasm` syntax:
//! `opcua [msgtype <str>] [chunktype <str>] [securechannelid <u32>] [tokenid <u32>] [seqnum <u32>] [reqid <u32>] [endpointurl <str>] [nodeid <str>]`.

/// IEC 62541-6 OPC Unified Architecture (OPC UA) Binary Protocol specification.
///
/// Syntax mapping: `opcua [msgtype <str>] [chunktype <str>] [securechannelid <u32>] [tokenid <u32>] [seqnum <u32>] [reqid <u32>] [endpointurl <str>] [nodeid <str>]`
#[doc(alias = "opcua")]
#[doc(alias = "OPC UA")]
#[doc(alias = "IEC 62541")]
#[doc(alias = "4840")]
#[doc(alias = "msgtype")]
#[doc(alias = "chunktype")]
#[doc(alias = "securechannelid")]
#[doc(alias = "tokenid")]
#[doc(alias = "seqnum")]
#[doc(alias = "reqid")]
#[doc(alias = "endpointurl")]
#[doc(alias = "nodeid")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpcuaSpec<'a> {
    /// 3-character UACP message type (`msgtype <str>`, e.g., `"HEL"`, `"ACK"`, `"OPN"`, `"CLO"`, `"MSG"`, `"ERR"`).
    pub msg_type: Option<&'a str>,
    /// Single-character chunking indicator (`chunktype <str>`, `'F'`, `'C'`, or `'A'`, default `'F'`).
    pub chunk_type: Option<char>,
    /// 32-bit SecureChannel identifier (`securechannelid <u32>`, default `1`).
    pub secure_channel_id: Option<u32>,
    /// 32-bit Security Token identifier (`tokenid <u32>`, default `1`).
    pub token_id: Option<u32>,
    /// 32-bit chunk Sequence Number (`seqnum <u32>`, default `1`).
    pub seq_num: Option<u32>,
    /// 32-bit service call Request ID (`reqid <u32>`, default `1`).
    pub req_id: Option<u32>,
    /// Server discovery URL for `HEL` messages (`endpointurl <str>`, default `"opc.tcp://localhost:4840"`).
    pub endpoint_url: Option<&'a str>,
    /// Target NodeId string for `msg` service requests (`nodeid <str>`).
    pub node_id: Option<&'a str>,
}
