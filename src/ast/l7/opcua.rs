//! OPCUA protocol AST definitions.

/// OPC Unified Architecture Binary Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpcuaSpec<'a> {
    /// Message type string (e.g. HEL, ACK, MSG).
    pub msg_type: Option<&'a str>,
    /// Chunk type character ('F', 'C', 'A').
    pub chunk_type: Option<char>,
    /// Secure channel ID.
    pub secure_channel_id: Option<u32>,
    /// Security token ID.
    pub token_id: Option<u32>,
    /// Sequence number.
    pub seq_num: Option<u32>,
    /// Request ID.
    pub req_id: Option<u32>,
    /// Endpoint URL string.
    pub endpoint_url: Option<&'a str>,
    /// Node identifier string.
    pub node_id: Option<&'a str>,
}
