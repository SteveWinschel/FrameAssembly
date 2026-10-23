//! Stream Control Transmission Protocol (SCTP) AST definitions.

use alloc::string::String;

/// SCTP transport parameters override.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SctpParams {
    /// Verification Tag.
    pub vtag: Option<u32>,
    /// Stream Identifier.
    pub stream: Option<u16>,
    /// Stream Sequence Number.
    pub ssn: Option<u16>,
    /// Payload Protocol Identifier.
    pub ppid: Option<u32>,
    /// Chunk type name.
    pub chunk: Option<String>,
}
