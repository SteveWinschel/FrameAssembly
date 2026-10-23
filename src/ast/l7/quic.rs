//! QUIC protocol AST definitions.

/// RFC 9000 QUIC Transport Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuicSpec<'a> {
    /// Initial packet flag.
    pub is_initial: bool,
    /// 0-RTT packet flag.
    pub is_zero_rtt: bool,
    /// Handshake packet flag.
    pub is_handshake: bool,
    /// Retry packet flag.
    pub is_retry: bool,
    /// Short header packet flag.
    pub is_short: bool,
    /// Version number.
    pub version: Option<u32>,
    /// Destination Connection ID.
    pub dcid: Option<u64>,
    /// Source Connection ID.
    pub scid: Option<u64>,
    /// Token string.
    pub token: Option<&'a str>,
    /// Packet number.
    pub pkt_num: Option<u32>,
}
