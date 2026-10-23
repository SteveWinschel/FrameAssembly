//! PTP protocol AST definitions.

/// IEEE 1588 Precision Time Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PtpSpec<'a> {
    /// Message type name (e.g. SYNC, DELAY_REQ).
    pub msg_type: Option<&'a str>,
    /// Domain number.
    pub domain: Option<u8>,
    /// Sequence identifier.
    pub seq_id: Option<u16>,
    /// Clock identity string or hex bytes.
    pub clock_id: Option<&'a str>,
}
