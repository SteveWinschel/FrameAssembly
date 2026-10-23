//! NTP protocol AST definitions.

/// RFC 5905 Network Time Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtpSpec<'a> {
    /// Leap Indicator (0..=3).
    pub li: Option<u8>,
    /// Version Number (1..=4).
    pub vn: Option<u8>,
    /// Mode (0..=7).
    pub mode: Option<u8>,
    /// Stratum (0..=16).
    pub stratum: Option<u8>,
    /// Poll interval in log2 seconds.
    pub poll: Option<u8>,
    /// Precision in log2 seconds.
    pub precision: Option<i8>,
    /// Reference Identifier string.
    pub refid: Option<&'a str>,
    /// Transmit Timestamp (64 bits).
    pub tx_timestamp: Option<u64>,
}
