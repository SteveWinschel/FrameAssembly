//! Network Time Protocol v4 (NTPv4) (RFC 5905 / RFC 4330 (SNTP)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Network Time Protocol v4 (NTPv4) packets over UDP port 123. On the wire, the protocol uses a 48-byte fixed NTP packet header starting with packed 8-bit LI (2 bits) / VN (3 bits) / Mode (3 bits) byte, 8-bit Stratum, 8-bit Poll interval (log2 seconds), signed 8-bit Precision, 32-bit Root Delay, 32-bit Root Dispersion, 32-bit Reference ID (ASCII kiss-code or IPv4), and four 64-bit fixed-point timestamps (Reference, Origin, Receive, Transmit).
//! Every field in [`NtpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ntp [li <u8>] [vn <u8>] [mode <u8>] [stratum <u8>] [poll <u8>] [precision <i8>] [refid <str>] [txtimestamp <u64>]`

/// RFC 5905 Network Time Protocol specification.
///
/// Syntax mapping: `ntp [li <u8>] [vn <u8>] [mode <u8>] [stratum <u8>] [poll <u8>] [precision <i8>] [refid <str>] [txtimestamp <u64>]`
#[doc(alias = "ntp")]
#[doc(alias = "SNTP")]
#[doc(alias = "RFC 5905")]
#[doc(alias = "RFC5905")]
#[doc(alias = "li")]
#[doc(alias = "vn")]
#[doc(alias = "mode")]
#[doc(alias = "stratum")]
#[doc(alias = "poll")]
#[doc(alias = "precision")]
#[doc(alias = "refid")]
#[doc(alias = "txtimestamp")]
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
