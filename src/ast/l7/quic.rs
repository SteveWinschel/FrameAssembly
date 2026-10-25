//! QUIC UDP-Based Multiplexed and Secure Transport (RFC 9000 (QUIC Transport) / RFC 9001 (QUIC-TLS) / RFC 9114 (HTTP/3)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! QUIC UDP-Based Multiplexed and Secure Transport packets over UDP port 443. On the wire, the protocol uses a RFC 9000 Long Header (`Header Form = 1`, `Fixed Bit = 1`, 2-bit Long Packet Type: `0x0` Initial, `0x1` 0-RTT, `0x2` Handshake, `0x3` Retry; 32-bit Version e.g. `0x00000001` v1 or `0x6b3343cf` v2; DCID Length + 64-bit DCID; SCID Length + 64-bit SCID; variable-length Token; Length; Packet Number) or 1-RTT Short Header (`Header Form = 0`, `Fixed Bit = 1`, DCID, Packet Number).
//! Every field in [`QuicSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b QUIC [INITIAL | ZERO_RTT | HANDSHAKE | RETRY | SHORT] [VERSION <u32>] [DCID <u64>] [SCID <u64>] [TOKEN <str>] [PKT_NUM <u32>]`

/// RFC 9000 QUIC Transport Protocol specification.
///
/// Syntax mapping: `QUIC [INITIAL | ZERO_RTT | HANDSHAKE | RETRY | SHORT] [VERSION <u32>] [DCID <u64>] [SCID <u64>] [TOKEN <str>] [PKT_NUM <u32>]`
#[doc(alias = "QUIC")]
#[doc(alias = "HTTP3")]
#[doc(alias = "RFC 9000")]
#[doc(alias = "RFC9000")]
#[doc(alias = "INITIAL")]
#[doc(alias = "ZERO_RTT")]
#[doc(alias = "HANDSHAKE")]
#[doc(alias = "RETRY")]
#[doc(alias = "SHORT")]
#[doc(alias = "VERSION")]
#[doc(alias = "DCID")]
#[doc(alias = "SCID")]
#[doc(alias = "TOKEN")]
#[doc(alias = "PKT_NUM")]
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
