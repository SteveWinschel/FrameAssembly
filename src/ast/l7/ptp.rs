//! Precision Time Protocol v2 (PTPv2) (IEEE 1588-2008 (PTPv2) / RFC 8173) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Precision Time Protocol v2 (PTPv2) packets over UDP port 319 (Event messages: SYNC, DELAY_REQ) and UDP port 320 (General messages: FOLLOW_UP, DELAY_RESP, ANNOUNCE). On the wire, the protocol uses a 34-byte IEEE 1588v2 commonPTP header (4-bit transportSpecific + 4-bit messageType, 4-bit versionPTP = 2, 16-bit messageLength, 8-bit domainNumber, 8-bit reserved, 16-bit flagField, 64-bit correctionField, 32-bit reserved, 80-bit sourcePortIdentity containing 64-bit ClockIdentity + 16-bit PortNumber, 16-bit sequenceId, 8-bit controlField, 8-bit logMessageInterval) followed by 10-byte originTimestamp.
//! Every field in [`PtpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b PTP [SYNC | DELAY_REQ | FOLLOW_UP | DELAY_RESP | ANNOUNCE | MSG_TYPE <str>] [DOMAIN <u8>] [SEQ_ID <u16>] [CLOCK_ID <str>]`

/// IEEE 1588 Precision Time Protocol specification.
///
/// Syntax mapping: `PTP [SYNC | DELAY_REQ | FOLLOW_UP | DELAY_RESP | ANNOUNCE | MSG_TYPE <str>] [DOMAIN <u8>] [SEQ_ID <u16>] [CLOCK_ID <str>]`
#[doc(alias = "PTP")]
#[doc(alias = "IEEE 1588")]
#[doc(alias = "IEEE1588")]
#[doc(alias = "RFC 8173")]
#[doc(alias = "PTPV2")]
#[doc(alias = "SYNC")]
#[doc(alias = "DELAY_REQ")]
#[doc(alias = "FOLLOW_UP")]
#[doc(alias = "DELAY_RESP")]
#[doc(alias = "ANNOUNCE")]
#[doc(alias = "MSG_TYPE")]
#[doc(alias = "DOMAIN")]
#[doc(alias = "SEQ_ID")]
#[doc(alias = "CLOCK_ID")]
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
