//! Diameter Base Protocol (RFC 6733) Layer 7 AST definitions.
//!
//! This module defines the [`DiameterSpec`] AST payload specification used inside compiled
//! FrameAssembly packets. It models Diameter version 1 headers (`cmd`, `flags`, `app_id`,
//! `hop_id`, `end_id`, `is_response`) and standard Base / Credit-Control Attribute-Value Pairs
//! (`Origin-Host`, `Origin-Realm`, `Destination-Host`, `Destination-Realm`, `Session-Id`,
//! `Result-Code`, and `User-Name`) over TCP or SCTP port `3868`.

/// Diameter Base Protocol (RFC 6733) message specification.
///
/// Syntax mapping: `diameter [cer|cea|dwr|dwa|ccr|cca] [request|response] [cmd <str|u32>] [flags <u8>] [appid <u32>] [hopid <u32>] [endid <u32>] [originhost <str>] [realm <str>] [dsthost <str>] [dstrealm <str>] [sessionid <str>] [resultcode <u32>] [user <str>]`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[doc(alias = "diameter")]
#[doc(alias = "rfc6733")]
#[doc(alias = "cer")]
#[doc(alias = "ccr")]
#[doc(alias = "dwr")]
pub struct DiameterSpec<'a> {
    /// Diameter command mnemonic (`cer`, `cea`, `dwr`, `dwa`, `ccr`, `cca`, `acr`, `ulr`, ...) or decimal command code.
    pub cmd: Option<&'a str>,
    /// Clears (`true`) or keeps (`false`) the Diameter Header `R` (Request) flag bit (`0x80`).
    pub is_response: bool,
    /// Explicit Diameter Command Flags byte override (`0x80` = Request, `0x40` = Proxiable, `0x20` = Error).
    pub flags: Option<u8>,
    /// Diameter Application-ID header field (e.g., `0` Base Common Messages, `4` DCCA, `16777251` S6a).
    pub app_id: Option<u32>,
    /// Diameter Hop-by-Hop Identifier (`u32`, defaults to `1`).
    pub hop_id: Option<u32>,
    /// Diameter End-to-End Identifier (`u32`, defaults to `1`).
    pub end_id: Option<u32>,
    /// `Origin-Host` (AVP 264) DiameterIdentity string.
    pub origin_host: Option<&'a str>,
    /// `Origin-Realm` (AVP 296) DiameterIdentity string.
    pub origin_realm: Option<&'a str>,
    /// `Destination-Host` (AVP 293) DiameterIdentity string.
    pub dst_host: Option<&'a str>,
    /// `Destination-Realm` (AVP 283) DiameterIdentity string.
    pub dst_realm: Option<&'a str>,
    /// `Session-Id` (AVP 263) UTF8String identifier.
    pub session_id: Option<&'a str>,
    /// `Result-Code` (AVP 268) Unsigned32 code (defaults to `2001` `DIAMETER_SUCCESS` on answers).
    pub result_code: Option<u32>,
    /// `User-Name` (AVP 1) UTF8String identity.
    pub user: Option<&'a str>,
}
