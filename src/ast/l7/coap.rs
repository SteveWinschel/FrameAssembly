//! Constrained Application Protocol (CoAP, RFC 7252) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`CoapSpec`], the zero-copy AST representation of an RFC 7252 Constrained
//! Application Protocol (CoAP) message over UDP port 5683 (or 5684 for DTLS-secured CoAPS). On the
//! wire, a CoAP frame starts with a 4-byte binary header (2-bit Version `1`, 2-bit Type `con`/`non`
//! /`ack`/`rst`, 4-bit Token Length, 8-bit `c.dd` Code byte, and 16-bit big-endian Message ID),
//! followed by the variable-length Token, delta-encoded CoAP Options (`Uri-Path` option 11,
//! `Content-Format` option 12), and an optional `0xFF` payload marker. Canonical `.fasm` syntax:
//! `coap [con | non | ack | rst] [code <str>] [msgid <u16>] [token <u32>] [uripath <str>] [contentformat <u16>]`.

/// RFC 7252 Constrained Application Protocol (CoAP) specification.
///
/// Syntax mapping: `coap [con | non | ack | rst] [code <str>] [msgid <u16>] [token <u32>] [uripath <str>] [contentformat <u16>]`
#[doc(alias = "coap")]
#[doc(alias = "RFC 7252")]
#[doc(alias = "RFC7252")]
#[doc(alias = "5683")]
#[doc(alias = "con")]
#[doc(alias = "non")]
#[doc(alias = "ack")]
#[doc(alias = "rst")]
#[doc(alias = "code")]
#[doc(alias = "msgid")]
#[doc(alias = "token")]
#[doc(alias = "uripath")]
#[doc(alias = "contentformat")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoapSpec<'a> {
    /// CoAP message type (`con`, `non`, `ack`, `rst`, default `"CON"`).
    pub msg_type: Option<&'a str>,
    /// Dotted class.detail request/response code (`code <str>`, e.g., `"0.01"` GET, `"2.05"` Content).
    pub code: Option<&'a str>,
    /// 16-bit Message ID for duplicate detection and ACK correlation (`msgid <u16>`).
    pub msgid: Option<u16>,
    /// 32-bit request/response matching Token (`token <u32>`).
    pub token: Option<u32>,
    /// Slash-delimited `Uri-Path` option segments (`uripath <str>`).
    pub uri_path: Option<&'a str>,
    /// Numeric CoAP `Content-Format` option 12 identifier (`contentformat <u16>`, e.g., `50` for JSON, `60` for CBOR).
    pub content_format: Option<u16>,
}
