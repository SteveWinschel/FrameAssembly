//! Session Initiation Protocol (SIP) (RFC 3261 / RFC 3262 (PRACK) / RFC 3428 (MESSAGE) / RFC 4566 (SDP)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Session Initiation Protocol (SIP) packets over UDP/TCP port 5060 (SIP) and TCP/TLS port 5061 (SIPS). On the wire, the protocol uses a UTF-8 text signaling message starting with a Request-Line (`<METHOD> <URI> SIP/2.0\r\n` for `INVITE`, `ACK`, `BYE`, `CANCEL`, `REGISTER`, `OPTIONS`, `MESSAGE`) or Status-Line (`SIP/2.0 <STATUS> <REASON>\r\n` e.g. `100 Trying`, `180 Ringing`, `200 OK`, `401 Unauthorized`, `486 Busy Here`), followed by `Via:`, `From:`, `To:`, `Call-ID:`, `CSeq:`, `Contact:`, `Content-Type:`, `Content-Length:`, and optional `application/sdp` body.
//! Every field in [`SipSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b SIP [INVITE | BYE | CANCEL | METHOD <str>] [URI <str>] [STATUS <u16>] [REASON <str>] [FROM <str>] [TO <str>] [CALL_ID <str>] [CSEQ <u32>] [VIA <str>] [CONTACT <str>] [CONTENT_TYPE <str>] [BODY <str>] [TRANSPORT TCP]`

/// RFC 3261 Session Initiation Protocol specification.
///
/// Syntax mapping: `SIP [INVITE | BYE | CANCEL | METHOD <str>] [URI <str>] [STATUS <u16>] [REASON <str>] [FROM <str>] [TO <str>] [CALL_ID <str>] [CSEQ <u32>] [VIA <str>] [CONTACT <str>] [CONTENT_TYPE <str>] [BODY <str>] [TRANSPORT TCP]`
#[doc(alias = "SIP")]
#[doc(alias = "VOIP")]
#[doc(alias = "RFC 3261")]
#[doc(alias = "RFC3261")]
#[doc(alias = "INVITE")]
#[doc(alias = "BYE")]
#[doc(alias = "CANCEL")]
#[doc(alias = "METHOD")]
#[doc(alias = "URI")]
#[doc(alias = "STATUS")]
#[doc(alias = "REASON")]
#[doc(alias = "FROM")]
#[doc(alias = "TO")]
#[doc(alias = "CALL_ID")]
#[doc(alias = "CSEQ")]
#[doc(alias = "VIA")]
#[doc(alias = "CONTACT")]
#[doc(alias = "CONTENT_TYPE")]
#[doc(alias = "BODY")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SipSpec<'a> {
    /// SIP method (e.g. INVITE, ACK, BYE, REGISTER).
    pub method: Option<&'a str>,
    /// Response status code.
    pub status: Option<u16>,
    /// Response reason phrase.
    pub reason: Option<&'a str>,
    /// From header URI.
    pub from: Option<&'a str>,
    /// To header URI.
    pub to: Option<&'a str>,
    /// Call-ID header string.
    pub call_id: Option<&'a str>,
    /// CSeq sequence number.
    pub cseq: Option<u32>,
    /// Via header string.
    pub via: Option<&'a str>,
    /// Contact header string.
    pub contact: Option<&'a str>,
    /// Content-Type header string.
    pub content_type: Option<&'a str>,
    /// Message body string.
    pub body: Option<&'a str>,
    /// Request URI.
    pub uri: Option<&'a str>,
}
