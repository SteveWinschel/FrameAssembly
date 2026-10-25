//! Real-Time Streaming Protocol (RTSP) (RFC 7826 (RTSP 2.0) / RFC 2326 (RTSP 1.0)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Real-Time Streaming Protocol (RTSP) packets over TCP port 554 (and alternate port 8554). On the wire, the protocol uses a CRLF-delimited text control protocol starting with a Request-Line (`<METHOD> <URI> RTSP/1.0\r\n` for `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `PAUSE`, `RECORD`, `ANNOUNCE`, `GET_PARAMETER`, `TEARDOWN`) or Status-Line (`RTSP/1.0 <STATUS> OK\r\n`), followed by `CSeq:`, `Transport:` (e.g. `RTP/AVP;unicast;client_port=5004-5005`), `Session:`, and `Content-Length:` headers.
//! Every field in [`RtspSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b RTSP [OPTIONS | METHOD <str>] [URI <str>] [STATUS <u16>] [CSEQ <u32>] [TRANSPORT_HDR <str>] [SESSION <str>]`

/// RFC 7826 Real-Time Streaming Protocol specification.
///
/// Syntax mapping: `RTSP [OPTIONS | METHOD <str>] [URI <str>] [STATUS <u16>] [CSEQ <u32>] [TRANSPORT_HDR <str>] [SESSION <str>]`
#[doc(alias = "RTSP")]
#[doc(alias = "RFC 7826")]
#[doc(alias = "RFC7826")]
#[doc(alias = "RFC 2326")]
#[doc(alias = "RFC2326")]
#[doc(alias = "OPTIONS")]
#[doc(alias = "METHOD")]
#[doc(alias = "URI")]
#[doc(alias = "STATUS")]
#[doc(alias = "CSEQ")]
#[doc(alias = "TRANSPORT_HDR")]
#[doc(alias = "SESSION")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RtspSpec<'a> {
    /// RTSP method.
    pub method: Option<&'a str>,
    /// Stream URI.
    pub uri: Option<&'a str>,
    /// CSeq sequence number.
    pub cseq: Option<u32>,
    /// Transport header string.
    pub transport_hdr: Option<&'a str>,
    /// Session identifier string.
    pub session: Option<&'a str>,
    /// Response status code.
    pub status: Option<u16>,
}
