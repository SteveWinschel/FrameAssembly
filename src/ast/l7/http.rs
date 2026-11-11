//! Hypertext Transfer Protocol (HTTP/1.1) (RFC 9110 (HTTP Semantics) / RFC 9112 (HTTP/1.1)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Hypertext Transfer Protocol (HTTP/1.1) packets over TCP port 80 (HTTP) or custom ports (8080, 8000, 8443). On the wire, the protocol uses a CRLF-delimited text message starting with a Request-Line (`<METHOD> <URI> http/<VERSION>\r\n`) or Status-Line (`http/<VERSION> <STATUS> <REASON>\r\n`), followed by `Host:`, `User-Agent:`, `Content-Type:`, `Content-Length:`, and custom `Header: Value\r\n` fields, an empty line (`\r\n`), and an optional entity body.
//! Every field in [`HttpSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b http [method <str>] [uri <str>] [version <str>] [hosthdr <str>] [useragent <str>] [contenttype <str>] [status <u16>] [reason <str>] [header <key> <val>] [body <str>]`

use alloc::vec::Vec;
/// RFC 9110 / RFC 9112 HTTP/1.1 specification.
///
/// Syntax mapping: `http [method <str>] [uri <str>] [version <str>] [hosthdr <str>] [useragent <str>] [contenttype <str>] [status <u16>] [reason <str>] [header <key> <val>] [body <str>]`
#[doc(alias = "http")]
#[doc(alias = "HTTP11")]
#[doc(alias = "RFC 9110")]
#[doc(alias = "RFC9110")]
#[doc(alias = "RFC 9112")]
#[doc(alias = "RFC9112")]
#[doc(alias = "method")]
#[doc(alias = "uri")]
#[doc(alias = "version")]
#[doc(alias = "hosthdr")]
#[doc(alias = "useragent")]
#[doc(alias = "contenttype")]
#[doc(alias = "status")]
#[doc(alias = "reason")]
#[doc(alias = "header")]
#[doc(alias = "body")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpSpec<'a> {
    /// HTTP method (GET, POST, etc.).
    pub method: Option<&'a str>,
    /// Request target URI.
    pub uri: Option<&'a str>,
    /// Protocol version string (e.g. "1.1").
    pub version: Option<&'a str>,
    /// Host header value.
    pub host_hdr: Option<&'a str>,
    /// User-Agent header value.
    pub user_agent: Option<&'a str>,
    /// Content-Type header value.
    pub content_type: Option<&'a str>,
    /// Status code for responses.
    pub status: Option<u16>,
    /// Reason phrase for responses.
    pub reason: Option<&'a str>,
    /// Custom HTTP headers.
    pub headers: Vec<(&'a str, &'a str)>,
    /// Message body string.
    pub body: Option<&'a str>,
}
