//! HTTP protocol AST definitions.

use alloc::vec::Vec;
/// RFC 9110 / RFC 9112 HTTP/1.1 specification.
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
