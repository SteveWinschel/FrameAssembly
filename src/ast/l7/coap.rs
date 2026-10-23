//! COAP protocol AST definitions.


/// RFC 7252 Constrained Application Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoapSpec<'a> {
    /// Message type (CON, NON, ACK, RST).
    pub msg_type: Option<&'a str>,
    /// Request/response code string.
    pub code: Option<&'a str>,
    /// Message ID.
    pub msgid: Option<u16>,
    /// Token integer.
    pub token: Option<u32>,
    /// Uri-Path option string.
    pub uri_path: Option<&'a str>,
    /// Content-Format option code.
    pub content_format: Option<u16>,
}
