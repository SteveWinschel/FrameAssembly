//! SIP protocol AST definitions.


/// RFC 3261 Session Initiation Protocol specification.
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
