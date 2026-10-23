//! RTSP protocol AST definitions.


/// RFC 7826 Real-Time Streaming Protocol specification.
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
