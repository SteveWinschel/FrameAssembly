//! HTTP2 protocol AST definitions.

use core::marker::PhantomData;
/// RFC 9113 HTTP/2 framing specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http2Spec<'a> {
    /// Connection preface flag.
    pub is_preface: bool,
    /// SETTINGS frame flag.
    pub is_settings: bool,
    /// HEADERS frame flag.
    pub is_headers: bool,
    /// DATA frame flag.
    pub is_data: bool,
    /// WINDOW_UPDATE frame flag.
    pub is_window_update: bool,
    /// PING frame flag.
    pub is_ping: bool,
    /// GOAWAY frame flag.
    pub is_goaway: bool,
    /// Stream identifier.
    pub stream_id: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
