//! WEBSOCKET protocol AST definitions.

/// RFC 6455 The WebSocket Protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebsocketSpec<'a> {
    /// Opcode name (e.g. TEXT, BINARY, PING, PONG, CLOSE).
    pub opcode: Option<&'a str>,
    /// FIN bit (0 or 1).
    pub fin_bit: Option<u8>,
    /// 32-bit masking key.
    pub mask_key: Option<u32>,
    /// Text payload string.
    pub payload: Option<&'a str>,
}
