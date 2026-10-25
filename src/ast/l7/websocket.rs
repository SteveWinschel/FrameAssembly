//! The WebSocket Protocol (RFC 6455) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! The WebSocket Protocol packets over TCP port 80 (`ws://`) or TCP port 443 (`wss://`). On the wire, the protocol uses a 2-to-14-byte RFC 6455 binary frame header: Byte 0 packs 1-bit `FIN` flag, 3-bit `RSV1..3` extension bits, and 4-bit `Opcode` (`0x1` TEXT, `0x2` BINARY, `0x8` CLOSE, `0x9` PING, `0xA` PONG); Byte 1 packs 1-bit `MASK` flag and 7-bit Payload Length (with optional 16-bit or 64-bit extended length), followed by an optional 32-bit XOR `Masking-Key` and masked/unmasked application payload.
//! Every field in [`WebsocketSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b WEBSOCKET [OPCODE <str>] [FIN_BIT <u8>] [MASK_KEY <u32>] [PAYLOAD <str>]`

/// RFC 6455 The WebSocket Protocol specification.
///
/// Syntax mapping: `WEBSOCKET [OPCODE <str>] [FIN_BIT <u8>] [MASK_KEY <u32>] [PAYLOAD <str>]`
#[doc(alias = "WEBSOCKET")]
#[doc(alias = "WS")]
#[doc(alias = "WSS")]
#[doc(alias = "RFC 6455")]
#[doc(alias = "RFC6455")]
#[doc(alias = "OPCODE")]
#[doc(alias = "FIN_BIT")]
#[doc(alias = "MASK_KEY")]
#[doc(alias = "PAYLOAD")]
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
