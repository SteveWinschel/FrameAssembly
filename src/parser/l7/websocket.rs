//! WebSocket (RFC 6455) Layer 7 full-duplex framing protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 6455 `WEBSOCKET` data and control
//! frames in FrameAssembly `.fasm` specifications. It recognizes the `WEBSOCKET` protocol keyword,
//! explicit `OPCODE` strings, shorthand opcode keywords (`TEXT`, `BINARY`, `PING`, `PONG`,
//! `CLOSE`), final fragment indicator bits (`FIN_BIT`), and 32-bit client masking keys
//! (`MASK_KEY`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Parses a WebSocket protocol declaration or framing field.
pub(crate) fn parse_websocket_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Websocket)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Websocket, (s.start, s.len()))),
        tag(Token::Text)
            .map(|(_, s)| ParsedField::L7StringField("OPCODE", "TEXT", (s.start, s.len()))),
        tag(Token::Binary)
            .map(|(_, s)| ParsedField::L7StringField("OPCODE", "BINARY", (s.start, s.len()))),
        tag(Token::Ping)
            .map(|(_, s)| ParsedField::L7StringField("OPCODE", "PING", (s.start, s.len()))),
        tag(Token::Pong)
            .map(|(_, s)| ParsedField::L7StringField("OPCODE", "PONG", (s.start, s.len()))),
        tag(Token::Close)
            .map(|(_, s)| ParsedField::L7StringField("OPCODE", "CLOSE", (s.start, s.len()))),
        (tag(Token::Opcode), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("OPCODE", v, (s.start, s.end - s.start))),
        (tag(Token::FinBit), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("FIN_BIT", v, (s.start, s.end - s.start))),
        (tag(Token::MaskKey), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("MASK_KEY", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
