//! Hypertext Transfer Protocol Version 2 (HTTP/2) Layer 7 multiplexed frame field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 9113 `HTTP2` binary framing in
//! FrameAssembly `.fasm` specifications. It recognizes the `HTTP2` protocol keyword, connection
//! preface flags (`PREFACE`), frame type flags (`SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`,
//! `PING`, `GOAWAY`), and 31-bit HTTP/2 stream identifiers (`STREAM_ID`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, tag, ParsedField, Stream};

/// Parses an HTTP/2 protocol declaration or frame field.
pub(crate) fn parse_http2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Http2)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Http2, (s.start, s.len()))),
        tag(Token::Preface).map(|(_, s)| ParsedField::L7Flag("PREFACE", (s.start, s.len()))),
        tag(Token::Settings).map(|(_, s)| ParsedField::L7Flag("SETTINGS", (s.start, s.len()))),
        tag(Token::Headers).map(|(_, s)| ParsedField::L7Flag("HEADERS", (s.start, s.len()))),
        tag(Token::Data).map(|(_, s)| ParsedField::L7Flag("DATA", (s.start, s.len()))),
        tag(Token::WindowUpdate)
            .map(|(_, s)| ParsedField::L7Flag("WINDOW_UPDATE", (s.start, s.len()))),
        tag(Token::Ping).map(|(_, s)| ParsedField::L7Flag("PING", (s.start, s.len()))),
        tag(Token::Goaway).map(|(_, s)| ParsedField::L7Flag("GOAWAY", (s.start, s.len()))),
        (tag(Token::StreamId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("STREAM_ID", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
