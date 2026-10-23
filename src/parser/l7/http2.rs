//! HTTP/2 Layer 7 multiplexed protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, tag, ParsedField, Stream};

/// Parses an HTTP/2 protocol declaration or frame field.
pub(crate) fn parse_http2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Http2).map(|(_, s)| ParsedField::Protocol(Protocol::Http2, (s.start, s.len()))),
        tag(Token::Preface).map(|(_, s)| ParsedField::L7Flag("PREFACE", (s.start, s.len()))),
        tag(Token::Settings).map(|(_, s)| ParsedField::L7Flag("SETTINGS", (s.start, s.len()))),
        tag(Token::Headers).map(|(_, s)| ParsedField::L7Flag("HEADERS", (s.start, s.len()))),
        tag(Token::WindowUpdate).map(|(_, s)| ParsedField::L7Flag("WINDOW_UPDATE", (s.start, s.len()))),
        tag(Token::Ping).map(|(_, s)| ParsedField::L7Flag("PING", (s.start, s.len()))),
        tag(Token::Goaway).map(|(_, s)| ParsedField::L7Flag("GOAWAY", (s.start, s.len()))),
        (tag(Token::StreamId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("STREAM_ID", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
