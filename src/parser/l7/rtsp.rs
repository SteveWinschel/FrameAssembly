//! Real Time Streaming Protocol (RTSP) Layer 7 media control field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 2326 and RFC 7826 `RTSP` session
//! control messages in FrameAssembly `.fasm` specifications. It recognizes the `RTSP` protocol
//! keyword, shorthand method tokens (`OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, `TEARDOWN`), explicit
//! `METHOD` strings, stream `URI` targets, sequence numbers (`CSEQ`), `TRANSPORT_HDR` parameters,
//! `SESSION` identifiers, and response `STATUS` codes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an RTSP protocol declaration or media session control field.
pub(crate) fn parse_rtsp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rtsp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Rtsp, (s.start, s.len()))),
            tag(Token::Options)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "OPTIONS", (s.start, s.len()))),
            tag(Token::Describe)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "DESCRIBE", (s.start, s.len()))),
            tag(Token::Setup)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "SETUP", (s.start, s.len()))),
            tag(Token::Play)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "PLAY", (s.start, s.len()))),
            tag(Token::Teardown)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "TEARDOWN", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Uri), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("URI", v, (s.start, s.end - s.start))),
            (tag(Token::Cseq), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CSEQ", v, (s.start, s.end - s.start))),
            (tag(Token::TransportHdr), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("TRANSPORT_HDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Session), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SESSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
