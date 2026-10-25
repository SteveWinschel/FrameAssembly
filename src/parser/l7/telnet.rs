//! Telnet (RFC 854) Layer 7 interactive terminal and IAC option negotiation field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 854 `TELNET` terminal streams and
//! Interpret As Command (`IAC`) option negotiations in FrameAssembly `.fasm` specifications. It
//! recognizes the `TELNET` protocol keyword, option negotiation commands (`WILL`, `WONT`, `DO`,
//! `DONT` with an optional `OPTION` keyword before the option code), standalone `OPTION` codes,
//! and terminal text data (`DATA`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a Telnet protocol declaration or IAC option field.
pub(crate) fn parse_telnet_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Telnet)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Telnet, (s.start, s.len()))),
        (tag(Token::Will), opt(tag(Token::Option)), cut_err(parse_u32))
            .map(|((_, s), _, v)| ParsedField::L7U32Field("WILL", v, (s.start, s.end - s.start))),
        (tag(Token::Wont), opt(tag(Token::Option)), cut_err(parse_u32))
            .map(|((_, s), _, v)| ParsedField::L7U32Field("WONT", v, (s.start, s.end - s.start))),
        (tag(Token::DoCmd), opt(tag(Token::Option)), cut_err(parse_u32))
            .map(|((_, s), _, v)| ParsedField::L7U32Field("DO", v, (s.start, s.end - s.start))),
        (tag(Token::Dont), opt(tag(Token::Option)), cut_err(parse_u32))
            .map(|((_, s), _, v)| ParsedField::L7U32Field("DONT", v, (s.start, s.end - s.start))),
        (tag(Token::Option), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("OPTION", v, (s.start, s.end - s.start))),
        (tag(Token::Data), parse_str_val)
            .map(|((_, s), v)| ParsedField::L7StringField("DATA", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
