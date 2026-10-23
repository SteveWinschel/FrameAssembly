//! Telnet Layer 7 terminal protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a Telnet protocol declaration or IAC option field.
pub(crate) fn parse_telnet_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Telnet).map(|(_, s)| ParsedField::Protocol(Protocol::Telnet, (s.start, s.len()))),
        (tag(Token::Will), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("WILL", v, (s.start, s.end - s.start))),
        (tag(Token::Wont), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("WONT", v, (s.start, s.end - s.start))),
        (tag(Token::DoCmd), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("DO", v, (s.start, s.end - s.start))),
        (tag(Token::Dont), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("DONT", v, (s.start, s.end - s.start))),
        (tag(Token::Option), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("OPTION", v, (s.start, s.end - s.start))),
        (tag(Token::Data), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("DATA", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
