//! Redis Layer 7 in-memory cache protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, tag, ParsedField, Stream};

/// Parses a Redis protocol declaration or RESP command field.
pub(crate) fn parse_redis_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Redis).map(|(_, s)| ParsedField::Protocol(Protocol::Redis, (s.start, s.len()))),
        (tag(Token::Cmd), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Args), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ARGS", v, (s.start, s.end - s.start))),
        (tag(Token::ReplyType), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("REPLY_TYPE", v, (s.start, s.end - s.start))),
        (tag(Token::Value), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("VALUE", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
