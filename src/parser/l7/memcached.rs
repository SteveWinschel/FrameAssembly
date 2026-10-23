//! Memcached Layer 7 cache protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses a Memcached protocol declaration or binary/text command field.
pub(crate) fn parse_memcached_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Memcached).map(|(_, s)| ParsedField::Protocol(Protocol::Memcached, (s.start, s.len()))),
        (tag(Token::Cmd), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Key), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("KEY", v, (s.start, s.end - s.start))),
        (tag(Token::Value), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("VALUE", v, (s.start, s.end - s.start))),
        (tag(Token::Exptime), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("EXPTIME", v, (s.start, s.end - s.start))),
        (tag(Token::Opaque), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("OPAQUE", v, (s.start, s.end - s.start))),
        (tag(Token::Cas), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::L7U64Field("CAS", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
