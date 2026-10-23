//! RIP Layer 3 routing protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a RIP protocol declaration or table update field.
pub(crate) fn parse_rip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Rip).map(|(_, s)| ParsedField::Protocol(Protocol::Rip, (s.start, s.len()))),
        (tag(Token::Metric), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Metric(v, (s.start, s.end - s.start))),
        (tag(Token::Prefix), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::PrefixVal(Some(v), None, (s.start, s.end - s.start))),
        (tag(Token::NextHop), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::NextHop(v, (s.start, s.end - s.start))),
        (tag(Token::Tag), parse_u16).map(|((_, s), v)| ParsedField::TagVal(Some(v), None, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
