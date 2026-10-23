//! MLD Layer 3 IPv6 multicast listener discovery protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u16, tag, ParsedField, Stream};

/// Parses an MLD protocol declaration or message field.
pub(crate) fn parse_mld_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Mld).map(|(_, s)| ParsedField::Protocol(Protocol::Mld, (s.start, s.len()))),
        tag(Token::Query).map(|(_, s)| ParsedField::MldType(MldType::Query, (s.start, s.len()))),
        tag(Token::Report).map(|(_, s)| ParsedField::MldType(MldType::Report, (s.start, s.len()))),
        tag(Token::Done).map(|(_, s)| ParsedField::MldType(MldType::Done, (s.start, s.len()))),
        (tag(Token::MulticastAddr), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::MulticastAddr(v, (s.start, s.end - s.start))),
        (tag(Token::MaxRespDelay), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::MaxRespDelay(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
