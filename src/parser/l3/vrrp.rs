//! VRRP Layer 3 redundancy protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u16, parse_u8, tag, ParsedField, Stream};

/// Parses a VRRP protocol declaration or advertisement field.
pub(crate) fn parse_vrrp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Vrrp).map(|(_, s)| ParsedField::Protocol(Protocol::Vrrp, (s.start, s.len()))),
        (tag(Token::Vrid), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Vrid(v, (s.start, s.end - s.start))),
        (tag(Token::Priority), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        (tag(Token::AdvInt), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::AdvInt(v, (s.start, s.end - s.start))),
        (tag(Token::Vip), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::Vip(v, (s.start, s.end - s.start))),
        (tag(Token::Version), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
