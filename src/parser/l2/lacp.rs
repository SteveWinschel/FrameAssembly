//! Link Aggregation Control Protocol (LACP) parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_mac, parse_u16, parse_u8, tag, ParsedField, Stream};

/// Parses an LACP protocol declaration or field.
pub(crate) fn parse_lacp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Lacp).map(|(_, s)| ParsedField::Protocol(Protocol::Lacp, (s.start, s.len()))),
        (tag(Token::ActorSys), cut_err(parse_mac)).map(|((_, s), v)| ParsedField::ActorSys(v, (s.start, s.end - s.start))),
        (tag(Token::ActorKey), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::ActorKey(v, (s.start, s.end - s.start))),
        (tag(Token::ActorPort), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::ActorPort(v, (s.start, s.end - s.start))),
        (tag(Token::PartnerSys), cut_err(parse_mac)).map(|((_, s), v)| ParsedField::PartnerSys(v, (s.start, s.end - s.start))),
        (tag(Token::PartnerKey), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::PartnerKey(v, (s.start, s.end - s.start))),
        (tag(Token::PartnerPort), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::PartnerPort(v, (s.start, s.end - s.start))),
        (tag(Token::ActorState), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::ActorState(v, (s.start, s.end - s.start))),
        (tag(Token::PartnerState), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::PartnerState(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
