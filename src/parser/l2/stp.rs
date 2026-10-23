//! Spanning Tree Protocol (STP / RSTP) parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u16, parse_u32, parse_u8, tag, ParsedField, Stream};

/// Parses an STP protocol declaration or BPDU field.
pub(crate) fn parse_stp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Stp).map(|(_, s)| ParsedField::Protocol(Protocol::Stp, (s.start, s.len()))),
        (tag(Token::RootId), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::RootId(v, (s.start, s.end - s.start))),
        (tag(Token::BridgeId), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::BridgeId(v, (s.start, s.end - s.start))),
        (tag(Token::Cost), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Cost(v, (s.start, s.end - s.start))),
        (tag(Token::MaxAge), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::MaxAge(v, (s.start, s.end - s.start))),
        (tag(Token::HelloTime), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::HelloTime(v, (s.start, s.end - s.start))),
        (tag(Token::ForwardDelay), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::ForwardDelay(v, (s.start, s.end - s.start))),
        tag(Token::Rstp).map(|(_, s)| ParsedField::Rstp((s.start, s.len()))),
        (tag(Token::Flags), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
