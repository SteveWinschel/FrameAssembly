//! IKEv2 Layer 3 key exchange protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, parse_u64, parse_u8, tag, ParsedField, Stream};

/// Parses an IKEv2 protocol declaration or parameter field.
pub(crate) fn parse_ikev2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ikev2).map(|(_, s)| ParsedField::Protocol(Protocol::Ikev2, (s.start, s.len()))),
            (tag(Token::InitiatorSpi), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::InitiatorSpi(v, (s.start, s.end - s.start))),
            (tag(Token::ResponderSpi), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::ResponderSpi(v, (s.start, s.end - s.start))),
            tag(Token::SaInit).map(|(_, s)| ParsedField::IkeExchange(IkeExchange::SaInit, (s.start, s.len()))),
        )),
        alt((
            tag(Token::CreateChildSa).map(|(_, s)| ParsedField::IkeExchange(IkeExchange::CreateChildSa, (s.start, s.len()))),
            tag(Token::Informational).map(|(_, s)| ParsedField::IkeExchange(IkeExchange::Informational, (s.start, s.len()))),
            (tag(Token::MsgId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::MsgId(v, (s.start, s.end - s.start))),
            (tag(Token::NextPayload), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::NextPayload(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
