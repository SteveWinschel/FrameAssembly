//! HSRP Layer 3 standby routing protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u16, parse_u8, tag, ParsedField, Stream};

/// Parses an HSRP protocol declaration or status field.
pub(crate) fn parse_hsrp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Hsrp).map(|(_, s)| ParsedField::Protocol(Protocol::Hsrp, (s.start, s.len()))),
        (tag(Token::Group), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::GroupVal(None, Some(v), (s.start, s.end - s.start))),
        (tag(Token::Priority), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        (tag(Token::State), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::HsrpState(v, (s.start, s.end - s.start))),
        (tag(Token::Vip), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::Vip(v, (s.start, s.end - s.start))),
        (tag(Token::HelloTimeHsrp), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::HelloTimeHsrp(v, (s.start, s.end - s.start))),
        (tag(Token::HoldTime), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::HoldTime(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
