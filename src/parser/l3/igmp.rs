//! IGMP Layer 3 multicast group membership protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u8, tag, ParsedField, Stream};

/// Parses an IGMP protocol declaration or message field.
pub(crate) fn parse_igmp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Igmp).map(|(_, s)| ParsedField::Protocol(Protocol::Igmp, (s.start, s.len()))),
        tag(Token::Query).map(|(_, s)| ParsedField::IgmpType(IgmpType::Query, (s.start, s.len()))),
        tag(Token::Report).map(|(_, s)| ParsedField::IgmpType(IgmpType::Report, (s.start, s.len()))),
        tag(Token::Leave).map(|(_, s)| ParsedField::IgmpType(IgmpType::Leave, (s.start, s.len()))),
        (tag(Token::Group), parse_ip).map(|((_, s), v)| ParsedField::GroupVal(Some(v), None, (s.start, s.end - s.start))),
        (tag(Token::MaxResp), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::MaxResp(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
