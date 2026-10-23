//! IEEE 802.1ad Provider Bridging (QinQ) parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{parse_u16, tag, ParsedField, Stream};

/// Parses a QinQ double-VLAN tag or field.
pub(crate) fn parse_qinq_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::Qinq), opt(parse_u16)).map(|((_, s), v)| ParsedField::Qinq(v.unwrap_or(1), (s.start, s.end - s.start))),
        (tag(Token::InnerVlan), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::InnerVlan(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
