//! IEEE 802.1Q Virtual LAN (VLAN) parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{parse_u32, parse_u8, tag, ParsedField, Stream};

/// Parses a VLAN tag or modifier field.
pub(crate) fn parse_vlan_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::Vlan), opt(parse_u32)).map(|((_, s), v)| ParsedField::Vlan(v.unwrap_or(1), (s.start, s.end - s.start))),
        (tag(Token::Pcp), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Pcp(v, (s.start, s.end - s.start))),
        (tag(Token::Dei), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Dei(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
