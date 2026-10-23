//! IPsec Layer 3 security protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_hex_bytes, parse_u32, tag, ParsedField, Stream};

/// Parses an IPsec protocol declaration or parameter field.
pub(crate) fn parse_ipsec_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ipsec).map(|(_, s)| ParsedField::Protocol(Protocol::Ipsec, (s.start, s.len()))),
        (tag(Token::Spi), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Spi(v, (s.start, s.end - s.start))),
        (tag(Token::Iv), cut_err(parse_hex_bytes)).map(|((_, s), v)| ParsedField::Iv(v, (s.start, s.end - s.start))),
        (tag(Token::Icv), cut_err(parse_hex_bytes)).map(|((_, s), v)| ParsedField::Icv(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
