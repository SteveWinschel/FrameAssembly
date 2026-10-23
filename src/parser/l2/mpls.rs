//! Multi-Protocol Label Switching (MPLS) parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{parse_u32, parse_u8, tag, ParsedField, Stream};

/// Parses an MPLS protocol declaration, label, or header field.
pub(crate) fn parse_mpls_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::Mpls), opt(parse_u32)).map(|((_, s), v)| ParsedField::Mpls(v.unwrap_or(0), (s.start, s.end - s.start))),
        (tag(Token::Label), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Mpls(v, (s.start, s.end - s.start))),
        (tag(Token::Exp), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Exp(v, (s.start, s.end - s.start))),
        (tag(Token::Bos), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Bos(v, (s.start, s.end - s.start))),
        (tag(Token::MplsTtl), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::MplsTtl(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
