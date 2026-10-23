//! BFD Layer 3 fault detection protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, parse_u8, tag, ParsedField, Stream};

/// Parses a BFD protocol declaration or control field.
pub(crate) fn parse_bfd_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Bfd).map(|(_, s)| ParsedField::Protocol(Protocol::Bfd, (s.start, s.len()))),
        (tag(Token::State), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::HsrpState(v, (s.start, s.end - s.start))),
        (tag(Token::Diag), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Diag(v, (s.start, s.end - s.start))),
        (tag(Token::MyDisc), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::MyDisc(v, (s.start, s.end - s.start))),
        (tag(Token::YourDisc), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::YourDisc(v, (s.start, s.end - s.start))),
        (tag(Token::MinTx), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::MinTx(v, (s.start, s.end - s.start))),
        (tag(Token::MinRx), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::MinRx(v, (s.start, s.end - s.start))),
        (tag(Token::Mult), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::Mult(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
