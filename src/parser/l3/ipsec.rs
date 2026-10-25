//! IP Security (`IPSEC`, RFC 4301 / RFC 4303) Security Association field parser.
//!
//! This module implements the winnow parser combinator for `IPSEC` security headers and parameters
//! shared across Encapsulating Security Payload (`ESP`) and Authentication Header (`AH`) frames.
//! It parses 32-bit Security Parameters Index values (`SPI`), Initialization Vectors (`IV`),
//! Integrity Check Values (`ICV`), sequence numbers (`SEQ`), and `NEXT_HEADER` protocol numbers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_hex_bytes, parse_u8, parse_u32, tag};

/// Parses an IPsec protocol declaration or parameter field.
pub(crate) fn parse_ipsec_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ipsec).map(|(_, s)| ParsedField::Protocol(Protocol::Ipsec, (s.start, s.len()))),
        (tag(Token::Spi), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Spi(v, (s.start, s.end - s.start))),
        (tag(Token::Seq), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Seq(v, (s.start, s.end - s.start))),
        (tag(Token::Iv), cut_err(parse_hex_bytes))
            .map(|((_, s), v)| ParsedField::Iv(v, (s.start, s.end - s.start))),
        (tag(Token::Icv), cut_err(parse_hex_bytes))
            .map(|((_, s), v)| ParsedField::Icv(v, (s.start, s.end - s.start))),
        (tag(Token::NextHeader), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::NextHeader(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
