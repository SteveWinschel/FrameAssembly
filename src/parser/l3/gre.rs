//! GRE Layer 3 encapsulation protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a GRE protocol declaration or header field.
pub(crate) fn parse_gre_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Gre).map(|(_, s)| ParsedField::Protocol(Protocol::Gre, (s.start, s.len()))),
        (tag(Token::GreKey), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::GreKey(v, (s.start, s.end - s.start))),
        (tag(Token::GreSeq), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::GreSeq(v, (s.start, s.end - s.start))),
        (tag(Token::GreProto), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::GreProto(v, (s.start, s.end - s.start))),
        tag(Token::Checksum).map(|(_, s)| ParsedField::ChecksumFlag((s.start, s.len()))),
    ))
    .parse_next(input)
}
