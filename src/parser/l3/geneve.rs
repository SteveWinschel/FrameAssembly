//! GENEVE Layer 3 overlay tunnel protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u16, parse_u32, parse_u8, tag, ParsedField, Stream};

/// Parses a GENEVE protocol declaration or option field.
pub(crate) fn parse_geneve_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Geneve).map(|(_, s)| ParsedField::Protocol(Protocol::Geneve, (s.start, s.len()))),
        (tag(Token::Vni), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Vni(v, (s.start, s.end - s.start))),
        (tag(Token::OptClass), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::OptClass(v, (s.start, s.end - s.start))),
        (tag(Token::OptType), cut_err(parse_u8)).map(|((_, s), v)| ParsedField::OptType(v, (s.start, s.end - s.start))),
        (tag(Token::ProtocolType), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::ProtocolType(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
