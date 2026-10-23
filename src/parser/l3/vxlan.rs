//! VXLAN Layer 3 overlay tunnel protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, tag, ParsedField, Stream};

/// Parses a VXLAN protocol declaration or VNI field.
pub(crate) fn parse_vxlan_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Vxlan).map(|(_, s)| ParsedField::Protocol(Protocol::Vxlan, (s.start, s.len()))),
        (tag(Token::Vni), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Vni(v, (s.start, s.end - s.start))),
        (tag(Token::Vnid), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Vni(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
