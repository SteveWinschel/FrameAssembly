//! Virtual eXtensible Local Area Network (`VXLAN`, RFC 7348) overlay tunnel parser.
//!
//! This module implements the winnow parser combinator for `VXLAN` UDP-encapsulated Layer 2
//! overlay frames. It parses the `VXLAN` protocol keyword and 24-bit Virtual Network Identifier
//! modifiers (`VNI <u32>` or `VNID <u32>`) into spanned [`ParsedField`] nodes for downstream
//! VXLAN header and inner frame construction.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u32, tag};

/// Parses a VXLAN protocol declaration or VNI field.
pub(crate) fn parse_vxlan_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Vxlan).map(|(_, s)| ParsedField::Protocol(Protocol::Vxlan, (s.start, s.len()))),
        (tag(Token::Vni), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Vni(v, (s.start, s.end - s.start))),
        (tag(Token::Vnid), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Vni(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
