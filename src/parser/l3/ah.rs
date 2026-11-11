//! IPsec Authentication Header (`ah`, RFC 4302) Layer 3 security protocol parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4302 `ah` connectionless
//! integrity and data origin authentication headers in FrameAssembly `.fasm` specifications. It
//! recognizes the `ah` protocol keyword as well as shared IPsec Security Association parameters,
//! including Security Parameter Index (`spi`), sequence number (`seq`), Integrity Check Value
//! (`icv`), and encapsulated `nextheader` protocol number via [`super::ipsec::parse_ipsec_field`].

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, tag};

/// Parses an AH protocol declaration or IPsec parameter field.
pub(crate) fn parse_ah_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ah).map(|(_, s)| ParsedField::Protocol(Protocol::Ah, (s.start, s.len()))),
        super::ipsec::parse_ipsec_field,
    ))
    .parse_next(input)
}
