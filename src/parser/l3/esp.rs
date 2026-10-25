//! IPsec Encapsulating Security Payload (`ESP`, RFC 4303) Layer 3 security protocol parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4303 `ESP` confidentiality and
//! authenticated encryption headers in FrameAssembly `.fasm` specifications. It recognizes the
//! `ESP` protocol keyword as well as shared IPsec Security Association parameters, including
//! Security Parameter Index (`SPI`), sequence number (`SEQ`), Initialization Vector (`IV`),
//! Integrity Check Value (`ICV`), and `NEXT_HEADER` via [`super::ipsec::parse_ipsec_field`].

use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, tag};

/// Parses an ESP protocol declaration or IPsec parameter field.
pub(crate) fn parse_esp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Esp).map(|(_, s)| ParsedField::Protocol(Protocol::Esp, (s.start, s.len()))),
        super::ipsec::parse_ipsec_field,
    ))
    .parse_next(input)
}
