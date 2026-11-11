//! IPsec Encapsulating Security Payload (`esp`, RFC 4303) Layer 3 security protocol parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4303 `esp` confidentiality and
//! authenticated encryption headers in FrameAssembly `.fasm` specifications. It recognizes the
//! `esp` protocol keyword as well as shared IPsec Security Association parameters, including
//! Security Parameter Index (`spi`), sequence number (`seq`), Initialization Vector (`iv`),
//! Integrity Check Value (`icv`), and `nextheader` via [`super::ipsec::parse_ipsec_field`].

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
