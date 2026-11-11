//! Multi-Protocol Label Switching (`mpls`, RFC 3032) shim header parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for MPLS label-switched frame statements
//! and Layer 2.5 shim modifiers. It parses 20-bit label values (`mpls <label>` or `label <label>`),
//! 3-bit traffic class / experimental bits (`exp <0..7>`), 1-bit bottom-of-stack indicators
//! (`bos <0..1>`), and 8-bit label time-to-live values (`mplsttl <0..255>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u32, tag};

/// Parses an MPLS protocol declaration, label, or header field.
pub(crate) fn parse_mpls_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::Mpls), opt(parse_u32))
            .map(|((_, s), v)| ParsedField::Mpls(v.unwrap_or(0), (s.start, s.end - s.start))),
        (tag(Token::Label), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Mpls(v, (s.start, s.end - s.start))),
        (tag(Token::Exp), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Exp(v, (s.start, s.end - s.start))),
        (tag(Token::Bos), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Bos(v, (s.start, s.end - s.start))),
        (tag(Token::MplsTtl), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::MplsTtl(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
