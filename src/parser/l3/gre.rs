//! Generic Routing Encapsulation (`GRE`, RFC 2784 / RFC 2890) tunnel parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `GRE` IP tunnel headers. It parses
//! optional RFC 2890 tunnel keys (`GRE_KEY` or `KEY`), sequence numbers (`GRE_SEQ`), inner
//! EtherType protocol identifiers (`GRE_PROTO`), and optional RFC 2784 header checksum enablement
//! (`CHECKSUM`) into spanned [`ParsedField`] AST modifiers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u16, parse_u32, tag};

/// Parses a GRE protocol declaration or header field.
pub(crate) fn parse_gre_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Gre).map(|(_, s)| ParsedField::Protocol(Protocol::Gre, (s.start, s.len()))),
        (alt((tag(Token::GreKey), tag(Token::Key))), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::GreKey(v, (s.start, s.end - s.start))),
        (tag(Token::GreSeq), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::GreSeq(v, (s.start, s.end - s.start))),
        (tag(Token::GreProto), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::GreProto(v, (s.start, s.end - s.start))),
        tag(Token::Checksum).map(|(_, s)| ParsedField::ChecksumFlag((s.start, s.len()))),
    ))
    .parse_next(input)
}
