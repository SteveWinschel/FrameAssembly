//! Segment Routing over IPv6 (`srv6`, RFC 8754 Segment Routing Header) parser.
//!
//! This module implements the winnow parser combinator for `srv6` IPv6 Segment Routing Header
//! packets (IPv6 Next Header `43`, Routing Type `4`). It parses the `srv6` protocol keyword,
//! upper-layer `nextheader <u8>`, active `segleft <u8>`, 8-bit `flags <u8>`, 16-bit `tag <u16>`,
//! and repeatable 128-bit Segment ID entries (`sid <ipv6>`) into spanned [`ParsedField`] entries.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u8, parse_u32, tag};

/// Parses an SRv6 protocol declaration or Segment Routing Header field.
pub(crate) fn parse_srv6_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Srv6).map(|(_, s)| ParsedField::Protocol(Protocol::Srv6, (s.start, s.len()))),
        (tag(Token::NextHeader), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::NextHeader(v, (s.start, s.end - s.start))),
        (tag(Token::SegLeft), cut_err(parse_u32)).map(|((_, s), v)| {
            ParsedField::L7U32Field("SRV6_SEG_LEFT", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Flags), cut_err(parse_u32)).map(|((_, s), v)| {
            ParsedField::L7U32Field("SRV6_FLAGS", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Tag), cut_err(parse_u32)).map(|((_, s), v)| {
            ParsedField::L7U32Field("SRV6_TAG", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Sid), cut_err(parse_ip)).map(|((_, s), v)| {
            ParsedField::L7IpField("SRV6_SID", v, (s.start, s.end - s.start))
        }),
    ))
    .parse_next(input)
}
