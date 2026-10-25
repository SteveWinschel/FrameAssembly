//! IEEE 802.1Q Virtual Local Area Network (`VLAN`) tag parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for IEEE 802.1Q single-tagged Ethernet
//! frames and cross-layer VLAN modifiers. It parses 12-bit VLAN identifiers (`VLAN <vid>`),
//! 3-bit Priority Code Point values (`PCP <0..7>`), and 1-bit Drop Eligible Indicator flags
//! (`DEI <0..1>`) into spanned [`ParsedField`] variants for semantic range verification.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u32, tag};

/// Parses a VLAN tag or modifier field.
pub(crate) fn parse_vlan_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::Vlan), opt(parse_u32))
            .map(|((_, s), v)| ParsedField::Vlan(v.unwrap_or(1), (s.start, s.end - s.start))),
        (tag(Token::Pcp), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Pcp(v, (s.start, s.end - s.start))),
        (tag(Token::Dei), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Dei(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
