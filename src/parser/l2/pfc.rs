//! IEEE 802.1Qbb Priority Flow Control (`pfc`) MAC Control parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for IEEE 802.1Qbb Priority Flow Control
//! (`pfc`, EtherType `0x8808`, OpCode `0x0101`) frames. It recognizes the `pfc` protocol keyword,
//! the 16-bit Class Enable Vector (`enable <u16>`), the uniform pause duration in 512-bit quanta
//! (`quanta <u16>`), and individual IEEE 802.1p priority queue pause overrides (`q0` through `q7`)
//! mapped cleanly onto `ParsedField::L7U32Field` variants.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u16, tag};

/// Parses a PFC protocol declaration, enable vector, uniform quanta, or per-class timer field.
pub(crate) fn parse_pfc_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Pfc).map(|(_, s)| ParsedField::Protocol(Protocol::Pfc, (s.start, s.len()))),
            (tag(Token::Enable), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_ENABLE", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Quanta), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_QUANTA", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q0), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q0", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q1), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q1", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q2), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q2", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Q3), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q3", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q4), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q4", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q5), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q5", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q6), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q6", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Q7), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PFC_Q7", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
