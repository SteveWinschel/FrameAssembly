//! Emerson ROC Plus (ROC+) SCADA RTU Layer 7 field parser.
//!
//! This module implements the `winnow` combinator parser for Emerson Bristol `rocplus` messages
//! over TCP or UDP port 4000 in FrameAssembly `.frasm` specifications. It recognizes the `rocplus`
//! protocol keyword, opcode shorthands (`read`, `write`, `error`) and explicit `opcode` / `func`
//! descriptors, RTU unit and group addressing (`dst`, `group`, `src`), Type-Logical-Parameter
//! selectors (`type`, `addr`, `param`), 32-bit `value` fields, `isresponse` markers, and 16-bit
//! `crc` overrides.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses a ROC+ protocol declaration or RTU TLP parameter field.
pub(crate) fn parse_rocplus_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rocplus)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Rocplus, (s.start, s.len()))),
            tag(Token::Read).map(|(_, s)| {
                ParsedField::L7StringField("ROC_OPCODE", "read", (s.start, s.len()))
            }),
            tag(Token::Write).map(|(_, s)| {
                ParsedField::L7StringField("ROC_OPCODE", "write", (s.start, s.len()))
            }),
            tag(Token::ErrorKw).map(|(_, s)| {
                ParsedField::L7StringField("ROC_OPCODE", "error", (s.start, s.len()))
            }),
            (tag(Token::Opcode), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ROC_OPCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Func), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ROC_OPCODE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Dst), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROC_DST", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Group), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("GROUP", v, (s.start, s.end - s.start))),
            (tag(Token::Src), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROC_SRC", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Type), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROC_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROC_ADDR", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Param), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ROC_PARAM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            (tag(Token::Crc), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CRC", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
