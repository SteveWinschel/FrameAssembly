//! Encapsulated Remote Switch Port Analyzer (`erspan`, Type II `0x88BE` / Type III `0x22EB`) parser.
//!
//! This module implements the winnow parser combinator for `erspan` GRE-encapsulated traffic
//! mirroring frames (IP protocol `47`). It parses ERSPAN version selectors (`v2`, `v3`, or
//! `version <2|3>`), monitor session identifiers (`sessionid <u16>`), mirrored VLAN IDs
//! (`vid <u16>`), Class of Service values (`cos <u8>`), GRE sequence numbers (`greseq <u32>`),
//! Type II port indices (`index <u32>`), and Type III `timestamp` and `direction` fields.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u32, tag};

/// Parses an ERSPAN protocol declaration or Type II/III header field.
pub(crate) fn parse_erspan_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Erspan)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Erspan, (s.start, s.len()))),
            tag(Token::V2)
                .map(|(_, s)| ParsedField::L7U32Field("ERSPAN_VERSION", 2, (s.start, s.len()))),
            tag(Token::V3)
                .map(|(_, s)| ParsedField::L7U32Field("ERSPAN_VERSION", 3, (s.start, s.len()))),
            (tag(Token::Version), cut_err(parse_u32.verify(|v| *v == 2 || *v == 3))).map(
                |((_, s), v)| {
                    ParsedField::L7U32Field("ERSPAN_VERSION", v, (s.start, s.end - s.start))
                },
            ),
            (tag(Token::SessionId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERSPAN_SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Vid), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERSPAN_VID", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Cos), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERSPAN_COS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::GreSeq), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::GreSeq(v, (s.start, s.end - s.start))),
            (tag(Token::Index), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERSPAN_INDEX", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Timestamp), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERSPAN_TIMESTAMP", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Direction), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERSPAN_DIRECTION", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
