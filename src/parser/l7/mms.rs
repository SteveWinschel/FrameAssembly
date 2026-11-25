//! Manufacturing Message Specification (ISO 9506 / IEC 61850 MMS) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for ISO 9506 / IEC 61850 `mms`
//! substation automation frames over ISO-on-TCP port 102 in FrameAssembly `.frasm`
//! specifications. It recognizes the `mms` protocol keyword, explicit `service` selectors,
//! shorthand service keywords (`init`, `initack`, `getnamelist`, `read`, `write`, `report`,
//! `conclude`), response modifiers (`isresponse`, `response`), 32-bit confirmed `invokeid`
//! correlation tags, MMS `domain` and `item` identifiers, and integer data `value` modifiers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_str_val, parse_u32, tag};

/// Parses an MMS protocol declaration or ISO 9506 / IEC 61850 service field.
pub(crate) fn parse_mms_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mms).map(|(_, s)| ParsedField::Protocol(Protocol::Mms, (s.start, s.len()))),
            tag(Token::Init).map(|(_, s)| {
                ParsedField::L7StringField("SERVICE", "initiate", (s.start, s.len()))
            }),
            tag(Token::InitAck).map(|(_, s)| {
                ParsedField::L7StringField("SERVICE", "initiateresp", (s.start, s.len()))
            }),
            tag(Token::GetNameList).map(|(_, s)| {
                ParsedField::L7StringField("SERVICE", "getnamelist", (s.start, s.len()))
            }),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("SERVICE", "read", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7StringField("SERVICE", "write", (s.start, s.len()))),
            tag(Token::Report)
                .map(|(_, s)| ParsedField::L7StringField("SERVICE", "report", (s.start, s.len()))),
            tag(Token::Conclude).map(|(_, s)| {
                ParsedField::L7StringField("SERVICE", "conclude", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            (tag(Token::Service), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("SERVICE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::InvokeId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MMS_INVOKE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Domain), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("DOMAIN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Item), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("ITEM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Value), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
