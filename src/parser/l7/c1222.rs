//! ANSI C12.22 / IEEE 1703 Smart Grid metering Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for ANSI `c1222` ACSE + EPSEM smart
//! meter messages over UDP and TCP port 1153 in FrameAssembly `.frasm` specifications. It
//! recognizes the `c1222` protocol keyword, EPSEM service selectors (`read`, `write`, `identify`,
//! `logon`, `logoff`, `terminate`, `response`, `ok`, `service`), ACSE Application Process Titles
//! (`callingap`, `calledap` as dotted numeric OIDs), invocation identifiers (`callingid`,
//! `calledid`), EPSEM control bytes (`epsemctrl`), device classes (`edclass`), C12.19 table
//! numbers (`tableid`), values (`value`), and response codes (`errcode`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_raw_string_lit, parse_u32, tag};

/// Validates a dotted numeric ASN.1 Object Identifier string (`arc0.arc1...`, `arc0 <= 2`).
fn is_valid_c1222_oid(raw: &str) -> bool {
    let mut parts = raw.split('.');
    let Some(a0) = parts.next().and_then(|s| s.parse::<u32>().ok()) else {
        return false;
    };
    let Some(a1) = parts.next().and_then(|s| s.parse::<u32>().ok()) else {
        return false;
    };
    if a0 > 2 || (a0 < 2 && a1 >= 40) || u32::checked_add(80, a1).is_none() {
        return false;
    }
    parts.all(|p| p.parse::<u32>().is_ok())
}

/// Parses an ASN.1 OID literal for `callingap` / `calledap` from an OID, IPv4, or quoted string.
fn parse_c1222_oid<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    alt((
        parse_raw_string_lit.verify(is_valid_c1222_oid),
        any.verify_map(|(t, _, _)| match t {
            Token::OidStr(s) | Token::IpAddress(s) if is_valid_c1222_oid(s) => Some(s),
            _ => None,
        }),
    ))
    .parse_next(input)
}

/// Parses an ANSI C12.22 protocol declaration or ACSE/EPSEM metering field.
pub(crate) fn parse_c1222_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::C1222)
                .map(|(_, s)| ParsedField::Protocol(Protocol::C1222, (s.start, s.len()))),
            tag(Token::Read).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "READ", (s.start, s.len()))
            }),
            tag(Token::Write).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "WRITE", (s.start, s.len()))
            }),
            tag(Token::Identify).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "IDENTIFY", (s.start, s.len()))
            }),
            tag(Token::Logon).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "LOGON", (s.start, s.len()))
            }),
            tag(Token::Logoff).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "LOGOFF", (s.start, s.len()))
            }),
            tag(Token::Terminate).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "TERMINATE", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::Response).map(|(_, s)| {
                ParsedField::L7StringField("C1222_SERVICE", "RESPONSE", (s.start, s.len()))
            }),
            tag(Token::Ok)
                .map(|(_, s)| ParsedField::L7StringField("C1222_SERVICE", "OK", (s.start, s.len()))),
            (tag(Token::Service), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("C1222_SERVICE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CallingAp), cut_err(parse_c1222_oid)).map(|((_, s), v)| {
                ParsedField::L7StringField("C1222_CALLING_AP", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CalledAp), cut_err(parse_c1222_oid)).map(|((_, s), v)| {
                ParsedField::L7StringField("C1222_CALLED_AP", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CallingId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("C1222_CALLING_ID", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::CalledId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("C1222_CALLED_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::EpsemCtrl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("C1222_EPSEM_CTRL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::EdClass), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("C1222_ED_CLASS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TableId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("C1222_TABLE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("C1222_ERRCODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
