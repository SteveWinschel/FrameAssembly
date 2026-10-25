//! Remote Authentication Dial-In User Service (RADIUS) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 2865 and RFC 2866 `RADIUS`
//! authentication and accounting packets in FrameAssembly `.fasm` specifications. It recognizes
//! the `RADIUS` protocol keyword, packet code shorthands (`ACCESS_REQUEST`, `ACCESS_ACCEPT`,
//! `ACCESS_REJECT`, `ACCESS_CHALLENGE`, `ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE`), explicit
//! `CODE` strings, packet identifiers (`ID`), usernames (`USER`), NAS IP addresses (`NAS_IP`),
//! service types (`SERVICE_TYPE`), and framed client IP addresses (`FRAMED_IP`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_str_val, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a RADIUS protocol declaration or AAA attribute field.
pub(crate) fn parse_radius_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Radius)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Radius, (s.start, s.len()))),
            tag(Token::AccessRequest).map(|(_, s)| {
                ParsedField::L7StringField("CODE", "ACCESS_REQUEST", (s.start, s.len()))
            }),
            tag(Token::AccessAccept).map(|(_, s)| {
                ParsedField::L7StringField("CODE", "ACCESS_ACCEPT", (s.start, s.len()))
            }),
            tag(Token::AccessReject).map(|(_, s)| {
                ParsedField::L7StringField("CODE", "ACCESS_REJECT", (s.start, s.len()))
            }),
            tag(Token::AccessChallenge).map(|(_, s)| {
                ParsedField::L7StringField("CODE", "ACCESS_CHALLENGE", (s.start, s.len()))
            }),
            tag(Token::AccountingRequest).map(|(_, s)| {
                ParsedField::L7StringField("CODE", "ACCOUNTING_REQUEST", (s.start, s.len()))
            }),
            tag(Token::AccountingResponse).map(|(_, s)| {
                ParsedField::L7StringField("CODE", "ACCOUNTING_RESPONSE", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Code), parse_str_val)
                .map(|((_, s), v)| ParsedField::L7StringField("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::Id), parse_u16)
                .map(|((_, s), v)| ParsedField::IcmpId(v, (s.start, s.end - s.start))),
            (tag(Token::User), parse_str_val)
                .map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
            (tag(Token::NasIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("NAS_IP", v, (s.start, s.end - s.start))),
            (tag(Token::ServiceType), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SERVICE_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::FramedIp), cut_err(parse_ip)).map(|((_, s), v)| {
                ParsedField::L7IpField("FRAMED_IP", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
