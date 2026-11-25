//! Diameter Base Protocol (RFC 6733) Layer 7 winnow parser combinators.
//!
//! This module implements protocol-scoped parsing for `diameter` frame declarations and modifiers
//! including message shorthands (`cer`, `cea`, `dwr`, `dwa`, `ccr`, `cca`), header parameters
//! (`cmd`, `flags`, `appid`, `hopid`, `endid`, `request`, `response`), and core AVP selectors
//! (`originhost`, `realm`, `dsthost`, `dstrealm`, `sessionid`, `resultcode`, `user`) within
//! strict `winnow` 8-arm `alt` constraints.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u8, parse_u32, tag};

/// Parses a borrowed decimal `u32` token string (`&'a str`) for numeric Diameter commands.
fn parse_cmd_num_str<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    any.verify_map(|(t, _, _)| match t {
        Token::Number(s) if s.parse::<u32>().is_ok() => Some(s),
        _ => None,
    })
    .parse_next(input)
}

/// Parses Diameter protocol header flags and command shorthands (`<= 8` `alt` arms).
fn parse_diameter_head<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Diameter).map(|(_, s)| ParsedField::Protocol(Protocol::Diameter, (s.start, s.end - s.start))),
        tag(Token::Cer).map(|(_, s)| ParsedField::L7Flag("cer", (s.start, s.end - s.start))),
        tag(Token::Cea).map(|(_, s)| ParsedField::L7Flag("cea", (s.start, s.end - s.start))),
        tag(Token::Dwr).map(|(_, s)| ParsedField::L7Flag("dwr", (s.start, s.end - s.start))),
        tag(Token::Dwa).map(|(_, s)| ParsedField::L7Flag("dwa", (s.start, s.end - s.start))),
        tag(Token::Ccr).map(|(_, s)| ParsedField::L7Flag("ccr", (s.start, s.end - s.start))),
        tag(Token::Cca).map(|(_, s)| ParsedField::L7Flag("cca", (s.start, s.end - s.start))),
        tag(Token::Request).map(|(_, s)| ParsedField::L7Flag("request", (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses Diameter header numeric and command modifiers (`<= 8` `alt` arms).
fn parse_diameter_header_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("response", (s.start, s.end - s.start))),
        (
            alt((tag(Token::Cmd), tag(Token::Command))),
            cut_err(alt((parse_cmd_num_str, parse_any_str))),
        )
            .map(|((_, s), v)| {
                ParsedField::L7StringField("cmd", v, (s.start, s.end - s.start))
            }),
        (tag(Token::Flags), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
        (tag(Token::AppId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("app_id", v, (s.start, s.end - s.start))),
        (tag(Token::HopId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("hop_id", v, (s.start, s.end - s.start))),
        (tag(Token::EndId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("end_id", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses Diameter AVP string and unsigned integer modifiers (`<= 8` `alt` arms).
fn parse_diameter_avp_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::OriginHost), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("origin_host", v, (s.start, s.end - s.start))),
        (tag(Token::Realm), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("origin_realm", v, (s.start, s.end - s.start))),
        (tag(Token::DstHost), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("dst_host", v, (s.start, s.end - s.start))),
        (tag(Token::DstRealm), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("dst_realm", v, (s.start, s.end - s.start))),
        (tag(Token::SessionId), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("session_id", v, (s.start, s.end - s.start))),
        (tag(Token::ResultCode), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("result_code", v, (s.start, s.end - s.start))),
        (tag(Token::User), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses a `diameter` protocol keyword or one of its RFC 6733 header/AVP modifier fields.
pub(crate) fn parse_diameter_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        parse_diameter_head,
        parse_diameter_header_mods,
        parse_diameter_avp_mods,
    ))
    .parse_next(input)
}
