//! Cisco Gateway Load Balancing Protocol (`glbp`) parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for Cisco GLBP gateway redundancy and
//! active-active load-sharing packets carried over UDP port `3222`. It parses the `glbp` protocol
//! keyword, message/TLV kinds (`hello`, `request`, `response`), `version <u8>`, standby `group <u16>`,
//! physical router `ownerid <mac>`, VG/VF `state <u8>`, `priority <u8>`, `weight <u8>`,
//! `forwarder <u8>`, millisecond timers (`hellotime <u32>`, `holdtime <u32>`), second timers
//! (`redirect <u16>`, `timeout <u16>`), virtual gateway `vip <ip>`, virtual forwarder `vmac <mac>`,
//! and plain-text authentication (`auth "<str>"`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_ip, parse_mac, parse_str_val, parse_u8, parse_u16, parse_u32, tag,
};

/// Parses a GLBP protocol declaration, TLV flavor, or gateway/forwarder field.
pub(crate) fn parse_glbp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Glbp).map(|(_, s)| ParsedField::Protocol(Protocol::Glbp, (s.start, s.len()))),
            tag(Token::Hello)
                .map(|(_, s)| ParsedField::L7StringField("GLBP_TYPE", "HELLO", (s.start, s.len()))),
            tag(Token::Request).map(|(_, s)| {
                ParsedField::L7StringField("GLBP_TYPE", "REQUEST", (s.start, s.len()))
            }),
            tag(Token::Response).map(|(_, s)| {
                ParsedField::L7StringField("GLBP_TYPE", "RESPONSE", (s.start, s.len()))
            }),
            (tag(Token::Version), parse_u8)
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (tag(Token::Group), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_GROUP", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::OwnerId), cut_err(parse_mac)).map(|((_, s), v)| {
                ParsedField::L7MacField("GLBP_OWNER_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::State), parse_u8).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_STATE", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Priority), parse_u8).map(|((_, s), v)| {
                ParsedField::PriorityVal(u16::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Weight), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_WEIGHT", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Forwarder), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_FORWARDER", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::HelloTime), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_HELLO_TIME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::HoldTime), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_HOLD_TIME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Redirect), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_REDIRECT", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Timeout), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("GLBP_TIMEOUT", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Vip), parse_ip)
                .map(|((_, s), v)| ParsedField::Vip(v, (s.start, s.end - s.start))),
            (tag(Token::Vmac), cut_err(parse_mac)).map(|((_, s), v)| {
                ParsedField::L7MacField("GLBP_VMAC", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Auth), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("GLBP_AUTH", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
