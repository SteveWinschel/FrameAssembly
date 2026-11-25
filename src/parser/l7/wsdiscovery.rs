//! Web Services Dynamic Discovery (WS-Discovery OASIS 1.1) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for OASIS WS-Discovery (`wsdiscovery`)
//! SOAP-over-UDP discovery datagrams in FrameAssembly `.frasm` specifications. It recognizes the
//! `wsdiscovery` protocol keyword, action shorthands (`probe`, `hello`, `msgtype`), WS-Addressing
//! `MessageID` (`msgid`) and endpoint reference addresses (`addr`), device `types`, `scopes`, and
//! service transport URLs (`xaddrs`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, tag, ParsedField, Stream};

/// Parses a WS-Discovery protocol declaration or SOAP discovery field.
pub(crate) fn parse_wsdiscovery_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Wsdiscovery)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Wsdiscovery, (s.start, s.len()))),
            tag(Token::Probe)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "probe", (s.start, s.len()))),
            tag(Token::Hello)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "hello", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSGID", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Types), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("TYPES", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Scopes), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SCOPES", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Xaddrs), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("XADDRS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("WSD_ADDR", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
