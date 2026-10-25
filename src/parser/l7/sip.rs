//! Session Initiation Protocol (SIP) Layer 7 VoIP signaling field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 3261 `SIP` multimedia session
//! signaling messages in FrameAssembly `.fasm` specifications. It recognizes the `SIP` protocol
//! keyword, shorthand method tokens (`INVITE`, `ACK`, `BYE`, `CANCEL`, `REGISTER`, `OPTIONS`),
//! explicit `METHOD` strings, request `URI` targets, signaling headers (`FROM`, `TO`, `CALL_ID`,
//! `CSEQ`, `VIA`, `CONTACT`, `CONTENT_TYPE`), response `STATUS` and `REASON`, and SDP `BODY`
//! payloads.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a SIP protocol declaration or message header field.
pub(crate) fn parse_sip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Sip).map(|(_, s)| ParsedField::Protocol(Protocol::Sip, (s.start, s.len()))),
            tag(Token::Invite)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "INVITE", (s.start, s.len()))),
            tag(Token::Ack)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "ACK", (s.start, s.len()))),
            tag(Token::Bye)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "BYE", (s.start, s.len()))),
            tag(Token::Cancel)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "CANCEL", (s.start, s.len()))),
            tag(Token::Register)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "REGISTER", (s.start, s.len()))),
            tag(Token::Options)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "OPTIONS", (s.start, s.len()))),
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Uri), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("URI", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::From), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("FROM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::To), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("TO", v, (s.start, s.end - s.start))),
            (tag(Token::CallId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("CALL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cseq), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CSEQ", v, (s.start, s.end - s.start))),
            (tag(Token::Via), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("VIA", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Contact), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("CONTACT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ContentType), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("CONTENT_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))),
            (tag(Token::Reason), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("REASON", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
