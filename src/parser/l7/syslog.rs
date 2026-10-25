//! Syslog (RFC 5424 and RFC 3164) Layer 7 event logging protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 5424 structured `SYSLOG` event
//! messages in FrameAssembly `.fasm` specifications. It recognizes the `SYSLOG` protocol keyword,
//! facility codes (`FACILITY`), severity levels (`SEVERITY`), explicit priority values (`PRI`),
//! originating hostnames (`HOSTNAME`), application names (`APP`), process identifiers (`PROCID`),
//! message type identifiers (`MSGID`), and log message strings (`MSG`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a Syslog protocol declaration or RFC 5424 header field.
pub(crate) fn parse_syslog_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Syslog)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Syslog, (s.start, s.len()))),
            (tag(Token::Facility), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FACILITY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Severity), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEVERITY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Pri), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("PRI", v, (s.start, s.end - s.start))),
            (tag(Token::Hostname), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("HOSTNAME", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::App), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("APP", v, (s.start, s.end - s.start))),
            (tag(Token::Procid), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("PROCID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MsgId), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("MSGID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Msg), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("MSG", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
