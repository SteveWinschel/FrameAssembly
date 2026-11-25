//! Oracle Transparent Network Substrate (TNS) Layer 7 database session field parser.
//!
//! This module implements the `winnow` parser combinator for Oracle `tns` connection setup,
//! session negotiation, redirection, query data, and error refusal frames in FrameAssembly
//! `.frasm` specifications. It recognizes the `tns` protocol keyword, packet type shorthands
//! (`connect`, `accept`, `refuse`, `redirect`, `data`, `marker`) and explicit `msgtype` strings,
//! protocol `version` numbers, Oracle `service` names and `sid` targets, SQL text (`sql`),
//! `flags`, and ORA `errcode` attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an Oracle TNS protocol declaration or session packet modifier field.
pub(crate) fn parse_tns_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Tns)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Tns, (s.start, s.len()))),
            tag(Token::Connect)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "CONNECT", (s.start, s.len()))),
            tag(Token::Accept)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ACCEPT", (s.start, s.len()))),
            tag(Token::Refuse)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "REFUSE", (s.start, s.len()))),
            tag(Token::Redirect).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "REDIRECT", (s.start, s.len()))
            }),
            tag(Token::Data)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "DATA", (s.start, s.len()))),
            tag(Token::Marker)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "MARKER", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::MsgType), parse_any_str).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Version), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Service), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SERVICE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Sid), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Sql), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SQL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("FLAGS", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
