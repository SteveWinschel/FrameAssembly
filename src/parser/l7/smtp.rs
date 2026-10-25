//! Simple Mail Transfer Protocol (SMTP) Layer 7 electronic mail field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 5321 `SMTP` mail submission and
//! relay exchanges in FrameAssembly `.fasm` specifications. It recognizes the `SMTP` protocol
//! keyword, shorthand command verbs (`EHLO`, `HELO`, `MAIL_FROM`, `RCPT_TO`, `QUIT` with optional
//! inline string parameters), explicit `CMD` and `PARAM` attributes, 3-digit server status codes
//! (`CODE`), reply strings (`REPLY`), and message `BODY` content.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    parse_any_str, parse_raw_string_lit, parse_str_val, parse_u32, tag, ParsedField, Stream,
};

/// Parses an SMTP protocol declaration or mail exchange field.
pub(crate) fn parse_smtp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Smtp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Smtp, (s.start, s.len()))),
            (tag(Token::Ehlo), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("EHLO_PARAM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Helo), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("HELO_PARAM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::MailFrom), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("MAIL_FROM_PARAM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::RcptTo), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("RCPT_TO_PARAM", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            tag(Token::Ehlo)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "EHLO", (s.start, s.len()))),
            tag(Token::Helo)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "HELO", (s.start, s.len()))),
            tag(Token::MailFrom)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "MAIL FROM", (s.start, s.len()))),
            tag(Token::RcptTo)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "RCPT TO", (s.start, s.len()))),
            tag(Token::Quit)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "QUIT", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Cmd), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
            (tag(Token::Param), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("PARAM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Code), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::Reply), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("REPLY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
