//! Hypertext Transfer Protocol (HTTP/1.1) Layer 7 web protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 9112 `HTTP` request and response
//! messages in FrameAssembly `.fasm` specifications. It recognizes the `HTTP` protocol keyword,
//! explicit `METHOD` verbs and shorthand HTTP method tokens (`GET`, `POST`, `PUT`, `DELETE`,
//! `HEAD`, `OPTIONS`, `PATCH`), request targets (`URI`), protocol versions (`VERSION`), header
//! shorthands (`HOST_HDR`, `USER_AGENT`, `CONTENT_TYPE`), arbitrary `HEADER <k> <v>` pairs, status
//! codes (`STATUS`), reason phrases (`REASON`), and message bodies (`BODY`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an HTTP protocol declaration or request/response header field.
pub(crate) fn parse_http_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Http)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Http, (s.start, s.len()))),
            tag(Token::Get)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "GET", (s.start, s.len()))),
            tag(Token::Post)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "POST", (s.start, s.len()))),
            tag(Token::Put)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "PUT", (s.start, s.len()))),
            tag(Token::Delete)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "DELETE", (s.start, s.len()))),
            tag(Token::Head)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "HEAD", (s.start, s.len()))),
            tag(Token::Options)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "OPTIONS", (s.start, s.len()))),
            tag(Token::Patch)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "PATCH", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Uri), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("URI", v, (s.start, s.end - s.start))),
            (tag(Token::Version), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::HostHdr), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("HOST_HDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::UserAgent), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("USER_AGENT", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
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
            (tag(Token::Header), cut_err((parse_str_val, parse_str_val))).map(
                |((_, s), (k, v))| ParsedField::L7Header(k, v, (s.start, s.end - s.start)),
            ),
        )),
    ))
    .parse_next(input)
}
