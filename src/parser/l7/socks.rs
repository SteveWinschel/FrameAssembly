//! SOCKS Version 5 Proxy Protocol (RFC 1928 / RFC 1929) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for SOCKS5 (`socks`) proxy negotiation,
//! RFC 1929 username/password authentication, and `CONNECT` / `BIND` / `UDP ASSOCIATE` command
//! requests and replies in FrameAssembly `.frasm` specifications. It recognizes the `socks`
//! protocol keyword, `greeting` and `reply` direction flags, command shorthands (`connect`,
//! `bind`, `udpassociate`, `cmd`), `version`, `method`, `status`, target endpoints (`addr`,
//! `targetport`), and authentication credentials (`user`, `password`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a SOCKS5 protocol declaration or proxy negotiation field.
pub(crate) fn parse_socks_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Socks)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Socks, (s.start, s.len()))),
            tag(Token::Greeting)
                .map(|(_, s)| ParsedField::L7Flag("GREETING", (s.start, s.len()))),
            tag(Token::Reply)
                .map(|(_, s)| ParsedField::L7Flag("SOCKS_REPLY", (s.start, s.len()))),
            tag(Token::Connect)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "CONNECT", (s.start, s.len()))),
            tag(Token::Bind)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "BIND", (s.start, s.len()))),
            tag(Token::Udpassociate).map(|(_, s)| {
                ParsedField::L7StringField("CMD", "UDPASSOCIATE", (s.start, s.len()))
            }),
            (tag(Token::Cmd), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOCKS_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SOCKS_STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("SOCKS_ADDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TargetPort), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TARGET_PORT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::User), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("USER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Password), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("PASSWORD", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
