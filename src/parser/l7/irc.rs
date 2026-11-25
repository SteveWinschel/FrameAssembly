//! Internet Relay Chat Protocol (IRC, RFC 1459 / RFC 2812) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1459 / RFC 2812 `irc` commands
//! and server replies in FrameAssembly `.frasm` specifications. It recognizes the `irc` protocol
//! keyword, sender prefixes (`prefix`), command verbs and shorthands (`nick`, `join`, `privmsg`,
//! `ping`, `pong`, `quit`, `cmd`), target channels or users (`channel`, `target`), middle
//! parameters (`param`), and trailing message strings (`msg`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_raw_string_lit, parse_str_val, tag, ParsedField, Stream};

/// Parses an IRC protocol declaration or chat command/reply field.
pub(crate) fn parse_irc_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Irc).map(|(_, s)| ParsedField::Protocol(Protocol::Irc, (s.start, s.len()))),
            (tag(Token::Nick), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("IRC_NICK_ARG", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Join), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("IRC_JOIN_ARG", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Privmsg), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("IRC_PRIVMSG_ARG", v, (s.start, s.end - s.start))
            }),
            tag(Token::Nick)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "NICK", (s.start, s.len()))),
            tag(Token::Join)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "JOIN", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Privmsg)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "PRIVMSG", (s.start, s.len()))),
            tag(Token::Ping)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "PING", (s.start, s.len()))),
            tag(Token::Pong)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "PONG", (s.start, s.len()))),
            tag(Token::Quit)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "QUIT", (s.start, s.len()))),
            (tag(Token::Cmd), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Prefix), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("IRC_PREFIX", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Channel), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("IRC_TARGET", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Target), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("IRC_TARGET", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Param), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("PARAM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Msg), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("MSG", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
