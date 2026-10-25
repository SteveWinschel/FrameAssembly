//! Redis Serialization Protocol (RESP2 and RESP3) Layer 7 in-memory cache field parser.
//!
//! This module implements the `winnow` parser combinator for `REDIS` RESP command arrays and
//! server replies in FrameAssembly `.fasm` specifications. It recognizes the `REDIS` protocol
//! keyword, shorthand `GET` and `SET` command keywords, explicit `CMD` strings, command arguments
//! (`ARGS` and `KEY`), RESP reply type designators (`REPLY_TYPE`, e.g., `"SIMPLE"`, `"BULK"`,
//! `"INT"`, `"ERR"`), and response values (`VALUE`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, tag, ParsedField, Stream};

/// Parses a Redis protocol declaration or RESP command field.
pub(crate) fn parse_redis_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Redis)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Redis, (s.start, s.len()))),
        tag(Token::Get)
            .map(|(_, s)| ParsedField::L7StringField("CMD", "GET", (s.start, s.len()))),
        tag(Token::Set)
            .map(|(_, s)| ParsedField::L7StringField("CMD", "SET", (s.start, s.len()))),
        (tag(Token::Cmd), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Key), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::L7StringField("KEY", v, (s.start, s.end - s.start))),
        (tag(Token::Args), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::L7StringField("ARGS", v, (s.start, s.end - s.start))),
        (tag(Token::ReplyType), cut_err(parse_any_str)).map(|((_, s), v)| {
            ParsedField::L7StringField("REPLY_TYPE", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Value), parse_str_val)
            .map(|((_, s), v)| ParsedField::L7StringField("VALUE", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
