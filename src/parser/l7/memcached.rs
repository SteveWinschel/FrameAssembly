//! Memcached Layer 7 distributed memory caching protocol field parser.
//!
//! This module implements the `winnow` parser combinator for `MEMCACHED` text and binary protocol
//! frames in FrameAssembly `.fasm` specifications. It recognizes the `MEMCACHED` protocol keyword,
//! shorthand `GET` and `SET` command keywords, explicit `CMD` strings, cache keys (`KEY`), data
//! payloads (`VALUE`), client-specific flags (`FLAGS`), expiration times (`EXPTIME`), request
//! correlation tokens (`OPAQUE`), and compare-and-swap 64-bit identifiers (`CAS`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses a Memcached protocol declaration or binary/text command field.
pub(crate) fn parse_memcached_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Memcached)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Memcached, (s.start, s.len()))),
            tag(Token::Get)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "GET", (s.start, s.len()))),
            tag(Token::Set)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "SET", (s.start, s.len()))),
            (tag(Token::Cmd), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
            (tag(Token::Key), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("KEY", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Value), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("VALUE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("FLAGS", v, (s.start, s.end - s.start))),
            (tag(Token::Exptime), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("EXPTIME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Opcode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OPCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Opaque), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OPAQUE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cas), cut_err(parse_u64))
                .map(|((_, s), v)| ParsedField::L7U64Field("CAS", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
