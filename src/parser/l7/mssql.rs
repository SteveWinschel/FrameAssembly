//! Microsoft SQL Server Tabular Data Stream (MS-TDS, TCP port `1433`) Layer 7 parser combinators.
//!
//! This module implements protocol-scoped winnow parsing for `mssql` frame declarations and
//! modifiers including packet selectors (`prelogin`, `login`, `query`, `ok`, `err`, `attention`,
//! `response`, `pkttype`), `LOGIN7` identity fields (`user`, `db`), SQL text (`sql`), error codes
//! (`errcode`), and TDS header selectors (`spid`, `pktid`) respecting `winnow` 8-arm limits.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u8, parse_u16, parse_u32, tag};

/// Parses a borrowed decimal `u8` token string (`&'a str`) for numeric MS-TDS packet types.
fn parse_pkttype_num_str<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    any.verify_map(|(t, _, _)| match t {
        Token::Number(s) if s.parse::<u8>().is_ok() => Some(s),
        _ => None,
    })
    .parse_next(input)
}

/// Parses primary MS-TDS keyword and packet-type shorthand flags (`<= 8` `alt` arms).
fn parse_mssql_head<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Mssql).map(|(_, s)| ParsedField::Protocol(Protocol::Mssql, (s.start, s.end - s.start))),
        tag(Token::Prelogin).map(|(_, s)| ParsedField::L7Flag("prelogin", (s.start, s.end - s.start))),
        tag(Token::Login).map(|(_, s)| ParsedField::L7Flag("login", (s.start, s.end - s.start))),
        tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("query", (s.start, s.end - s.start))),
        tag(Token::Ok).map(|(_, s)| ParsedField::L7Flag("ok", (s.start, s.end - s.start))),
        tag(Token::Err).map(|(_, s)| ParsedField::L7Flag("err", (s.start, s.end - s.start))),
        tag(Token::Attention).map(|(_, s)| ParsedField::L7Flag("attention", (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses MS-TDS field modifiers and header controls (`<= 8` `alt` arms).
fn parse_mssql_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("ok", (s.start, s.end - s.start))),
        (
            tag(Token::PktType),
            cut_err(alt((parse_pkttype_num_str, parse_any_str))),
        )
            .map(|((_, s), v)| {
                ParsedField::L7StringField("pkt_type", v, (s.start, s.end - s.start))
            }),
        (tag(Token::User), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
        (tag(Token::Db), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("db", v, (s.start, s.end - s.start))),
        (tag(Token::Sql), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("sql", v, (s.start, s.end - s.start))),
        (tag(Token::ErrCode), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("errcode", v, (s.start, s.end - s.start))),
        (tag(Token::Spid), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::L7U32Field("spid", v as u32, (s.start, s.end - s.start))),
        (tag(Token::PktId), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::L7U32Field("pkt_id", v as u32, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses an `mssql` protocol keyword or one of its MS-TDS modifier fields.
pub(crate) fn parse_mssql_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((parse_mssql_head, parse_mssql_mods)).parse_next(input)
}
