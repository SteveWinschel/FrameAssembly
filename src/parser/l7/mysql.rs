//! MySQL Client/Server Wire Protocol Layer 7 database field parser.
//!
//! This module implements the `winnow` parser combinator for `MYSQL` connection handshakes,
//! authentication packets, SQL command queries, and server result packets in FrameAssembly `.fasm`
//! specifications. It recognizes the `MYSQL` protocol keyword, packet type flags (`GREETING`,
//! `LOGIN`, `QUERY`, `OK`, `ERR`, `EOF`), SQL query strings (`SQL`), server version banners
//! (`SERVER_VERSION`), login usernames (`USER`), database schemas (`DB`), and numeric error codes
//! (`ERRCODE`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a MySQL protocol declaration or query/handshake field.
pub(crate) fn parse_mysql_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mysql)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Mysql, (s.start, s.len()))),
            tag(Token::Greeting).map(|(_, s)| ParsedField::L7Flag("GREETING", (s.start, s.len()))),
            tag(Token::Login).map(|(_, s)| ParsedField::L7Flag("LOGIN", (s.start, s.len()))),
            tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("QUERY", (s.start, s.len()))),
            (tag(Token::Sql), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("SQL", v, (s.start, s.end - s.start))),
            tag(Token::Ok).map(|(_, s)| ParsedField::L7Flag("OK", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Err).map(|(_, s)| ParsedField::L7Flag("ERR", (s.start, s.len()))),
            tag(Token::Eof).map(|(_, s)| ParsedField::L7Flag("EOF", (s.start, s.len()))),
            (tag(Token::User), parse_str_val)
                .map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
            (tag(Token::ServerVersion), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SERVER_VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Db), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("DB", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
