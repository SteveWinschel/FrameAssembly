//! MongoDB Wire Protocol (`OP_MSG`) Layer 7 document database field parser.
//!
//! This module implements the `winnow` parser combinator for `mongodb` `OP_MSG` (`opCode = 2013`)
//! request and response packets in FrameAssembly `.frasm` specifications. It recognizes the
//! `mongodb` protocol keyword, shorthand command and reply flags (`ping`, `query`, `response`,
//! `ok`, `err`), explicit command names (`cmd`), target collections (`collection`) and databases
//! (`db`), query filters (`filter`), wire correlation IDs (`reqid`, `responseto`), `flagBits`
//! (`flags`), and error attributes (`errcode`, `errmsg`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a MongoDB protocol declaration or `OP_MSG` command/reply modifier field.
pub(crate) fn parse_mongodb_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mongodb)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Mongodb, (s.start, s.len()))),
            tag(Token::Ping)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "ping", (s.start, s.len()))),
            tag(Token::Query)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "find", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
            tag(Token::Ok).map(|(_, s)| ParsedField::L7Flag("OK", (s.start, s.len()))),
            tag(Token::Err).map(|(_, s)| ParsedField::L7Flag("ERR", (s.start, s.len()))),
            (tag(Token::Cmd), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Collection), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("COLLECTION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Db), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("DB", v, (s.start, s.end - s.start))),
            (tag(Token::Filter), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("FILTER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ReqId), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("REQ_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ResponseTo), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RESPONSE_TO", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("FLAGS", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ErrMsg), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("ERRMSG", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
