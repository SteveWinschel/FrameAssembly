//! Lightweight Directory Access Protocol (LDAPv3) Layer 7 directory service field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4511 `LDAP` directory operations
//! in FrameAssembly `.fasm` specifications. It recognizes the `LDAP` protocol keyword, BER message
//! identifiers (`MSGID`), protocol operation flags (`BIND_REQ`, `BIND_RES`, `SEARCH_REQ`,
//! `SEARCH_ENTRY`, `SEARCH_DONE`, `UNBIND_REQ`), distinguished names (`BASE_DN`), search filters
//! (`FILTER`), and LDAP result codes (`RESULT_CODE`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an LDAP protocol declaration or directory operation field.
pub(crate) fn parse_ldap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ldap)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Ldap, (s.start, s.len()))),
            (tag(Token::MsgId), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("MSGID", v, (s.start, s.end - s.start))),
            tag(Token::BindReq).map(|(_, s)| ParsedField::L7Flag("BIND_REQ", (s.start, s.len()))),
            tag(Token::BindRes).map(|(_, s)| ParsedField::L7Flag("BIND_RES", (s.start, s.len()))),
            tag(Token::SearchReq)
                .map(|(_, s)| ParsedField::L7Flag("SEARCH_REQ", (s.start, s.len()))),
            tag(Token::SearchEntry)
                .map(|(_, s)| ParsedField::L7Flag("SEARCH_ENTRY", (s.start, s.len()))),
        )),
        alt((
            tag(Token::SearchDone)
                .map(|(_, s)| ParsedField::L7Flag("SEARCH_DONE", (s.start, s.len()))),
            tag(Token::UnbindReq)
                .map(|(_, s)| ParsedField::L7Flag("UNBIND_REQ", (s.start, s.len()))),
            (tag(Token::BaseDn), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("BASE_DN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Filter), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("FILTER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ResultCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RESULT_CODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
