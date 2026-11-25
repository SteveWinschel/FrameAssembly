//! Network Configuration Protocol (`netconf`, RFC 6241 / RFC 6242) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 6241 / RFC 6242 `netconf`
//! XML management messages over TCP port `830` in FrameAssembly `.frasm` specifications. It
//! recognizes the `netconf` protocol keyword, message envelope selectors (`hello`, `rpc`,
//! `rpcreply`, `reply`, `notification`, or `msgtype`), RPC `msgid`, capability `sessionid`,
//! `operation` tags, `capability` URNs, RFC 6242 `chunked` framing, and custom XML `body` content.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_str_val, parse_u64, tag,
};

/// Parses a NETCONF protocol declaration or RFC 6241/6242 XML framing field.
pub(crate) fn parse_netconf_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Netconf)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Netconf, (s.start, s.len()))),
            tag(Token::Hello).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "HELLO", (s.start, s.len()))
            }),
            tag(Token::Rpc)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "RPC", (s.start, s.len()))),
            tag(Token::Rpcreply).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "RPCREPLY", (s.start, s.len()))
            }),
            tag(Token::Reply).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "RPCREPLY", (s.start, s.len()))
            }),
            tag(Token::Notification).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "NOTIFICATION", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::MsgId), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSGID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SessionId), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Operation), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("OPERATION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Capability), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("CAPABILITY", v, (s.start, s.end - s.start))
            }),
            tag(Token::Chunked)
                .map(|(_, s)| ParsedField::L7Flag("CHUNKED", (s.start, s.len()))),
            (tag(Token::Body), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("BODY", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
