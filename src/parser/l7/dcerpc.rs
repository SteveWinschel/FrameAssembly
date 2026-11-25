//! Distributed Computing Environment / Remote Procedure Call (`dcerpc`) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for connection-oriented DCE/RPC v5
//! (`dcerpc`, MS-RPCE over TCP port 135) statements in FrameAssembly `.frasm` specifications. It
//! recognizes the `dcerpc` protocol keyword, PDU shorthand flags (`bind`, `bindack`, `bindnak`,
//! `request`, `response`, `fault`, `altercontext`) and explicit `msgtype`, interface or object
//! UUIDs (`uuid`), interface versions (`vers`), operation numbers (`opnum`), call IDs (`callid`),
//! context IDs (`ctxid`), header flags (`flags`), and fault or rejection codes (`status`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_u16, parse_u32, parse_u8, tag,
};

/// Parses a DCE/RPC v5 protocol declaration or RPC header/presentation modifier field.
pub(crate) fn parse_dcerpc_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Dcerpc)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Dcerpc, (s.start, s.len()))),
            tag(Token::Bind).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "BIND", (s.start, s.len()))
            }),
            tag(Token::BindAck).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "BINDACK", (s.start, s.len()))
            }),
            tag(Token::BindNak).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "BINDNAK", (s.start, s.len()))
            }),
            tag(Token::Request).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "REQUEST", (s.start, s.len()))
            }),
            tag(Token::Response).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "RESPONSE", (s.start, s.len()))
            }),
            tag(Token::Fault).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "FAULT", (s.start, s.len()))
            }),
            tag(Token::AlterContext).map(|(_, s)| {
                ParsedField::L7StringField("DCERPC_PDU", "ALTERCONTEXT", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("DCERPC_PDU", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Uuid), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("DCERPC_UUID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Vers), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("DCERPC_VERS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Opnum), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DCERPC_OPNUM", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::CallId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DCERPC_CALL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::CtxId), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DCERPC_CTX_ID", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DCERPC_FLAGS", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DCERPC_STATUS", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
