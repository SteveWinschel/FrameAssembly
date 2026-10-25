//! OPC Unified Architecture (OPC UA Binary Protocol) Layer 7 industrial field parser.
//!
//! This module implements the `winnow` parser combinator for IEC 62541 `OPCUA` binary TCP
//! connection and secure channel messages in FrameAssembly `.fasm` specifications. It recognizes
//! the `OPCUA` protocol keyword, 3-character message types (`MSG_TYPE`, e.g., `"HEL"`, `"ACK"`,
//! `"OPN"`, `"MSG"`, `"CLO"`), chunk flags (`CHUNK_TYPE`), secure channel IDs
//! (`SECURE_CHANNEL_ID`), security token IDs (`TOKEN_ID`), sequence numbers (`SEQ_NUM`), request
//! IDs (`REQID`), endpoint URLs (`ENDPOINT_URL`), and target node identifiers (`NODE_ID`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an OPC UA protocol declaration or secure channel field.
pub(crate) fn parse_opcua_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Opcua)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Opcua, (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ChunkType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("CHUNK_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SecureChannelId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SECURE_CHANNEL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TokenId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TOKEN_ID", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ReqId), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("REQ_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::EndpointUrl), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("ENDPOINT_URL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::NodeId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("NODE_ID", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
