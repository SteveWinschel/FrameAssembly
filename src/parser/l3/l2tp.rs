//! Layer 2 Tunneling Protocol (`l2tp`, RFC 2661 / RFC 3931) parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for L2TPv2 (UDP port `1701`) and L2TPv3
//! (IP protocol `115` or UDP port `1701`) control and data tunnel frames. It recognizes the `l2tp`
//! protocol keyword, version selectors (`v2`, `v3`, `version <u8>`), plane/message keywords
//! (`data`, `hello`, `sccrq`, `sccrp`, `scccn`, `stopccn`, `msgtype <str|u16>`), tunnel and
//! session identifiers (`tunnelid <u32>`, `sessionid <u32>`), control sequence numbers (`ns <u16>`,
//! `nr <u16>`), and header flags (`flags <u16>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u8, parse_u16, parse_u32, tag};

/// Parses an L2TP protocol declaration, message type, or tunnel header field.
pub(crate) fn parse_l2tp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::L2tp).map(|(_, s)| ParsedField::Protocol(Protocol::L2tp, (s.start, s.len()))),
            tag(Token::V2).map(|(_, s)| ParsedField::VersionByte(2, (s.start, s.len()))),
            tag(Token::V3).map(|(_, s)| ParsedField::VersionByte(3, (s.start, s.len()))),
            (tag(Token::Version), parse_u8)
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            tag(Token::Data).map(|(_, s)| ParsedField::L7Flag("L2TP_DATA", (s.start, s.len()))),
            tag(Token::Hello)
                .map(|(_, s)| ParsedField::L7StringField("L2TP_MSG_TYPE", "HELLO", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Sccrq)
                .map(|(_, s)| ParsedField::L7StringField("L2TP_MSG_TYPE", "SCCRQ", (s.start, s.len()))),
            tag(Token::Sccrp)
                .map(|(_, s)| ParsedField::L7StringField("L2TP_MSG_TYPE", "SCCRP", (s.start, s.len()))),
            tag(Token::Scccn)
                .map(|(_, s)| ParsedField::L7StringField("L2TP_MSG_TYPE", "SCCCN", (s.start, s.len()))),
            tag(Token::Stopccn).map(|(_, s)| {
                ParsedField::L7StringField("L2TP_MSG_TYPE", "STOPCCN", (s.start, s.len()))
            }),
            (tag(Token::MsgType), parse_any_str).map(|((_, s), v)| {
                ParsedField::L7StringField("L2TP_MSG_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::TunnelId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("L2TP_TUNNEL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SessionId), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("L2TP_SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Ns), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("L2TP_NS", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Nr), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("L2TP_NR", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("L2TP_FLAGS", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
