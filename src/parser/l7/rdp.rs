//! Remote Desktop Protocol (`rdp`) Layer 7 terminal services field parser.
//!
//! This module implements the `winnow` parser combinator for Microsoft Remote Desktop Protocol
//! (`rdp`, MS-RDPBCGR over TPKT + X.224 TCP port 3389) statements in FrameAssembly `.frasm`
//! specifications. It recognizes the `rdp` protocol keyword, handshake stage shorthands (`x224cr`,
//! `x224cc`, `mcs`) and explicit `msgtype`, routing cookies (`cookie`), requested/selected security
//! protocol masks (`proto`), negotiation flags (`flags`), X.224 source references (`sessionid`),
//! and MCS desktop geometry (`width`, `height`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_str_val, parse_u16, parse_u32, parse_u8, tag};

/// Parses an RDP protocol declaration or TPKT/X.224/MCS handshake modifier field.
pub(crate) fn parse_rdp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rdp).map(|(_, s)| ParsedField::Protocol(Protocol::Rdp, (s.start, s.len()))),
            tag(Token::X224Cr).map(|(_, s)| {
                ParsedField::L7StringField("RDP_MSG_TYPE", "X224CR", (s.start, s.len()))
            }),
            tag(Token::X224Cc).map(|(_, s)| {
                ParsedField::L7StringField("RDP_MSG_TYPE", "X224CC", (s.start, s.len()))
            }),
            tag(Token::Mcs)
                .map(|(_, s)| ParsedField::L7StringField("RDP_MSG_TYPE", "MCS", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("RDP_MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cookie), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("RDP_COOKIE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Proto), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RDP_PROTO", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RDP_FLAGS", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::SessionId), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RDP_SESSION_ID", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Width), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RDP_WIDTH", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Height), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RDP_HEIGHT", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
