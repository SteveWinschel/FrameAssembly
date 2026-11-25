//! NT LAN Manager Authentication over HTTP (`ntlm`) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for MS-NLMP / RFC 4559 HTTP-wrapped
//! NTLM authentication (`ntlm`) messages in FrameAssembly `.frasm` specifications. It recognizes
//! the `ntlm` protocol keyword, NTLMSSP stage flags (`negotiate`, `challenge`, `authenticate`),
//! explicit `msgtype`, NetBIOS `domain`, authenticated `user`, client/server `workstation`, 8-byte
//! Type 2 server challenge `nonce`, NTLMSSP `flags`, and HTTP carrier fields (`method`, `uri`,
//! `hosthdr`, `status`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_str_val, parse_u16, parse_u32, tag};

/// Parses an NTLM-over-HTTP protocol declaration or authentication modifier field.
pub(crate) fn parse_ntlm_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ntlm)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Ntlm, (s.start, s.len()))),
            tag(Token::Negotiate).map(|(_, s)| {
                ParsedField::L7StringField("NTLM_MSG_TYPE", "NEGOTIATE", (s.start, s.len()))
            }),
            tag(Token::Challenge).map(|(_, s)| {
                ParsedField::L7StringField("NTLM_MSG_TYPE", "CHALLENGE", (s.start, s.len()))
            }),
            tag(Token::Authenticate).map(|(_, s)| {
                ParsedField::L7StringField("NTLM_MSG_TYPE", "AUTHENTICATE", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Domain), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_DOMAIN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::User), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_USER", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Workstation), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_WORKSTATION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Nonce), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_NONCE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NTLM_FLAGS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Uri), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_URI", v, (s.start, s.end - s.start))
            }),
            (tag(Token::HostHdr), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("NTLM_HOST_HDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("NTLM_STATUS", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
