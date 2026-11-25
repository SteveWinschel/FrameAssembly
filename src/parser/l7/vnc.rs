//! Virtual Network Computing Remote Framebuffer Protocol (VNC / RFB 003.008) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 6143 Remote Framebuffer (`vnc`)
//! handshakes and display/input messages in FrameAssembly `.frasm` specifications. It recognizes
//! the `vnc` protocol keyword, RFB message types (`msgtype`), protocol versions (`version`),
//! security types (`securitytype`), framebuffer dimensions (`width`, `height`), desktop names
//! (`desktop`), keysyms (`key`), message flag bytes (`flags`), and pointer/update coordinates
//! (`xpos`, `ypos`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a VNC (RFB) protocol declaration or handshake/input field.
pub(crate) fn parse_vnc_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Vnc).map(|(_, s)| ParsedField::Protocol(Protocol::Vnc, (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Version), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SecurityType), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SECURITY_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Width), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("WIDTH", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Height), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("HEIGHT", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Desktop), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("DESKTOP", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Key), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("VNC_KEY", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("VNC_FLAGS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Xpos), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("XPOS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Ypos), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("YPOS", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
