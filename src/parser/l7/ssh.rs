//! Secure Shell (SSH-2) Layer 7 transport and key exchange protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4253 `SSH` version banners and
//! binary packet protocol messages in FrameAssembly `.fasm` specifications. It recognizes the
//! `SSH` protocol keyword, version identification strings (`BANNER`), key exchange flags
//! (`KEXINIT`, `NEWKEYS`), explicit SSH message type numbers (`MSG_CODE`), and 16-byte key
//! exchange cookies (`COOKIE`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an SSH protocol declaration or handshake field.
pub(crate) fn parse_ssh_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ssh).map(|(_, s)| ParsedField::Protocol(Protocol::Ssh, (s.start, s.len()))),
        (tag(Token::Banner), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::L7StringField("BANNER", v, (s.start, s.end - s.start))),
        tag(Token::KexInit).map(|(_, s)| ParsedField::L7Flag("KEXINIT", (s.start, s.len()))),
        tag(Token::NewKeys).map(|(_, s)| ParsedField::L7Flag("NEWKEYS", (s.start, s.len()))),
        (tag(Token::MsgCode), cut_err(parse_u32)).map(|((_, s), v)| {
            ParsedField::L7U32Field("MSG_CODE", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Cookie), parse_str_val)
            .map(|((_, s), v)| ParsedField::L7StringField("COOKIE", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
