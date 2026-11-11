//! IEEE 802.1X Extensible Authentication Protocol over LAN (`eapol`) parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `eapol` port-based network access
//! control frames. It supports both explicit (`type start`, `type logoff`, `type key`,
//! `type eappacket`) and bare shorthand packet types (`start`, `logoff`, `key`, `eappacket`),
//! alongside protocol version (`version`), EAP code (`eapcode`), identifier (`eapid`), method
//! (`eapmethod`), and user identity string (`identity`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_str_val, parse_u8, tag};

/// Parses an EAPOL protocol declaration or frame field.
pub(crate) fn parse_eapol_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Eapol).map(|(_, s)| ParsedField::Protocol(Protocol::Eapol, (s.start, s.len()))),
        (tag(Token::Version), parse_u8)
            .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
        (tag(Token::EapCode), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::EapCode(v, (s.start, s.end - s.start))),
        (tag(Token::EapId), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::EapId(v, (s.start, s.end - s.start))),
        (tag(Token::EapMethod), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::EapMethod(v, (s.start, s.end - s.start))),
        (tag(Token::Identity), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::Identity(v, (s.start, s.end - s.start))),
        (
            opt(tag(Token::Type)),
            alt((
                tag(Token::Start).map(|(_, s)| (EapolType::Start, s)),
                tag(Token::Logoff).map(|(_, s)| (EapolType::Logoff, s)),
                tag(Token::Key).map(|(_, s)| (EapolType::Key, s)),
                tag(Token::EapPacket).map(|(_, s)| (EapolType::EapPacket, s)),
            )),
        )
            .map(|(opt_t, (t, s2))| {
                let start = opt_t.map(|(_, s1)| s1.start).unwrap_or(s2.start);
                ParsedField::EapolType(t, (start, s2.end - start))
            }),
    ))
    .parse_next(input)
}
