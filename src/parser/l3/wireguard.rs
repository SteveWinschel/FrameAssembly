//! WireGuard (`WIREGUARD`) Layer 3 cryptographic VPN tunnel parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `WIREGUARD` Noise-protocol handshake
//! and encrypted transport packets over UDP port 51820. It supports both explicit (`TYPE INITIATION`,
//! `TYPE RESPONSE`, `TYPE COOKIE`, `TYPE DATA`) and bare shorthand message types (`INITIATION`,
//! `RESPONSE`, `COOKIE`, `DATA`), alongside `SENDER`, `RECEIVER`, and `COUNTER` modifiers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u32, parse_u64, tag};

/// Parses a WireGuard protocol declaration or handshake field.
pub(crate) fn parse_wireguard_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Wireguard)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Wireguard, (s.start, s.len()))),
        (
            opt(tag(Token::Type)),
            alt((
                tag(Token::Initiation).map(|(_, s)| (WireguardType::Initiation, s)),
                tag(Token::Response).map(|(_, s)| (WireguardType::Response, s)),
                tag(Token::Cookie).map(|(_, s)| (WireguardType::Cookie, s)),
                tag(Token::Data).map(|(_, s)| (WireguardType::Data, s)),
            )),
        )
            .map(|(opt_t, (v, s2))| {
                let start = opt_t.map(|(_, s1)| s1.start).unwrap_or(s2.start);
                ParsedField::WireguardType(v, (start, s2.end - start))
            }),
        (tag(Token::Sender), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Sender(v, (s.start, s.end - s.start))),
        (tag(Token::Receiver), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Receiver(v, (s.start, s.end - s.start))),
        (tag(Token::Counter), cut_err(parse_u64))
            .map(|((_, s), v)| ParsedField::Counter(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
