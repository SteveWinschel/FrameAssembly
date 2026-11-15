//! Internet Key Exchange v2 (`ikev2`, RFC 7296) key management parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `ikev2` security association negotiation
//! packets over UDP port 500/4500. It supports both explicit (`exchange sainit`, `exchange auth`,
//! `exchange createchildsa`, `exchange informational`) and shorthand exchange types (`sainit`,
//! `auth`, `createchildsa`, `informational`), alongside `initiatorspi`, `responderspi`, `msgid`,
//! `flags`, and `nextpayload` (with `nextheader` accepted as an alias).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u32, parse_u64, tag};

/// Parses an IKEv2 protocol declaration or parameter field (safe for fallback dispatch).
pub(crate) fn parse_ikev2_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ikev2)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Ikev2, (s.start, s.len()))),
            (tag(Token::InitiatorSpi), cut_err(parse_u64))
                .map(|((_, s), v)| ParsedField::InitiatorSpi(v, (s.start, s.end - s.start))),
            (tag(Token::ResponderSpi), cut_err(parse_u64))
                .map(|((_, s), v)| ParsedField::ResponderSpi(v, (s.start, s.end - s.start))),
            (
                tag(Token::Exchange),
                cut_err(alt((
                    tag(Token::SaInit).map(|(_, s)| (IkeExchange::SaInit, s)),
                    tag(Token::Auth).map(|(_, s)| (IkeExchange::Auth, s)),
                    tag(Token::CreateChildSa).map(|(_, s)| (IkeExchange::CreateChildSa, s)),
                    tag(Token::Informational).map(|(_, s)| (IkeExchange::Informational, s)),
                ))),
            )
                .map(|((_, s1), (ex, s2))| {
                    ParsedField::IkeExchange(ex, (s1.start, s2.end - s1.start))
                }),
            alt((
                tag(Token::SaInit).map(|(_, s)| (IkeExchange::SaInit, s)),
                tag(Token::CreateChildSa).map(|(_, s)| (IkeExchange::CreateChildSa, s)),
                tag(Token::Informational).map(|(_, s)| (IkeExchange::Informational, s)),
            ))
            .map(|(ex, s2)| ParsedField::IkeExchange(ex, (s2.start, s2.end - s2.start))),
        )),
        alt((
            (tag(Token::MsgId), parse_u32)
                .map(|((_, s), v)| ParsedField::MsgId(v, (s.start, s.end - s.start))),
            (tag(Token::Flags), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::NextPayload), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::NextPayload(v, (s.start, s.end - s.start))),
            (tag(Token::NextHeader), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::NextPayload(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}

/// Parses an IKEv2 parameter field when `ikev2` is the active protocol, additionally accepting bare `auth`.
pub(crate) fn parse_ikev2_scoped_field<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<ParsedField<'a>> {
    alt((
        parse_ikev2_field,
        tag(Token::Auth)
            .map(|(_, s)| ParsedField::IkeExchange(IkeExchange::Auth, (s.start, s.len()))),
    ))
    .parse_next(input)
}
