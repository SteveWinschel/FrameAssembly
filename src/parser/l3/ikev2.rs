//! Internet Key Exchange v2 (`IKEV2`, RFC 7296) key management parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `IKEV2` security association negotiation
//! packets over UDP port 500/4500. It supports both explicit (`EXCHANGE SA_INIT`,
//! `EXCHANGE CREATE_CHILD_SA`, `EXCHANGE INFORMATIONAL`) and shorthand exchange types (`SA_INIT`,
//! `CREATE_CHILD_SA`, `INFORMATIONAL`), alongside `INITIATOR_SPI`, `RESPONDER_SPI`, `MSGID`,
//! `FLAGS`, and `NEXT_PAYLOAD`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u32, parse_u64, tag};

/// Parses an IKEv2 protocol declaration or parameter field.
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
                opt(tag(Token::Exchange)),
                alt((
                    tag(Token::SaInit).map(|(_, s)| (IkeExchange::SaInit, s)),
                    tag(Token::CreateChildSa).map(|(_, s)| (IkeExchange::CreateChildSa, s)),
                    tag(Token::Informational).map(|(_, s)| (IkeExchange::Informational, s)),
                )),
            )
                .map(|(opt_ex, (ex, s2))| {
                    let start = opt_ex.map(|(_, s1)| s1.start).unwrap_or(s2.start);
                    ParsedField::IkeExchange(ex, (start, s2.end - start))
                }),
        )),
        alt((
            (tag(Token::MsgId), parse_u32)
                .map(|((_, s), v)| ParsedField::MsgId(v, (s.start, s.end - s.start))),
            (tag(Token::Flags), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::NextPayload), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::NextPayload(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
