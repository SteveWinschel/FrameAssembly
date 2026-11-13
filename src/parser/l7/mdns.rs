//! Multicast DNS (mDNS) Layer 7 service discovery protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 6762 Multicast DNS (`mdns`)
//! messages in FrameAssembly `.frasm` specifications. It recognizes the `mdns` protocol keyword,
//! `query` and `response` flags, transaction identifiers (`txid`), multicast service query names
//! (`qname`), record types (`qtype`), resource data (`rdata`), response status codes (`rcode`),
//! and answer time-to-live intervals (`ansttl`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Parses an mDNS protocol declaration or service discovery field.
pub(crate) fn parse_mdns_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mdns)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Mdns, (s.start, s.len()))),
            (tag(Token::Txid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
            (tag(Token::Qname), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("QNAME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Qtype), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("QTYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Rdata), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("RDATA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rcode), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("RCODE", v, (s.start, s.end - s.start))),
            (tag(Token::AnsTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ANS_TTL", v, (s.start, s.end - s.start))
            }),
            tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("QUERY", (s.start, s.len()))),
            tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
