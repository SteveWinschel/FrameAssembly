//! Link-Local Multicast Name Resolution (`llmnr`) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 4795 Link-Local Multicast Name
//! Resolution (`llmnr`) messages over UDP and TCP port 5355 in FrameAssembly `.frasm`
//! specifications. It recognizes the `llmnr` protocol keyword, direction flags (`query` and
//! `response`), 16-bit transaction identifiers (`txid`), host query names (`qname`), DNS record
//! types (`qtype`), single or repeated answer resource data (`rdata`), response codes (`rcode`),
//! answer TTLs (`ansttl`), and 16-bit RFC 4795 flags (`flags`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u16, parse_u32, tag};

/// Parses an LLMNR protocol declaration or query/response modifier field.
pub(crate) fn parse_llmnr_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Llmnr)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Llmnr, (s.start, s.len()))),
            tag(Token::Query)
                .map(|(_, s)| ParsedField::L7Flag("LLMNR_QUERY", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("LLMNR_RESPONSE", (s.start, s.len()))),
            (tag(Token::Txid), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LLMNR_TXID", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Qname), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("LLMNR_QNAME", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Qtype), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("LLMNR_QTYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rdata), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("LLMNR_RDATA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rcode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LLMNR_RCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::AnsTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LLMNR_ANS_TTL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("LLMNR_FLAGS", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
