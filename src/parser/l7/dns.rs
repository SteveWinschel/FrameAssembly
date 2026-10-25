//! Domain Name System (DNS) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1035 / RFC 3596 Domain Name
//! System (`DNS`) messages in FrameAssembly `.fasm` specifications. It recognizes the `DNS`
//! protocol keyword, `QUERY` and `RESPONSE` direction flags, transaction identifiers (`TXID`),
//! query domain names (`QNAME`), record types (`QTYPE`), answer resource data (`RDATA` as strings
//! or IP literals), response codes (`RCODE`), and answer TTLs (`ANS_TTL`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Parses a DNS protocol declaration or query/record field.
pub(crate) fn parse_dns_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Dns).map(|(_, s)| ParsedField::Protocol(Protocol::Dns, (s.start, s.len()))),
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
