//! Domain Name System (DNS) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1035 / RFC 3596 / RFC 6891 Domain
//! Name System (`dns`) messages in FrameAssembly `.frasm` specifications. It recognizes the `dns`
//! protocol keyword, `query` and `response` direction flags, transaction identifiers (`txid`),
//! query domain names (`qname`), record types (`qtype` including `SOA`/`SRV`), single or repeated
//! answer resource data (`rdata`), response codes (`rcode`), answer TTLs (`ansttl`), and EDNS0
//! OPT attributes (`edns0`, `udpsize`, `dobit`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u16, parse_u32, tag, ParsedField, Stream};

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
            (tag(Token::Rdata), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("RDATA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Rcode), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("RCODE", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::AnsTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ANS_TTL", v, (s.start, s.end - s.start))
            }),
            tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("QUERY", (s.start, s.len()))),
            tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
            tag(Token::Edns0).map(|(_, s)| ParsedField::L7Flag("EDNS0", (s.start, s.len()))),
            (tag(Token::UdpSize), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("UDP_SIZE", u32::from(v), (s.start, s.end - s.start))
            }),
            tag(Token::DoBit).map(|(_, s)| ParsedField::L7Flag("DO_BIT", (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
