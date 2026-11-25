//! DNS over HTTPS (DoH, RFC 8484) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 8484 DNS over HTTPS (`doh`)
//! HTTP/1.1 + DNS wire messages in FrameAssembly `.frasm` specifications. It recognizes the `doh`
//! protocol keyword, HTTP attributes (`get`, `post`, `method`, `uri`, `hosthdr`, `useragent`,
//! `status`, `reason`), DNS direction flags (`query`, `response`), DNS query/answer fields
//! (`txid`, `qname`, `qtype`, `rdata`, `rcode`, `ansttl`), and EDNS0 options (`edns0`, `udpsize`,
//! `dobit`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a DoH protocol declaration or HTTP/DNS modifier field.
pub(crate) fn parse_doh_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Doh).map(|(_, s)| ParsedField::Protocol(Protocol::Doh, (s.start, s.len()))),
            tag(Token::Get)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "GET", (s.start, s.len()))),
            tag(Token::Post)
                .map(|(_, s)| ParsedField::L7StringField("METHOD", "POST", (s.start, s.len()))),
            (tag(Token::Method), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("METHOD", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Uri), cut_err(parse_str_val))
                .map(|((_, s), v)| ParsedField::L7StringField("URI", v, (s.start, s.end - s.start))),
            (tag(Token::HostHdr), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("HOST_HDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::UserAgent), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("USER_AGENT", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Reason), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("REASON", v, (s.start, s.end - s.start))
            }),
            tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("QUERY", (s.start, s.len()))),
            tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
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
            (tag(Token::Rcode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::AnsTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ANS_TTL", v, (s.start, s.end - s.start))
            }),
            tag(Token::Edns0).map(|(_, s)| ParsedField::L7Flag("EDNS0", (s.start, s.len()))),
            (tag(Token::UdpSize), cut_err(parse_u16)).map(|((_, s), v)| {
                ParsedField::L7U32Field("UDP_SIZE", u32::from(v), (s.start, s.end - s.start))
            }),
            tag(Token::DoBit).map(|(_, s)| ParsedField::L7Flag("DO_BIT", (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
