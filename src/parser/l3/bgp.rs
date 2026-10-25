//! Border Gateway Protocol v4 (`BGP`, RFC 4271) exterior routing protocol parser.
//!
//! This module implements the winnow parser combinator for `BGP` inter-domain routing messages
//! over TCP port 179. It parses BGP message types (`OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`),
//! Autonomous System Numbers (`ASN`), hold timers (`HOLDTIME`), router identifiers (`BGPID`),
//! Network Layer Reachability Information prefixes (`PREFIX` or `NLRI`), and `NEXTHOP` addresses.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_ip, parse_u16, parse_u32, tag};

/// Parses a BGP protocol declaration or message field.
pub(crate) fn parse_bgp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Bgp).map(|(_, s)| ParsedField::Protocol(Protocol::Bgp, (s.start, s.len()))),
            tag(Token::Open).map(|(_, s)| ParsedField::BgpType(BgpType::Open, (s.start, s.len()))),
            tag(Token::Update)
                .map(|(_, s)| ParsedField::BgpType(BgpType::Update, (s.start, s.len()))),
            tag(Token::Notification)
                .map(|(_, s)| ParsedField::BgpType(BgpType::Notification, (s.start, s.len()))),
            tag(Token::Keepalive)
                .map(|(_, s)| ParsedField::BgpType(BgpType::Keepalive, (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Asn), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Asn(v, (s.start, s.end - s.start))),
            (tag(Token::HoldTime), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::HoldTime(v, (s.start, s.end - s.start))),
            (tag(Token::BgpId), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::BgpId(v, (s.start, s.end - s.start))),
            (alt((tag(Token::Prefix), tag(Token::Nlri))), parse_any_str)
                .map(|((_, s), v)| ParsedField::PrefixVal(None, Some(v), (s.start, s.end - s.start))),
            (tag(Token::NextHop), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::NextHop(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
