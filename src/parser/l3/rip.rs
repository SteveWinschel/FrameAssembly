//! Routing Information Protocol v2 (`rip`, RFC 2453) distance-vector routing parser.
//!
//! This module implements the winnow parser combinator for `rip` distance-vector routing updates
//! over UDP port 520. It parses command types (`request`, `reply`, `response`), route table entry
//! destination addresses (`prefix <ipv4>`), hop-count metrics (`metric <1..16>`), next-hop router
//! addresses (`nexthop <ipv4>`), and external route tags (`tag <u16>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u16, parse_u32, tag};

/// Parses a RIP protocol declaration or table update field.
pub(crate) fn parse_rip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Rip).map(|(_, s)| ParsedField::Protocol(Protocol::Rip, (s.start, s.len()))),
        tag(Token::Request)
            .map(|(_, s)| ParsedField::ArpOpcode(ArpOpcode::Request, (s.start, s.len()))),
        alt((tag(Token::Reply), tag(Token::Response)))
            .map(|(_, s)| ParsedField::ArpOpcode(ArpOpcode::Reply, (s.start, s.len()))),
        (tag(Token::Metric), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Metric(v, (s.start, s.end - s.start))),
        (tag(Token::Prefix), parse_ip)
            .map(|((_, s), v)| ParsedField::PrefixVal(Some(v), None, (s.start, s.end - s.start))),
        (tag(Token::NextHop), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::NextHop(v, (s.start, s.end - s.start))),
        (tag(Token::Tag), parse_u16)
            .map(|((_, s), v)| ParsedField::TagVal(Some(v), None, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
