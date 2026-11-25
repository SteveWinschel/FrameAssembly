//! Routing Information Protocol v2 (`rip`, RFC 2453) and RIPng (RFC 2080) routing parser.
//!
//! This module implements the winnow parser combinator for `rip` distance-vector routing updates
//! over UDP ports 520 and 521. It parses command types (`request`, `reply`, `response`, or
//! `command <str|u8>`), route table entry destination addresses (`prefix <ip>`), hop-count metrics
//! (`metric <1..16>`), next-hop router addresses (`nexthop <ip>`), and external route tags
//! (`tag <u16>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_ip, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a RIP protocol declaration or table update field.
pub(crate) fn parse_rip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Rip).map(|(_, s)| ParsedField::Protocol(Protocol::Rip, (s.start, s.len()))),
        tag(Token::Request)
            .map(|(_, s)| ParsedField::ArpOpcode(ArpOpcode::Request, (s.start, s.len()))),
        alt((tag(Token::Reply), tag(Token::Response)))
            .map(|(_, s)| ParsedField::ArpOpcode(ArpOpcode::Reply, (s.start, s.len()))),
        (
            tag(Token::Command),
            parse_any_str.verify_map(|s| {
                if s == "1"
                    || s.eq_ignore_ascii_case("0x1")
                    || s.eq_ignore_ascii_case("0x01")
                    || s.eq_ignore_ascii_case("request")
                    || s.eq_ignore_ascii_case("req")
                {
                    Some(ArpOpcode::Request)
                } else if s == "2"
                    || s.eq_ignore_ascii_case("0x2")
                    || s.eq_ignore_ascii_case("0x02")
                    || s.eq_ignore_ascii_case("response")
                    || s.eq_ignore_ascii_case("reply")
                    || s.eq_ignore_ascii_case("resp")
                {
                    Some(ArpOpcode::Reply)
                } else {
                    None
                }
            }),
        )
            .map(|((_, s), op)| ParsedField::ArpOpcode(op, (s.start, s.end - s.start))),
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
