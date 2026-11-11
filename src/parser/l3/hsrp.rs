//! Cisco Hot Standby Router Protocol (`hsrp`, RFC 2281) redundancy parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `hsrp` gateway redundancy packets over
//! UDP port 1985. It parses standby group numbers (`group <u8>`), router election priorities
//! (`priority <u16>`), state codes (`state <u8>`), cleartext authentication strings (`auth <str>`),
//! virtual IP addresses (`vip <ip>`), and hello/hold timers (`hellotime`, `holdtime`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_str_val, parse_u8, parse_u16, tag};

/// Parses an HSRP protocol declaration or status field.
pub(crate) fn parse_hsrp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Hsrp).map(|(_, s)| ParsedField::Protocol(Protocol::Hsrp, (s.start, s.len()))),
        (tag(Token::Group), parse_u8)
            .map(|((_, s), v)| ParsedField::GroupVal(None, Some(v), (s.start, s.end - s.start))),
        (tag(Token::Priority), parse_u16)
            .map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        (tag(Token::State), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::HsrpState(v, (s.start, s.end - s.start))),
        (tag(Token::Auth), parse_str_val).map(|((_, s), v)| {
            ParsedField::L7StringField("HSRP_AUTH", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Vip), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::Vip(v, (s.start, s.end - s.start))),
        (tag(Token::HelloTime), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::HelloTime(v, (s.start, s.end - s.start))),
        (tag(Token::HoldTime), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::HoldTime(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
