//! Virtual Router Redundancy Protocol (`VRRP`, RFC 5798) first-hop redundancy parser.
//!
//! This module implements the winnow parser combinator for `VRRP` router redundancy advertisements
//! (IP protocol 112). It parses Virtual Router Identifiers (`VRID <u8>`), election priorities
//! (`PRIORITY <u16>`), advertisement intervals (`ADV_INT <u16>`), Virtual IP addresses (`VIP <ip>`),
//! and protocol versions (`VERSION <2|3>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u8, parse_u16, tag};

/// Parses a VRRP protocol declaration or advertisement field.
pub(crate) fn parse_vrrp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Vrrp).map(|(_, s)| ParsedField::Protocol(Protocol::Vrrp, (s.start, s.len()))),
        (tag(Token::Vrid), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::Vrid(v, (s.start, s.end - s.start))),
        (tag(Token::Priority), parse_u16)
            .map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        (tag(Token::AdvInt), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::AdvInt(v, (s.start, s.end - s.start))),
        (tag(Token::Vip), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::Vip(v, (s.start, s.end - s.start))),
        (tag(Token::Version), parse_u8)
            .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
