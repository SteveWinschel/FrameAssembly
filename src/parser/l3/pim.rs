//! Protocol Independent Multicast - Sparse Mode (`PIM`, RFC 7761) routing parser.
//!
//! This module implements the winnow parser combinator for `PIM` multicast routing control messages
//! (IP protocol 103). It parses PIM message types (`HELLO`, `JOIN_PRUNE`, `REGISTER`), multicast
//! group addresses (`GROUP <ip>`), multicast source addresses (`SOURCE <ip>`), Rendezvous Point
//! addresses (`RP <ip>`), neighbor holdtimes (`HOLDTIME <u16>`), and DR priorities (`DR_PRIORITY <u32>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u16, parse_u32, tag};

/// Parses a PIM protocol declaration or routing field.
pub(crate) fn parse_pim_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Pim).map(|(_, s)| ParsedField::Protocol(Protocol::Pim, (s.start, s.len()))),
            tag(Token::Hello).map(|(_, s)| ParsedField::HelloWord((s.start, s.len()))),
            tag(Token::JoinPrune).map(|(_, s)| ParsedField::PimJoinPrune((s.start, s.len()))),
            tag(Token::Register).map(|(_, s)| ParsedField::PimRegister((s.start, s.len()))),
            (tag(Token::Group), parse_ip)
                .map(|((_, s), v)| ParsedField::GroupVal(Some(v), None, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Source), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::SourceIp(v, (s.start, s.end - s.start))),
            (tag(Token::Rp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::Rp(v, (s.start, s.end - s.start))),
            (tag(Token::HoldTime), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::HoldTime(v, (s.start, s.end - s.start))),
            (tag(Token::DrPriority), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::DrPriority(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
