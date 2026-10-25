//! IPv6 Multicast Listener Discovery (`MLD`, RFC 2710 / RFC 3810) parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `MLD` IPv6 multicast group management
//! messages encapsulated inside ICMPv6 headers. It parses MLD message types (`QUERY`, `REPORT`,
//! `DONE`), multicast group IPv6 addresses (`MULTICAST_ADDR <ipv6>`), and maximum response delay
//! timers (`MAX_RESP_DELAY <u16>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u16, tag};

/// Parses an MLD protocol declaration or message field.
pub(crate) fn parse_mld_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Mld).map(|(_, s)| ParsedField::Protocol(Protocol::Mld, (s.start, s.len()))),
        tag(Token::Query).map(|(_, s)| ParsedField::MldType(MldType::Query, (s.start, s.len()))),
        tag(Token::Report).map(|(_, s)| ParsedField::MldType(MldType::Report, (s.start, s.len()))),
        tag(Token::Done).map(|(_, s)| ParsedField::MldType(MldType::Done, (s.start, s.len()))),
        (tag(Token::MulticastAddr), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::MulticastAddr(v, (s.start, s.end - s.start))),
        (tag(Token::MaxRespDelay), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::MaxRespDelay(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
