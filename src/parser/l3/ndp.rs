//! IPv6 Neighbor Discovery Protocol (`NDP`, RFC 4861) field parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `NDP` ICMPv6 neighbor and router
//! discovery frames. It parses message types (`ROUTER_SOLICIT`, `ROUTER_ADVERT`,
//! `NEIGHBOR_SOLICIT`, `NEIGHBOR_ADVERT`), target IPv6 addresses (`TARGET`), Source and Target
//! Link-Layer Address options (`SLLA`, `TLLA`), and router lifetime intervals (`ROUTER_LIFETIME`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_mac, parse_u16, tag};

/// Parses an NDP protocol declaration or option field.
pub(crate) fn parse_ndp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ndp).map(|(_, s)| ParsedField::Protocol(Protocol::Ndp, (s.start, s.len()))),
            tag(Token::RouterSolicit)
                .map(|(_, s)| ParsedField::NdpType(NdpType::RouterSolicit, (s.start, s.len()))),
            tag(Token::RouterAdvert)
                .map(|(_, s)| ParsedField::NdpType(NdpType::RouterAdvert, (s.start, s.len()))),
            tag(Token::NeighborSolicit)
                .map(|(_, s)| ParsedField::NdpType(NdpType::NeighborSolicit, (s.start, s.len()))),
            tag(Token::NeighborAdvert)
                .map(|(_, s)| ParsedField::NdpType(NdpType::NeighborAdvert, (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Target), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::TargetVal(Some(v), None, (s.start, s.end - s.start))),
            (tag(Token::Slla), cut_err(parse_mac))
                .map(|((_, s), v)| ParsedField::Slla(v, (s.start, s.end - s.start))),
            (tag(Token::Tlla), cut_err(parse_mac))
                .map(|((_, s), v)| ParsedField::Tlla(v, (s.start, s.end - s.start))),
            (tag(Token::RouterLifetime), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::RouterLifetime(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
