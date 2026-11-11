//! Open Shortest Path First (`ospf`, RFC 2328) link-state routing protocol parser.
//!
//! This module implements the winnow parser combinator for `ospf` link-state routing packets
//! (IP protocol 89). It parses OSPF packet types (`hello`, `dbd`, `lsr`, `lsu`, `lsack`), router
//! identifiers (`routerid <ipv4>`), 32-bit or dotted-quad area identifiers (`areaid`), timer
//! intervals (`hellointerval`, `deadinterval`), and designated router priority (`priority`).

use core::net::IpAddr;
use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u16, parse_u32, tag};

/// Parses an OSPF protocol declaration or packet field.
pub(crate) fn parse_ospf_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ospf).map(|(_, s)| ParsedField::Protocol(Protocol::Ospf, (s.start, s.len()))),
            tag(Token::Hello).map(|(_, s)| ParsedField::OspfType(OspfType::Hello, (s.start, s.len()))),
            tag(Token::Dbd).map(|(_, s)| ParsedField::OspfType(OspfType::Dbd, (s.start, s.len()))),
            tag(Token::Lsr).map(|(_, s)| ParsedField::OspfType(OspfType::Lsr, (s.start, s.len()))),
            tag(Token::Lsu).map(|(_, s)| ParsedField::OspfType(OspfType::Lsu, (s.start, s.len()))),
            tag(Token::LsAck).map(|(_, s)| ParsedField::OspfType(OspfType::LsAck, (s.start, s.len()))),
        )),
        alt((
            (tag(Token::RouterId), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::RouterId(v, (s.start, s.end - s.start))),
            (
                tag(Token::AreaId),
                cut_err(alt((
                    parse_u32,
                    parse_ip.verify_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(u32::from_be_bytes(v4.octets())),
                        IpAddr::V6(_) => None,
                    }),
                ))),
            )
                .map(|((_, s), v)| ParsedField::AreaId(v, (s.start, s.end - s.start))),
            (tag(Token::HelloInterval), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::HelloInterval(v, (s.start, s.end - s.start))),
            (tag(Token::DeadInterval), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::DeadInterval(v, (s.start, s.end - s.start))),
            (tag(Token::Priority), parse_u16)
                .map(|((_, s), v)| ParsedField::PriorityVal(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
