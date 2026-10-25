//! Internet Group Management Protocol (`IGMP`, RFC 1112 / RFC 2236 / RFC 3376) parser.
//!
//! This module implements the winnow parser combinator for IPv4 `IGMP` multicast group membership
//! statements. It supports membership operations (`QUERY`, `REPORT`, `LEAVE`), protocol version
//! shorthands (`V1`, `V2`, `V3`, or `VERSION <1..3>`), multicast group addresses (`GROUP <ipv4>`),
//! and maximum response time intervals (`MAX_RESP <u8>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u8, tag};

/// Parses an IGMP protocol declaration or message field.
pub(crate) fn parse_igmp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Igmp).map(|(_, s)| ParsedField::Protocol(Protocol::Igmp, (s.start, s.len()))),
            tag(Token::Query)
                .map(|(_, s)| ParsedField::IgmpType(IgmpType::Query, (s.start, s.len()))),
            tag(Token::Report)
                .map(|(_, s)| ParsedField::IgmpType(IgmpType::Report, (s.start, s.len()))),
            tag(Token::Leave)
                .map(|(_, s)| ParsedField::IgmpType(IgmpType::Leave, (s.start, s.len()))),
            tag(Token::V1).map(|(_, s)| ParsedField::VersionByte(1, (s.start, s.len()))),
        )),
        alt((
            tag(Token::V2).map(|(_, s)| ParsedField::VersionByte(2, (s.start, s.len()))),
            tag(Token::V3).map(|(_, s)| ParsedField::VersionByte(3, (s.start, s.len()))),
            (tag(Token::Version), parse_u8)
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (
                tag(Token::Group),
                alt((
                    parse_ip.map(|ip| (Some(ip), None)),
                    parse_u8.map(|u| (None, Some(u))),
                )),
            )
                .map(|((_, s), (ip, u))| ParsedField::GroupVal(ip, u, (s.start, s.end - s.start))),
            (tag(Token::MaxResp), cut_err(parse_u8))
                .map(|((_, s), v)| ParsedField::MaxResp(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
