//! BGP Monitoring Protocol (`bmp`, RFC 7854) telemetry and route-monitoring parser.
//!
//! This module implements the `winnow` parser combinator for RFC 7854 BGP Monitoring Protocol
//! (`bmp`) messages carried over TCP port `1790`. It recognizes the `bmp` protocol keyword,
//! message types (`routemon`, `statsreport`, `peerdown`, `peerup`, `initiation`, `termination`),
//! protocol version (`version <u8>`), Per-Peer Header fields (`peertype <u8>`, `flags <u8>`,
//! `peerip <ip>`, `asn <u32>`, `bgpid <ipv4>`), Initiation TLVs (`sysname <str>`, `sysdesc <str>`),
//! and Termination/PeerDown `reason <u16>` codes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_ip, parse_str_val, parse_u8, parse_u16, parse_u32, tag,
};

/// Parses a BMP protocol declaration, message type selector, or Per-Peer / TLV field.
pub(crate) fn parse_bmp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Bmp).map(|(_, s)| ParsedField::Protocol(Protocol::Bmp, (s.start, s.len()))),
            tag(Token::Routemon)
                .map(|(_, s)| ParsedField::L7StringField("BMP_TYPE", "ROUTEMON", (s.start, s.len()))),
            tag(Token::StatsReport).map(|(_, s)| {
                ParsedField::L7StringField("BMP_TYPE", "STATSREPORT", (s.start, s.len()))
            }),
            tag(Token::PeerDown)
                .map(|(_, s)| ParsedField::L7StringField("BMP_TYPE", "PEERDOWN", (s.start, s.len()))),
            tag(Token::PeerUp)
                .map(|(_, s)| ParsedField::L7StringField("BMP_TYPE", "PEERUP", (s.start, s.len()))),
            tag(Token::Initiation).map(|(_, s)| {
                ParsedField::L7StringField("BMP_TYPE", "INITIATION", (s.start, s.len()))
            }),
            tag(Token::Termination).map(|(_, s)| {
                ParsedField::L7StringField("BMP_TYPE", "TERMINATION", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Version), parse_u8)
                .map(|((_, s), v)| ParsedField::VersionByte(v, (s.start, s.end - s.start))),
            (tag(Token::PeerType), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("BMP_PEER_TYPE", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u8)
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::PeerIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("BMP_PEER_IP", v, (s.start, s.end - s.start))),
            (tag(Token::Asn), parse_u32)
                .map(|((_, s), v)| ParsedField::Asn(v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::BgpId), parse_ip)
                .map(|((_, s), v)| ParsedField::BgpId(v, (s.start, s.end - s.start))),
            (tag(Token::SysName), parse_str_val)
                .map(|((_, s), v)| ParsedField::SysName(v, (s.start, s.end - s.start))),
            (tag(Token::SysDesc), parse_str_val)
                .map(|((_, s), v)| ParsedField::SysDesc(v, (s.start, s.end - s.start))),
            (tag(Token::Reason), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("BMP_REASON", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
