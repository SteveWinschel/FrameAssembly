//! Internet Control Message Protocol (`ICMP`, RFC 792 / RFC 4443) parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for IPv4 `ICMP` and IPv6 `ICMPv6` diagnostic
//! and control messages. It parses symbolic message types (`ECHO_REQUEST`, `ECHO_REPLY`,
//! `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`), numeric type and code overrides (`TYPE`, `CODE`),
//! echo identifier and sequence numbers (`ID`, `SEQ`), and redirect gateway addresses (`GATEWAY`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u8, parse_u16, parse_u32, tag};

/// Parses an ICMP protocol declaration or message field.
pub(crate) fn parse_icmp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Icmp).map(|(_, s)| ParsedField::Protocol(Protocol::Icmp, (s.start, s.len()))),
            tag(Token::EchoRequest)
                .map(|(_, s)| ParsedField::IcmpTypeChoice(IcmpTypeChoice::EchoRequest, (s.start, s.len()))),
            tag(Token::EchoReply)
                .map(|(_, s)| ParsedField::IcmpTypeChoice(IcmpTypeChoice::EchoReply, (s.start, s.len()))),
            tag(Token::DestUnreach)
                .map(|(_, s)| ParsedField::IcmpTypeChoice(IcmpTypeChoice::DestUnreach, (s.start, s.len()))),
            tag(Token::TimeExceeded)
                .map(|(_, s)| ParsedField::IcmpTypeChoice(IcmpTypeChoice::TimeExceeded, (s.start, s.len()))),
            tag(Token::Redirect)
                .map(|(_, s)| ParsedField::IcmpTypeChoice(IcmpTypeChoice::Redirect, (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Gateway), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::Gateway(v, (s.start, s.end - s.start))),
            (tag(Token::Type), parse_u8).map(|((_, s), v)| {
                ParsedField::L7U32Field("ICMP_TYPE", v as u32, (s.start, s.end - s.start))
            }),
            (tag(Token::Code), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::Id), cut_err(parse_u16))
                .map(|((_, s), v)| ParsedField::IcmpId(v, (s.start, s.end - s.start))),
            (tag(Token::Seq), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::Seq(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
