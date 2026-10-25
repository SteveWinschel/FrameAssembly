//! Address Resolution Protocol (`ARP`, RFC 826) field parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `ARP` frame statements and modifiers.
//! It supports `REQUEST`, `REPLY`, and `GRATUITOUS` (`GARP`) operation codes alongside sender
//! hardware address (`SHA`/`SENDERMAC`), sender protocol address (`SPA`/`SENDERIP`), target
//! hardware address (`THA`/`TARGETMAC`), and target protocol address (`TPA`/`TARGETIP`) overrides.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_mac, parse_raw_string_lit, tag};

/// Parses an ARP protocol declaration or field.
pub(crate) fn parse_arp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Arp).map(|(_, s)| ParsedField::Protocol(Protocol::Arp, (s.start, s.len()))),
        tag(Token::Request)
            .map(|(_, s)| ParsedField::ArpOpcode(ArpOpcode::Request, (s.start, s.len()))),
        alt((
            (tag(Token::Reply), parse_raw_string_lit).map(|((_, s), v)| {
                ParsedField::L7StringField("REPLY", v, (s.start, s.end - s.start))
            }),
            tag(Token::Reply)
                .map(|(_, s)| ParsedField::ArpOpcode(ArpOpcode::Reply, (s.start, s.len()))),
        )),
        alt((tag(Token::Gratuitous), tag(Token::Garp)))
            .map(|(_, s)| ParsedField::Gratuitous((s.start, s.len()))),
        (alt((tag(Token::Sha), tag(Token::SenderMac))), cut_err(parse_mac))
            .map(|((_, s), v)| ParsedField::Sha(v, (s.start, s.end - s.start))),
        (alt((tag(Token::Spa), tag(Token::SenderIp))), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::Spa(v, (s.start, s.end - s.start))),
        (alt((tag(Token::Tha), tag(Token::TargetMac))), cut_err(parse_mac))
            .map(|((_, s), v)| ParsedField::Tha(v, (s.start, s.end - s.start))),
        (alt((tag(Token::Tpa), tag(Token::TargetIp))), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::Tpa(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
