//! WireGuard Layer 3 VPN protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses a WireGuard protocol declaration or handshake field.
pub(crate) fn parse_wireguard_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Wireguard).map(|(_, s)| ParsedField::Protocol(Protocol::Wireguard, (s.start, s.len()))),
            (
                tag(Token::Type),
                alt((
                    tag(Token::Initiation).map(|(_, s)| (WireguardType::Initiation, s)),
                    tag(Token::Response).map(|(_, s)| (WireguardType::Response, s)),
                    tag(Token::Cookie).map(|(_, s)| (WireguardType::Cookie, s)),
                    tag(Token::Data).map(|(_, s)| (WireguardType::Data, s)),
                )),
            )
                .map(|((_, s1), (v, s2))| ParsedField::WireguardType(v, (s1.start, s2.end - s1.start))),
            tag(Token::Initiation).map(|(_, s)| ParsedField::WireguardType(WireguardType::Initiation, (s.start, s.len()))),
            tag(Token::Cookie).map(|(_, s)| ParsedField::WireguardType(WireguardType::Cookie, (s.start, s.len()))),
        )),
        alt((
            tag(Token::Data).map(|(_, s)| ParsedField::WireguardType(WireguardType::Data, (s.start, s.len()))),
            (tag(Token::Sender), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Sender(v, (s.start, s.end - s.start))),
            (tag(Token::Receiver), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Receiver(v, (s.start, s.end - s.start))),
            (tag(Token::Counter), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::Counter(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
