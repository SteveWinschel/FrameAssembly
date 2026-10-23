//! DHCP Layer 7 protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_mac, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a DHCP protocol declaration or configuration option field.
pub(crate) fn parse_dhcp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Dhcp).map(|(_, s)| ParsedField::Protocol(Protocol::Dhcp, (s.start, s.len()))),
            tag(Token::Discover).map(|(_, s)| ParsedField::L7Flag("DISCOVER", (s.start, s.len()))),
            tag(Token::Solicit).map(|(_, s)| ParsedField::L7Flag("SOLICIT", (s.start, s.len()))),
            tag(Token::Offer).map(|(_, s)| ParsedField::L7Flag("OFFER", (s.start, s.len()))),
            tag(Token::Advertise).map(|(_, s)| ParsedField::L7Flag("ADVERTISE", (s.start, s.len()))),
            tag(Token::Request).map(|(_, s)| ParsedField::L7Flag("REQUEST", (s.start, s.len()))),
            tag(Token::Ack).map(|(_, s)| ParsedField::L7Flag("ACK", (s.start, s.len()))),
            tag(Token::Reply).map(|(_, s)| ParsedField::L7Flag("REPLY", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Release).map(|(_, s)| ParsedField::L7Flag("RELEASE", (s.start, s.len()))),
            (tag(Token::Ciaddr), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("CIADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Yiaddr), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("YIADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Siaddr), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("SIADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Chaddr), cut_err(parse_mac)).map(|((_, s), v)| ParsedField::L7MacField("CHADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Hostname), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("HOSTNAME", v, (s.start, s.end - s.start))),
            (tag(Token::DnsServer), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("DNS_SERVER", v, (s.start, s.end - s.start))),
            (tag(Token::Router), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("ROUTER", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::SubnetMask), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("SUBNET_MASK", v, (s.start, s.end - s.start))),
            (tag(Token::LeaseTime), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("LEASE_TIME", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
