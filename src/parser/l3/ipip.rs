//! IP-in-IP Encapsulation (`ipip`, RFC 2003 / RFC 2473 / RFC 4213) tunnel parser.
//!
//! This module implements the winnow parser combinator for `ipip` IP-in-IP encapsulation frames
//! over outer IP protocol `4` (IPv4-in-IP) or `41` (IPv6-in-IP). It parses inner address family
//! selectors (`v4`, `v6`, or `version <4|6>`), inner IP addresses (`srcip`, `dstip`), inner TTL
//! / Hop Limit (`innerttl <u8>`), inner DSCP (`innerdscp <u8>`), and inner IP protocol numbers
//! (`proto <u8>`) into spanned [`ParsedField`] attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_ip, parse_u32, tag};

/// Parses an IP-in-IP (`ipip`) protocol declaration or inner IP header field.
pub(crate) fn parse_ipip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ipip).map(|(_, s)| ParsedField::Protocol(Protocol::Ipip, (s.start, s.len()))),
            tag(Token::V4).map(|(_, s)| ParsedField::L7U32Field("IPIP_VERSION", 4, (s.start, s.len()))),
            tag(Token::V6).map(|(_, s)| ParsedField::L7U32Field("IPIP_VERSION", 6, (s.start, s.len()))),
            (tag(Token::Version), cut_err(parse_u32.verify(|v| *v == 4 || *v == 6))).map(
                |((_, s), v)| ParsedField::L7U32Field("IPIP_VERSION", v, (s.start, s.end - s.start)),
            ),
            (tag(Token::SrcIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("SRCIP", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::DstIp), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("DSTIP", v, (s.start, s.end - s.start))),
            (tag(Token::InnerTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("INNER_TTL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::InnerDscp), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("INNER_DSCP", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Proto), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("PROTO", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
