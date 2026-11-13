//! IP Flow Information Export (IPFIX / NetFlow v10) Layer 7 telemetry field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 7011 `ipfix` flow telemetry
//! messages in FrameAssembly `.frasm` specifications. It recognizes the `ipfix` protocol keyword,
//! observation domain identifiers (`domainid`), flow source and destination IP addresses
//! (`srcip`, `dstip`), encapsulated transport protocol numbers (`proto`), packet counts
//! (`packets`), and octet counts (`octets`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u32, tag, ParsedField, Stream};

/// Parses an IPFIX protocol declaration or telemetry export field.
pub(crate) fn parse_ipfix_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ipfix)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Ipfix, (s.start, s.len()))),
        (tag(Token::SrcIp), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::L7IpField("SRCIP", v, (s.start, s.end - s.start))),
        (tag(Token::DstIp), cut_err(parse_ip))
            .map(|((_, s), v)| ParsedField::L7IpField("DSTIP", v, (s.start, s.end - s.start))),
        (tag(Token::Proto), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("PROTO", v, (s.start, s.end - s.start))),
        (tag(Token::Packets), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("PACKETS", v, (s.start, s.end - s.start))),
        (tag(Token::Octets), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("OCTETS", v, (s.start, s.end - s.start))),
        (tag(Token::DomainId), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("DOMAIN_ID", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
