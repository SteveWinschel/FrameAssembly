//! Cisco NetFlow v5 Layer 7 network flow telemetry protocol field parser.
//!
//! This module implements the `winnow` parser combinator for Cisco `NETFLOW` v5 flow export
//! datagrams in FrameAssembly `.fasm` specifications. It recognizes the `NETFLOW` protocol
//! keyword, flow source and destination IPv4 addresses (`SRCIP`, `DSTIP`), IP protocol numbers
//! (`PROTO`), packet counters (`PACKETS`), and byte counters (`OCTETS`), while `SRCPORT` and
//! `DSTPORT` are populated through universal modifier dispatch.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u32, tag, ParsedField, Stream};

/// Parses a NetFlow protocol declaration or flow telemetry field.
pub(crate) fn parse_netflow_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Netflow)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Netflow, (s.start, s.len()))),
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
    ))
    .parse_next(input)
}
