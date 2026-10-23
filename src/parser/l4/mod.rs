//! Layer 4 transport protocol and option field parsers.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u16, parse_u32, tag, ParsedField, Stream};

/// Stream Control Transmission Protocol parser.
pub mod sctp;
/// Transmission Control Protocol parser.
pub mod tcp;
/// User Datagram Protocol parser.
pub mod udp;

pub(crate) use sctp::*;
pub(crate) use tcp::*;
pub(crate) use udp::*;

/// Parses a Layer 4 protocol or modifier field from a token stream.
pub(crate) fn parse_l4_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        parse_tcp_field,
        parse_udp_field,
        parse_sctp_field,
        alt((
            (tag(Token::SrcPort), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::SrcPort(v, (s.start, s.end - s.start))),
            (tag(Token::DstPort), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::DstPort(v, (s.start, s.end - s.start))),
            (tag(Token::Transport), cut_err(alt((tag(Token::Tcp).value(TransportProto::Tcp), tag(Token::Udp).value(TransportProto::Udp)))))
                .map(|((_, s), v)| ParsedField::Transport(v, (s.start, s.end - s.start))),
            (tag(Token::Seq), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Seq(v, (s.start, s.end - s.start))),
            (tag(Token::AckNum), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::AckNum(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
