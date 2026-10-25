//! Generic Network Virtualization Encapsulation (`GENEVE`, RFC 8926) tunnel parser.
//!
//! This module implements the winnow parser combinator for `GENEVE` network virtualization
//! overlay packets. It parses 24-bit Virtual Network Identifiers (`VNI <u32>` or `VNID <u32>`),
//! TLV Option Class namespaces (`OPT_CLASS <u16>`), Option Type codes (`OPT_TYPE <u8>`), and inner
//! EtherType protocol identifiers (`PROTOCOL_TYPE <u16>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u16, parse_u32, tag};

/// Parses a GENEVE protocol declaration or option field.
pub(crate) fn parse_geneve_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Geneve)
            .map(|(_, s)| ParsedField::Protocol(Protocol::Geneve, (s.start, s.len()))),
        (alt((tag(Token::Vni), tag(Token::Vnid))), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Vni(v, (s.start, s.end - s.start))),
        (tag(Token::OptClass), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::OptClass(v, (s.start, s.end - s.start))),
        (tag(Token::OptType), cut_err(parse_u8))
            .map(|((_, s), v)| ParsedField::OptType(v, (s.start, s.end - s.start))),
        (tag(Token::ProtocolType), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::ProtocolType(v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
