//! OSPF Layer 3 routing protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses an OSPF protocol declaration or packet field.
pub(crate) fn parse_ospf_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ospf).map(|(_, s)| ParsedField::Protocol(Protocol::Ospf, (s.start, s.len()))),
            tag(Token::Hello).map(|(_, s)| ParsedField::OspfType(OspfType::Hello, (s.start, s.len()))),
            tag(Token::Dbd).map(|(_, s)| ParsedField::OspfType(OspfType::Dbd, (s.start, s.len()))),
            tag(Token::Lsr).map(|(_, s)| ParsedField::OspfType(OspfType::Lsr, (s.start, s.len()))),
            tag(Token::Lsu).map(|(_, s)| ParsedField::OspfType(OspfType::Lsu, (s.start, s.len()))),
        )),
        alt((
            tag(Token::LsAck).map(|(_, s)| ParsedField::OspfType(OspfType::LsAck, (s.start, s.len()))),
            (tag(Token::RouterId), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::RouterId(v, (s.start, s.end - s.start))),
            (tag(Token::AreaId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::AreaId(v, (s.start, s.end - s.start))),
            (tag(Token::HelloInterval), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::HelloInterval(v, (s.start, s.end - s.start))),
            (tag(Token::DeadInterval), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::DeadInterval(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
