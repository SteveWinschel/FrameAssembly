//! BGP Layer 3 routing protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_str_val, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses a BGP protocol declaration or message field.
pub(crate) fn parse_bgp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Bgp).map(|(_, s)| ParsedField::Protocol(Protocol::Bgp, (s.start, s.len()))),
            tag(Token::Open).map(|(_, s)| ParsedField::BgpType(BgpType::Open, (s.start, s.len()))),
            tag(Token::Update).map(|(_, s)| ParsedField::BgpType(BgpType::Update, (s.start, s.len()))),
            tag(Token::Notification).map(|(_, s)| ParsedField::BgpType(BgpType::Notification, (s.start, s.len()))),
            tag(Token::Keepalive).map(|(_, s)| ParsedField::BgpType(BgpType::Keepalive, (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Asn), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Asn(v, (s.start, s.end - s.start))),
            (tag(Token::HoldTime), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::HoldTime(v, (s.start, s.end - s.start))),
            (tag(Token::BgpId), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::BgpId(v, (s.start, s.end - s.start))),
            (tag(Token::Prefix), parse_str_val).map(|((_, s), v)| ParsedField::PrefixVal(None, Some(v), (s.start, s.end - s.start))),
            (tag(Token::NextHop), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::NextHop(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
