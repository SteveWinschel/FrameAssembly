//! RADIUS Layer 7 authentication protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a RADIUS protocol declaration or AAA attribute field.
pub(crate) fn parse_radius_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Radius).map(|(_, s)| ParsedField::Protocol(Protocol::Radius, (s.start, s.len()))),
            tag(Token::AccessRequest).map(|(_, s)| ParsedField::L7StringField("CODE", "ACCESS_REQUEST", (s.start, s.len()))),
            tag(Token::AccessAccept).map(|(_, s)| ParsedField::L7StringField("CODE", "ACCESS_ACCEPT", (s.start, s.len()))),
            tag(Token::AccessReject).map(|(_, s)| ParsedField::L7StringField("CODE", "ACCESS_REJECT", (s.start, s.len()))),
            tag(Token::AccessChallenge).map(|(_, s)| ParsedField::L7StringField("CODE", "ACCESS_CHALLENGE", (s.start, s.len()))),
            tag(Token::AccountingRequest).map(|(_, s)| ParsedField::L7StringField("CODE", "ACCOUNTING_REQUEST", (s.start, s.len()))),
            tag(Token::AccountingResponse).map(|(_, s)| ParsedField::L7StringField("CODE", "ACCOUNTING_RESPONSE", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Code), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::User), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
            (tag(Token::NasIp), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("NAS_IP", v, (s.start, s.end - s.start))),
            (tag(Token::ServiceType), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("SERVICE_TYPE", v, (s.start, s.end - s.start))),
            (tag(Token::FramedIp), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("FRAMED_IP", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
