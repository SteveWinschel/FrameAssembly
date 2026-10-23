//! STUN Layer 7 NAT traversal protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ip, parse_str_val, tag, ParsedField, Stream};

/// Parses a STUN protocol declaration or binding attribute field.
pub(crate) fn parse_stun_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Stun).map(|(_, s)| ParsedField::Protocol(Protocol::Stun, (s.start, s.len()))),
        tag(Token::BindingRequest).map(|(_, s)| ParsedField::L7Flag("BINDING_REQUEST", (s.start, s.len()))),
        tag(Token::BindingResponse).map(|(_, s)| ParsedField::L7Flag("BINDING_RESPONSE", (s.start, s.len()))),
        tag(Token::BindingError).map(|(_, s)| ParsedField::L7Flag("BINDING_ERROR", (s.start, s.len()))),
        (tag(Token::XorMappedAddr), cut_err(parse_ip)).map(|((_, s), v)| ParsedField::L7IpField("XOR_MAPPED_ADDR", v, (s.start, s.end - s.start))),
        (tag(Token::Software), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("SOFTWARE", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
