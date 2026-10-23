//! WHOIS Layer 7 registry protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, tag, ParsedField, Stream};

/// Parses a WHOIS protocol declaration or domain lookup field.
pub(crate) fn parse_whois_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Whois).map(|(_, s)| ParsedField::Protocol(Protocol::Whois, (s.start, s.len()))),
        (tag(Token::Domain), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("DOMAIN", v, (s.start, s.end - s.start))),
        (tag(Token::Registrar), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("REGISTRAR", v, (s.start, s.end - s.start))),
        tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("QUERY", (s.start, s.len()))),
        tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
    ))
    .parse_next(input)
}
