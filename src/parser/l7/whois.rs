//! WHOIS (RFC 3912) Layer 7 domain and IP registry lookup protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 3912 `WHOIS` directory lookup
//! queries and registry responses in FrameAssembly `.fasm` specifications. It recognizes the
//! `WHOIS` protocol keyword, direction flags (`QUERY`, `RESPONSE`), queried domain names or IP
//! prefixes (`DOMAIN`), and sponsoring registrar names (`REGISTRAR`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, tag, ParsedField, Stream};

/// Parses a WHOIS protocol declaration or domain lookup field.
pub(crate) fn parse_whois_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Whois).map(|(_, s)| ParsedField::Protocol(Protocol::Whois, (s.start, s.len()))),
        (tag(Token::Domain), parse_any_str)
            .map(|((_, s), v)| ParsedField::L7StringField("DOMAIN", v, (s.start, s.end - s.start))),
        (tag(Token::Registrar), cut_err(parse_str_val)).map(|((_, s), v)| {
            ParsedField::L7StringField("REGISTRAR", v, (s.start, s.end - s.start))
        }),
        tag(Token::Query).map(|(_, s)| ParsedField::L7Flag("QUERY", (s.start, s.len()))),
        tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("RESPONSE", (s.start, s.len()))),
    ))
    .parse_next(input)
}
