//! IMAP Layer 7 mail access protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, tag, ParsedField, Stream};

/// Parses an IMAP protocol declaration or mailbox field.
pub(crate) fn parse_imap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Imap).map(|(_, s)| ParsedField::Protocol(Protocol::Imap, (s.start, s.len()))),
        (tag(Token::Tag), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::TagVal(None, Some(v), (s.start, s.end - s.start))),
        (tag(Token::Cmd), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Arg), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ARG", v, (s.start, s.end - s.start))),
        (tag(Token::Status), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("STATUS", v, (s.start, s.end - s.start))),
        (tag(Token::Response), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("RESPONSE", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
