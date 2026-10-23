//! FTP Layer 7 file transfer protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an FTP protocol declaration or command/reply field.
pub(crate) fn parse_ftp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ftp).map(|(_, s)| ParsedField::Protocol(Protocol::Ftp, (s.start, s.len()))),
        (tag(Token::Cmd), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Arg), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ARG", v, (s.start, s.end - s.start))),
        (tag(Token::Code), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CODE", v, (s.start, s.end - s.start))),
        (tag(Token::Reply), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("REPLY", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
