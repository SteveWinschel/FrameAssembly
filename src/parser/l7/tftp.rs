//! TFTP Layer 7 file transfer protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a TFTP protocol declaration or transfer parameter field.
pub(crate) fn parse_tftp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Tftp).map(|(_, s)| ParsedField::Protocol(Protocol::Tftp, (s.start, s.len()))),
        tag(Token::Rrq).map(|(_, s)| ParsedField::L7Flag("RRQ", (s.start, s.len()))),
        tag(Token::Wrq).map(|(_, s)| ParsedField::L7Flag("WRQ", (s.start, s.len()))),
        (tag(Token::Filename), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("FILENAME", v, (s.start, s.end - s.start))),
        (tag(Token::Mode), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("MODE", v, (s.start, s.end - s.start))),
        (tag(Token::Block), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("BLOCK", v, (s.start, s.end - s.start))),
        (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))),
        (tag(Token::ErrMsg), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ERRMSG", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
