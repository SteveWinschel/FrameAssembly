//! NFS Layer 7 network file system protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an NFS protocol declaration or RPC procedure field.
pub(crate) fn parse_nfs_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Nfs).map(|(_, s)| ParsedField::Protocol(Protocol::Nfs, (s.start, s.len()))),
        (tag(Token::Vers), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("VERS", v, (s.start, s.end - s.start))),
        (tag(Token::Proc), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("PROC", v, (s.start, s.end - s.start))),
        (tag(Token::Tag), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::TagVal(None, Some(v), (s.start, s.end - s.start))),
        (tag(Token::Path), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("PATH", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
