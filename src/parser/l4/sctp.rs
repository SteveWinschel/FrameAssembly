//! Stream Control Transmission Protocol (SCTP) field parser.

use alloc::string::ToString;
use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_spanned_ident, parse_u16, parse_u32, tag, ParsedField, Stream};

/// Parses an SCTP protocol declaration or transport parameter field.
pub(crate) fn parse_sctp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Sctp).map(|(_, s)| ParsedField::Protocol(Protocol::Sctp, (s.start, s.len()))),
        (tag(Token::Vtag), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Vtag(v, (s.start, s.end - s.start))),
        (tag(Token::Stream), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::Stream(v, (s.start, s.end - s.start))),
        (tag(Token::Ssn), cut_err(parse_u16)).map(|((_, s), v)| ParsedField::Ssn(v, (s.start, s.end - s.start))),
        (tag(Token::Ppid), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::Ppid(v, (s.start, s.end - s.start))),
        (tag(Token::Chunk), cut_err(parse_spanned_ident)).map(|((_, s), v)| ParsedField::Chunk(v.node.to_string(), (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
