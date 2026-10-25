//! Post Office Protocol Version 3 (POP3) Layer 7 mail retrieval field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 1939 `POP3` mailbox commands and
//! server responses in FrameAssembly `.fasm` specifications. It recognizes the `POP3` protocol
//! keyword, client commands (`CMD`, e.g., `"USER"`, `"PASS"`, `"STAT"`, `"RETR"`, `"QUIT"`),
//! command arguments (`ARG`), status indicator flags (`OK` for `+OK` and `ERR` for `-ERR`), and
//! server response lines (`RESPONSE`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, tag, ParsedField, Stream};

/// Parses a POP3 protocol declaration or mailbox command field.
pub(crate) fn parse_pop3_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Pop3).map(|(_, s)| ParsedField::Protocol(Protocol::Pop3, (s.start, s.len()))),
        (tag(Token::Cmd), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Arg), cut_err(parse_str_val))
            .map(|((_, s), v)| ParsedField::L7StringField("ARG", v, (s.start, s.end - s.start))),
        tag(Token::Ok).map(|(_, s)| ParsedField::L7Flag("OK", (s.start, s.len()))),
        tag(Token::Err).map(|(_, s)| ParsedField::L7Flag("ERR", (s.start, s.len()))),
        (tag(Token::Response), parse_str_val).map(|((_, s), v)| {
            ParsedField::L7StringField("RESPONSE", v, (s.start, s.end - s.start))
        }),
    ))
    .parse_next(input)
}
