//! Terminal Access Controller Access-Control System Plus (TACACS+) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 8907 `TACACS` authentication,
//! authorization, and accounting frames in FrameAssembly `.fasm` specifications. It recognizes
//! the `TACACS` protocol keyword, session types (`AUTHEN`, `AUTHOR`, `ACCT` bare or after `TYPE`),
//! session identifiers (`SESSION_ID`), sequence numbers (`SEQ`), header flags (`FLAGS`), user
//! principals (`USER`), and payload data strings (`DATA`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u8, parse_u64, tag, ParsedField, Stream};

/// Parses a TACACS+ protocol declaration or session field.
pub(crate) fn parse_tacacs_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Tacacs)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Tacacs, (s.start, s.len()))),
            (
                tag(Token::Type),
                alt((
                    tag(Token::Authen).value("AUTHEN"),
                    tag(Token::Author).value("AUTHOR"),
                    tag(Token::Acct).value("ACCT"),
                    parse_str_val,
                )),
            )
                .map(|((_, s), v)| {
                    ParsedField::L7StringField("TACACS_TYPE", v, (s.start, s.end - s.start))
                }),
            tag(Token::Authen)
                .map(|(_, s)| ParsedField::L7StringField("TACACS_TYPE", "AUTHEN", (s.start, s.len()))),
            tag(Token::Author)
                .map(|(_, s)| ParsedField::L7StringField("TACACS_TYPE", "AUTHOR", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Acct)
                .map(|(_, s)| ParsedField::L7StringField("TACACS_TYPE", "ACCT", (s.start, s.len()))),
            (tag(Token::Flags), parse_u8)
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::SessionId), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("SESSION_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Data), parse_str_val)
                .map(|((_, s), v)| ParsedField::L7StringField("DATA", v, (s.start, s.end - s.start))),
            (tag(Token::User), parse_str_val)
                .map(|((_, s), v)| ParsedField::User(v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
