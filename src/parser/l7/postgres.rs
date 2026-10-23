//! PostgreSQL Layer 7 database protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, tag, ParsedField, Stream};

/// Parses a PostgreSQL protocol declaration or frontend/backend message field.
pub(crate) fn parse_postgres_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Postgres).map(|(_, s)| ParsedField::Protocol(Protocol::Postgres, (s.start, s.len()))),
        tag(Token::Startup).map(|(_, s)| ParsedField::L7Flag("STARTUP", (s.start, s.len()))),
        (tag(Token::Sql), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("SQL", v, (s.start, s.end - s.start))),
        tag(Token::ReadyForQuery).map(|(_, s)| ParsedField::L7Flag("READY_FOR_QUERY", (s.start, s.len()))),
        tag(Token::CommandComplete).map(|(_, s)| ParsedField::L7Flag("COMMAND_COMPLETE", (s.start, s.len()))),
        tag(Token::ErrorResponse).map(|(_, s)| ParsedField::L7Flag("ERROR_RESPONSE", (s.start, s.len()))),
        tag(Token::AuthOk).map(|(_, s)| ParsedField::L7Flag("AUTH_OK", (s.start, s.len()))),
        (tag(Token::Db), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("DB", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
