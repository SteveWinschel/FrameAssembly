//! Encapsulating Security Payload (ESP) Layer 3 protocol field parser.

use winnow::ModalResult as PResult;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{tag, ParsedField, Stream};

/// Parses an ESP protocol declaration.
pub(crate) fn parse_esp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    tag(Token::Esp)
        .map(|(_, s)| ParsedField::Protocol(Protocol::Esp, (s.start, s.len())))
        .parse_next(input)
}
