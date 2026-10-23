//! Authentication Header (AH) Layer 3 protocol field parser.

use winnow::ModalResult as PResult;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{tag, ParsedField, Stream};

/// Parses an AH protocol declaration.
pub(crate) fn parse_ah_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    tag(Token::Ah)
        .map(|(_, s)| ParsedField::Protocol(Protocol::Ah, (s.start, s.len())))
        .parse_next(input)
}
