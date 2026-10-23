//! User Datagram Protocol (UDP) field parser.

use winnow::ModalResult as PResult;
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{tag, ParsedField, Stream};

/// Parses a UDP protocol declaration.
pub(crate) fn parse_udp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    tag(Token::Udp)
        .map(|(_, s)| ParsedField::Protocol(Protocol::Udp, (s.start, s.len())))
        .parse_next(input)
}
