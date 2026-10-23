//! WebSocket Layer 7 streaming protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a WebSocket protocol declaration or framing field.
pub(crate) fn parse_websocket_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Websocket).map(|(_, s)| ParsedField::Protocol(Protocol::Websocket, (s.start, s.len()))),
        (tag(Token::Opcode), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("OPCODE", v, (s.start, s.end - s.start))),
        (tag(Token::FinBit), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("FIN_BIT", v, (s.start, s.end - s.start))),
        (tag(Token::MaskKey), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("MASK_KEY", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
