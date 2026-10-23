//! Modbus Layer 7 industrial automation protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a Modbus protocol declaration or register field.
pub(crate) fn parse_modbus_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Modbus).map(|(_, s)| ParsedField::Protocol(Protocol::Modbus, (s.start, s.len()))),
        (tag(Token::Txid), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
        (tag(Token::ProtoId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("PROTO_ID", v, (s.start, s.end - s.start))),
        (tag(Token::UnitId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("UNITID", v, (s.start, s.end - s.start))),
        (tag(Token::Func), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
        (tag(Token::Addr), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("ADDR", v, (s.start, s.end - s.start))),
        (tag(Token::Count), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))),
        (tag(Token::Value), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
        tag(Token::IsResponse).map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
    ))
    .parse_next(input)
}
