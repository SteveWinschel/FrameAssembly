//! BACnet Layer 7 building automation protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, tag, ParsedField, Stream};

/// Parses a BACnet protocol declaration or object property field.
pub(crate) fn parse_bacnet_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Bacnet).map(|(_, s)| ParsedField::Protocol(Protocol::Bacnet, (s.start, s.len()))),
            tag(Token::WhoIs).map(|(_, s)| ParsedField::L7Flag("WHO_IS", (s.start, s.len()))),
            tag(Token::IAm).map(|(_, s)| ParsedField::L7Flag("I_AM", (s.start, s.len()))),
            tag(Token::ReadProperty).map(|(_, s)| ParsedField::L7Flag("READ_PROPERTY", (s.start, s.len()))),
            tag(Token::WriteProperty).map(|(_, s)| ParsedField::L7Flag("WRITE_PROPERTY", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::InvokeId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("INVOKE_ID", v, (s.start, s.end - s.start))),
            (tag(Token::ObjectType), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("OBJECT_TYPE", v, (s.start, s.end - s.start))),
            (tag(Token::ObjectInstance), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("OBJECT_INSTANCE", v, (s.start, s.end - s.start))),
            (tag(Token::PropertyId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("PROPERTY_ID", v, (s.start, s.end - s.start))),
            (tag(Token::Value), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
