//! DNP3 Layer 7 industrial SCADA protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a DNP3 protocol declaration or supervisory control field.
pub(crate) fn parse_dnp3_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Dnp3).map(|(_, s)| ParsedField::Protocol(Protocol::Dnp3, (s.start, s.len()))),
        (tag(Token::Func), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
        (tag(Token::Src), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("SRC", v, (s.start, s.end - s.start))),
        (tag(Token::Dst), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("DST", v, (s.start, s.end - s.start))),
        (tag(Token::Group), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("GROUP", v, (s.start, s.end - s.start))),
        (tag(Token::Variation), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("VARIATION", v, (s.start, s.end - s.start))),
        (tag(Token::Crc), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CRC", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
