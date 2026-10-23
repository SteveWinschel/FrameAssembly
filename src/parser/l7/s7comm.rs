//! S7comm Layer 7 industrial PLC protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an S7comm protocol declaration or PLC memory field.
pub(crate) fn parse_s7comm_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::S7comm).map(|(_, s)| ParsedField::Protocol(Protocol::S7comm, (s.start, s.len()))),
        (tag(Token::Rosctr), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("ROSCTR", v, (s.start, s.end - s.start))),
        (tag(Token::PduRef), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("PDU_REF", v, (s.start, s.end - s.start))),
        (tag(Token::Func), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
        (tag(Token::Area), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("AREA", v, (s.start, s.end - s.start))),
        (tag(Token::DbNum), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("DB_NUM", v, (s.start, s.end - s.start))),
        (tag(Token::Offset), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("OFFSET", v, (s.start, s.end - s.start))),
        (tag(Token::Count), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
