//! EtherNet/IP Layer 7 industrial CIP protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses an EtherNet/IP protocol declaration or CIP session field.
pub(crate) fn parse_ethernetip_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Ethernetip).map(|(_, s)| ParsedField::Protocol(Protocol::Ethernetip, (s.start, s.len()))),
        (tag(Token::Cmd), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
        (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))),
        (tag(Token::SessionHandle), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("SESSION_HANDLE", v, (s.start, s.end - s.start))),
        (tag(Token::ContextVal), cut_err(parse_u64)).map(|((_, s), v)| ParsedField::L7U64Field("CONTEXT", v, (s.start, s.end - s.start))),
        (tag(Token::CipService), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CIP_SERVICE", v, (s.start, s.end - s.start))),
        (tag(Token::CipClass), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CIP_CLASS", v, (s.start, s.end - s.start))),
        (tag(Token::CipInstance), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CIP_INSTANCE", v, (s.start, s.end - s.start))),
        (tag(Token::CipAttr), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CIP_ATTR", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
