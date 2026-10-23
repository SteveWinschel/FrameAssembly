//! CoAP Layer 7 IoT REST protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a CoAP protocol declaration or RESTful option field.
pub(crate) fn parse_coap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Coap).map(|(_, s)| ParsedField::Protocol(Protocol::Coap, (s.start, s.len()))),
            tag(Token::Con).map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "CON", (s.start, s.len()))),
            tag(Token::Non).map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "NON", (s.start, s.len()))),
            tag(Token::Ack).map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ACK", (s.start, s.len()))),
            tag(Token::Rst).map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "RST", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Code), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::MsgId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("MSGID", v, (s.start, s.end - s.start))),
            (tag(Token::Token), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("TOKEN", v, (s.start, s.end - s.start))),
            (tag(Token::UriPath), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("URI_PATH", v, (s.start, s.end - s.start))),
            (tag(Token::ContentFormat), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("CONTENT_FORMAT", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
