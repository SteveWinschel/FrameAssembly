//! Constrained Application Protocol (CoAP) Layer 7 IoT REST protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 7252 `COAP` constrained RESTful
//! exchanges in FrameAssembly `.fasm` specifications. It recognizes the `COAP` protocol keyword,
//! message types (`CON`, `NON`, `ACK`, `RST`, or `MSG_TYPE`), method/response codes (`CODE` or
//! shorthands `GET`, `POST`, `PUT`, `DELETE`, `CREATED`, `CHANGED`, `NOT_FOUND`), 16-bit message
//! IDs (`MSGID`), client tokens (`TOKEN`), `URI_PATH` options, and `CONTENT_FORMAT` IDs.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a CoAP protocol declaration or RESTful option field.
pub(crate) fn parse_coap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Coap)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Coap, (s.start, s.len()))),
            tag(Token::Con)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "CON", (s.start, s.len()))),
            tag(Token::Non)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "NON", (s.start, s.len()))),
            tag(Token::Ack)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ACK", (s.start, s.len()))),
            tag(Token::Rst)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "RST", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            tag(Token::Get)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "GET", (s.start, s.len()))),
            tag(Token::Post)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "POST", (s.start, s.len()))),
            tag(Token::Put)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "PUT", (s.start, s.len()))),
            tag(Token::Delete)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "DELETE", (s.start, s.len()))),
            tag(Token::Created)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "CREATED", (s.start, s.len()))),
            tag(Token::Changed)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "CHANGED", (s.start, s.len()))),
            tag(Token::NotFound)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "NOT_FOUND", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Code), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::MsgId), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("MSGID", v, (s.start, s.end - s.start))),
            (tag(Token::Token), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("TOKEN", v, (s.start, s.end - s.start))),
            (tag(Token::Token), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("TOKEN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::UriPath), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("URI_PATH", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ContentFormat), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CONTENT_FORMAT", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
