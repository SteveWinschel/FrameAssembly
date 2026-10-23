//! MQTT Layer 7 IoT messaging protocol field parser.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an MQTT protocol declaration or publish/subscribe field.
pub(crate) fn parse_mqtt_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mqtt).map(|(_, s)| ParsedField::Protocol(Protocol::Mqtt, (s.start, s.len()))),
            tag(Token::Connect).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "CONNECT", (s.start, s.len()))),
            tag(Token::Connack).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "CONNACK", (s.start, s.len()))),
            tag(Token::Publish).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PUBLISH", (s.start, s.len()))),
            tag(Token::Puback).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PUBACK", (s.start, s.len()))),
            tag(Token::Subscribe).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "SUBSCRIBE", (s.start, s.len()))),
            tag(Token::Suback).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "SUBACK", (s.start, s.len()))),
            tag(Token::Pingreq).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PINGREQ", (s.start, s.len()))),
            tag(Token::Pingresp).map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PINGRESP", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::ClientId), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("CLIENT_ID", v, (s.start, s.end - s.start))),
            (tag(Token::Topic), cut_err(parse_str_val)).map(|((_, s), v)| ParsedField::L7StringField("TOPIC", v, (s.start, s.end - s.start))),
            (tag(Token::Qos), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("QOS", v, (s.start, s.end - s.start))),
            tag(Token::Retain).map(|(_, s)| ParsedField::L7Flag("RETAIN", (s.start, s.len()))),
            (tag(Token::PktId), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("PKT_ID", v, (s.start, s.end - s.start))),
            (tag(Token::Keepalive), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("KEEPALIVE", v, (s.start, s.end - s.start))),
            (tag(Token::ReturnCode), cut_err(parse_u32)).map(|((_, s), v)| ParsedField::L7U32Field("RETURN_CODE", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
