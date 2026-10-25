//! Message Queuing Telemetry Transport (MQTT v3.1.1) Layer 7 IoT protocol field parser.
//!
//! This module implements the `winnow` parser combinator for OASIS `MQTT` v3.1.1 publish/subscribe
//! control packets in FrameAssembly `.fasm` specifications. It recognizes the `MQTT` protocol
//! keyword, control packet types (`CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`, `SUBSCRIBE`,
//! `SUBACK`, `PINGREQ`, `PINGRESP`, `DISCONNECT` or explicit `PKT_TYPE`), client identifiers
//! (`CLIENT_ID`), topic strings (`TOPIC`), QoS levels (`QOS`), `RETAIN` flags, packet IDs
//! (`PKT_ID`), `KEEPALIVE` timers, and `RETURN_CODE` values.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an MQTT protocol declaration or publish/subscribe field.
pub(crate) fn parse_mqtt_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Mqtt)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Mqtt, (s.start, s.len()))),
            tag(Token::Connect)
                .map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "CONNECT", (s.start, s.len()))),
            tag(Token::Connack)
                .map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "CONNACK", (s.start, s.len()))),
            tag(Token::Publish)
                .map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PUBLISH", (s.start, s.len()))),
            tag(Token::Puback)
                .map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PUBACK", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Subscribe).map(|(_, s)| {
                ParsedField::L7StringField("PKT_TYPE", "SUBSCRIBE", (s.start, s.len()))
            }),
            tag(Token::Suback)
                .map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "SUBACK", (s.start, s.len()))),
            tag(Token::Pingreq)
                .map(|(_, s)| ParsedField::L7StringField("PKT_TYPE", "PINGREQ", (s.start, s.len()))),
            tag(Token::Pingresp).map(|(_, s)| {
                ParsedField::L7StringField("PKT_TYPE", "PINGRESP", (s.start, s.len()))
            }),
            tag(Token::Disconnect).map(|(_, s)| {
                ParsedField::L7StringField("PKT_TYPE", "DISCONNECT", (s.start, s.len()))
            }),
            (tag(Token::Ident("PKT_TYPE")), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("PKT_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::ClientId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("CLIENT_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Topic), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("TOPIC", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Qos), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("QOS", v, (s.start, s.end - s.start))),
            (tag(Token::Retain), opt(parse_u32)).map(|((_, s), v)| {
                if v == Some(0) {
                    ParsedField::L7Flag("NO_RETAIN", (s.start, s.len()))
                } else {
                    ParsedField::L7Flag("RETAIN", (s.start, s.len()))
                }
            }),
            (tag(Token::PktId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PKT_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Keepalive), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("KEEPALIVE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ReturnCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RETURN_CODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
