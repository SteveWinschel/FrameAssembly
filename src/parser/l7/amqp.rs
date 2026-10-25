//! Advanced Message Queuing Protocol (AMQP 0-9-1) Layer 7 broker protocol field parser.
//!
//! This module implements the `winnow` parser combinator for `AMQP` 0-9-1 message broker frames in
//! FrameAssembly `.fasm` specifications. It recognizes the `AMQP` protocol keyword, frame type
//! flags (`PROTOCOL_HEADER`, `CONNECTION_START`, `CHANNEL_OPEN`, `BASIC_PUBLISH`, `BASIC_DELIVER`,
//! `HEARTBEAT`), virtual channel numbers (`CHANNEL`), broker exchange names (`EXCHANGE`), and
//! message routing keys (`ROUTING_KEY`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an AMQP protocol declaration or message broker field.
pub(crate) fn parse_amqp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Amqp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Amqp, (s.start, s.len()))),
            tag(Token::ProtocolHeader)
                .map(|(_, s)| ParsedField::L7Flag("PROTOCOL_HEADER", (s.start, s.len()))),
            tag(Token::ConnectionStart)
                .map(|(_, s)| ParsedField::L7Flag("CONNECTION_START", (s.start, s.len()))),
            tag(Token::ChannelOpen)
                .map(|(_, s)| ParsedField::L7Flag("CHANNEL_OPEN", (s.start, s.len()))),
            tag(Token::BasicPublish)
                .map(|(_, s)| ParsedField::L7Flag("BASIC_PUBLISH", (s.start, s.len()))),
        )),
        alt((
            tag(Token::BasicDeliver)
                .map(|(_, s)| ParsedField::L7Flag("BASIC_DELIVER", (s.start, s.len()))),
            tag(Token::Heartbeat)
                .map(|(_, s)| ParsedField::L7Flag("HEARTBEAT", (s.start, s.len()))),
            (tag(Token::Channel), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CHANNEL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Exchange), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("EXCHANGE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::RoutingKey), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("ROUTING_KEY", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
