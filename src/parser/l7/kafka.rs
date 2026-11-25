//! Apache Kafka Binary Wire Protocol (TCP port `9092`) Layer 7 winnow parser combinators.
//!
//! This module implements protocol-scoped parsing for `kafka` frame declarations and modifiers
//! including API selectors (`apiversions`, `metadata`, `produce`, `fetch`, `heartbeat`, `apikey`),
//! direction (`response`), framing parameters (`version`, `correlationid`, `clientid`, `acks`),
//! and message/topic fields (`topic`, `partition`, `offset`, `key`, `value`, `group`, `errcode`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_i32, parse_u16, parse_u64, tag};

/// Parses a borrowed `i16` API key numeric token string (`&'a str`) for Kafka `apikey`.
fn parse_apikey_num_str<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    any.verify_map(|(t, _, _)| match t {
        Token::Number(s) if s.parse::<i16>().is_ok() => Some(s),
        _ => None,
    })
    .parse_next(input)
}

/// Parses primary Kafka protocol keyword and API shorthands (`<= 8` `alt` arms).
fn parse_kafka_head<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Kafka).map(|(_, s)| ParsedField::Protocol(Protocol::Kafka, (s.start, s.end - s.start))),
        tag(Token::ApiVersions)
            .map(|(_, s)| ParsedField::L7Flag("apiversions", (s.start, s.end - s.start))),
        tag(Token::Metadata)
            .map(|(_, s)| ParsedField::L7Flag("metadata", (s.start, s.end - s.start))),
        tag(Token::Produce).map(|(_, s)| ParsedField::L7Flag("produce", (s.start, s.end - s.start))),
        tag(Token::Fetch).map(|(_, s)| ParsedField::L7Flag("fetch", (s.start, s.end - s.start))),
        tag(Token::Heartbeat)
            .map(|(_, s)| ParsedField::L7Flag("heartbeat", (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses Kafka header, direction, and client/group modifiers (`<= 8` `alt` arms).
fn parse_kafka_header_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Response).map(|(_, s)| ParsedField::L7Flag("response", (s.start, s.end - s.start))),
        (
            tag(Token::ApiKey),
            cut_err(alt((parse_apikey_num_str, parse_any_str))),
        )
            .map(|((_, s), v)| {
                ParsedField::L7StringField("api", v, (s.start, s.end - s.start))
            }),
        (tag(Token::Version), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::L7U32Field("api_version", v as u32, (s.start, s.end - s.start))),
        (tag(Token::CorrelationId), cut_err(parse_i32))
            .map(|((_, s), v)| ParsedField::L7I32Field("correlation_id", v, (s.start, s.end - s.start))),
        (tag(Token::ClientId), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("client_id", v, (s.start, s.end - s.start))),
        (tag(Token::Group), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("group", v, (s.start, s.end - s.start))),
        (tag(Token::Acks), cut_err(parse_i32))
            .map(|((_, s), v)| ParsedField::L7I32Field("acks", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses Kafka topic, partition, offset, record payload, and error code modifiers (`<= 8` `alt` arms).
fn parse_kafka_data_mods<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        (tag(Token::Topic), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("topic", v, (s.start, s.end - s.start))),
        (tag(Token::Partition), cut_err(parse_i32))
            .map(|((_, s), v)| ParsedField::L7I32Field("partition", v, (s.start, s.end - s.start))),
        (tag(Token::Offset), cut_err(parse_u64))
            .map(|((_, s), v)| ParsedField::L7U64Field("offset", v, (s.start, s.end - s.start))),
        (tag(Token::Key), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("key", v, (s.start, s.end - s.start))),
        (tag(Token::Value), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::L7StringField("value", v, (s.start, s.end - s.start))),
        (tag(Token::ErrCode), cut_err(parse_i32))
            .map(|((_, s), v)| ParsedField::L7I32Field("errcode", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}

/// Parses a `kafka` protocol keyword or one of its wire protocol modifier fields.
pub(crate) fn parse_kafka_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        parse_kafka_head,
        parse_kafka_header_mods,
        parse_kafka_data_mods,
    ))
    .parse_next(input)
}
