//! Two-Way Active Measurement Protocol (`twamp`, RFC 5357) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 5357 `twamp` TWAMP-Test (UDP
//! port `862`) and TWAMP-Control (TCP port `862` via `transport tcp`) packets in FrameAssembly
//! `.frasm` specifications. It recognizes the `twamp` protocol keyword, TWAMP-Test and
//! TWAMP-Control message type keywords (`sender`, `reflector`, `greeting`, `setupresponse`,
//! `serverstart`, `requestsession`, `acceptsession`, `startsessions`, `startack`, `stopsessions`,
//! or `msgtype`), `seqnum`, `timestamp`, `errorestimate`, `senderttl`, `mode`, `count`, `status`,
//! `port`, and `padding` attributes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_u32, parse_u64, tag,
};

/// Parses a TWAMP protocol declaration or TWAMP-Test / TWAMP-Control field.
pub(crate) fn parse_twamp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Twamp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Twamp, (s.start, s.len()))),
            tag(Token::Sender).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "SENDER", (s.start, s.len()))
            }),
            tag(Token::Reflector).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "REFLECTOR", (s.start, s.len()))
            }),
            tag(Token::Greeting).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "GREETING", (s.start, s.len()))
            }),
            tag(Token::SetupResponse).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "SETUPRESPONSE", (s.start, s.len()))
            }),
            tag(Token::ServerStart).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "SERVERSTART", (s.start, s.len()))
            }),
            tag(Token::RequestSession).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "REQUESTSESSION", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::AcceptSession).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "ACCEPTSESSION", (s.start, s.len()))
            }),
            tag(Token::StartSessions).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "STARTSESSIONS", (s.start, s.len()))
            }),
            tag(Token::StartAck).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "STARTACK", (s.start, s.len()))
            }),
            tag(Token::StopSessions).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "STOPSESSIONS", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Timestamp), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("TWAMP_TIMESTAMP", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::ErrorEstimate), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERROR_ESTIMATE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SenderTtl), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SENDER_TTL", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Mode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TWAMP_MODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Count), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TWAMP_COUNT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Port), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PORT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Padding), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PADDING", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
