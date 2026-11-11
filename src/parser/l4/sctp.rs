//! Stream Control Transmission Protocol (`sctp`, RFC 4960) field parser for FrameAssembly.
//!
//! This module implements the winnow parser combinator for `sctp` association and chunk modifiers.
//! It supports Verification Tag (`vtag`), Stream Identifier (`stream`), Stream Sequence Number
//! (`ssn`), Payload Protocol Identifier (`ppid`), Transmission Sequence Number (`tsn`), explicit
//! chunk type (`chunk <type>`), and bare shorthand chunk keywords (`data`, `init`, `initack`,
//! `sack`, `heartbeat`, `heartbeatack`, `abort`, `shutdown`, `shutdownack`, `cookieecho`,
//! `cookieack`).

use alloc::string::ToString;
use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u16, parse_u32, tag};

/// Parses an SCTP protocol declaration or transport parameter field.
pub(crate) fn parse_sctp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Sctp).map(|(_, s)| ParsedField::Protocol(Protocol::Sctp, (s.start, s.len()))),
        (tag(Token::Vtag), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Vtag(v, (s.start, s.end - s.start))),
        (tag(Token::Stream), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::Stream(v, (s.start, s.end - s.start))),
        (tag(Token::Ssn), cut_err(parse_u16))
            .map(|((_, s), v)| ParsedField::Ssn(v, (s.start, s.end - s.start))),
        (tag(Token::Ppid), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Ppid(v, (s.start, s.end - s.start))),
        (tag(Token::Tsn), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::Seq(v, (s.start, s.end - s.start))),
        (tag(Token::Chunk), cut_err(parse_any_str))
            .map(|((_, s), v)| ParsedField::Chunk(v.to_string(), (s.start, s.end - s.start))),
        alt((
            tag(Token::Data).map(|(_, s)| ParsedField::Chunk("DATA".to_string(), (s.start, s.len()))),
            tag(Token::Init).map(|(_, s)| ParsedField::Chunk("INIT".to_string(), (s.start, s.len()))),
            tag(Token::InitAck)
                .map(|(_, s)| ParsedField::Chunk("INIT_ACK".to_string(), (s.start, s.len()))),
            tag(Token::Sack).map(|(_, s)| ParsedField::Chunk("SACK".to_string(), (s.start, s.len()))),
            tag(Token::Heartbeat)
                .map(|(_, s)| ParsedField::Chunk("HEARTBEAT".to_string(), (s.start, s.len()))),
        )),
        alt((
            tag(Token::HeartbeatAck)
                .map(|(_, s)| ParsedField::Chunk("HEARTBEAT_ACK".to_string(), (s.start, s.len()))),
            tag(Token::Abort)
                .map(|(_, s)| ParsedField::Chunk("ABORT".to_string(), (s.start, s.len()))),
            tag(Token::Shutdown)
                .map(|(_, s)| ParsedField::Chunk("SHUTDOWN".to_string(), (s.start, s.len()))),
            tag(Token::ShutdownAck)
                .map(|(_, s)| ParsedField::Chunk("SHUTDOWN_ACK".to_string(), (s.start, s.len()))),
            tag(Token::CookieEcho)
                .map(|(_, s)| ParsedField::Chunk("COOKIE_ECHO".to_string(), (s.start, s.len()))),
            tag(Token::CookieAck)
                .map(|(_, s)| ParsedField::Chunk("COOKIE_ACK".to_string(), (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
