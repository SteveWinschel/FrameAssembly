//! GPRS Tunneling Protocol User Plane (`gtpu`, 3GPP TS 29.281) parser for FrameAssembly.
//!
//! This module implements the `winnow` parser combinator for GTPv1-U user-plane tunnel packets
//! carried over UDP port `2152`. It recognizes the `gtpu` protocol keyword, GTPv1-U message types
//! (`gpdu`, `echorequest`, `echoreply`, `errorindication`, `endmarker`), 32-bit Tunnel Endpoint
//! Identifiers (`teid <u32>`), header flags (`flags <u8>`), sequence numbers (`seqnum <u16>`),
//! N-PDU numbers (`npdu <u8>`), and 5G QoS Flow Identifiers (`qfi <0..63>`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_u8, parse_u16, parse_u32, tag};

/// Parses a GTP-U protocol declaration, message type, or tunnel header field.
pub(crate) fn parse_gtpu_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Gtpu).map(|(_, s)| ParsedField::Protocol(Protocol::Gtpu, (s.start, s.len()))),
            tag(Token::Gpdu)
                .map(|(_, s)| ParsedField::L7StringField("GTPU_TYPE", "GPDU", (s.start, s.len()))),
            tag(Token::EchoRequest).map(|(_, s)| {
                ParsedField::L7StringField("GTPU_TYPE", "ECHOREQUEST", (s.start, s.len()))
            }),
            tag(Token::EchoReply).map(|(_, s)| {
                ParsedField::L7StringField("GTPU_TYPE", "ECHOREPLY", (s.start, s.len()))
            }),
            tag(Token::ErrorIndication).map(|(_, s)| {
                ParsedField::L7StringField("GTPU_TYPE", "ERRORINDICATION", (s.start, s.len()))
            }),
            tag(Token::EndMarker).map(|(_, s)| {
                ParsedField::L7StringField("GTPU_TYPE", "ENDMARKER", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Teid), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("GTPU_TEID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u8)
                .map(|((_, s), v)| ParsedField::FlagsByte(v, (s.start, s.end - s.start))),
            (tag(Token::SeqNum), parse_u16).map(|((_, s), v)| {
                ParsedField::L7U32Field("GTPU_SEQNUM", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Npdu), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("GTPU_NPDU", u32::from(v), (s.start, s.end - s.start))
            }),
            (tag(Token::Qfi), cut_err(parse_u8)).map(|((_, s), v)| {
                ParsedField::L7U32Field("GTPU_QFI", u32::from(v), (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
