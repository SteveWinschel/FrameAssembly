//! QUIC (RFC 9000) Layer 7 encrypted transport protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 9000 `QUIC` long-header and
//! short-header packets in FrameAssembly `.fasm` specifications. It recognizes the `QUIC` protocol
//! keyword, packet type flags (`INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`, `SHORT`), protocol
//! versions (`VERSION`), destination and source connection IDs (`DCID`, `SCID` as numeric or hex
//! string literals), retry/initial tokens (`TOKEN`), and packet numbers (`PKT_NUM`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses a QUIC protocol declaration or packet field.
pub(crate) fn parse_quic_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Quic)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Quic, (s.start, s.len()))),
            tag(Token::Initial).map(|(_, s)| ParsedField::L7Flag("INITIAL", (s.start, s.len()))),
            tag(Token::ZeroRtt).map(|(_, s)| ParsedField::L7Flag("ZERO_RTT", (s.start, s.len()))),
            tag(Token::Handshake)
                .map(|(_, s)| ParsedField::L7Flag("HANDSHAKE", (s.start, s.len()))),
            tag(Token::Retry).map(|(_, s)| ParsedField::L7Flag("RETRY", (s.start, s.len()))),
            tag(Token::Short).map(|(_, s)| ParsedField::L7Flag("SHORT", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Version), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Dcid), parse_u64)
                .map(|((_, s), v)| ParsedField::L7U64Field("DCID", v, (s.start, s.end - s.start))),
            (tag(Token::Dcid), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("DCID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Scid), parse_u64)
                .map(|((_, s), v)| ParsedField::L7U64Field("SCID", v, (s.start, s.end - s.start))),
            (tag(Token::Scid), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("SCID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Token), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("TOKEN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::PktNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PKT_NUM", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
