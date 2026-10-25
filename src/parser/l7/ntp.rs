//! Network Time Protocol (NTPv4) Layer 7 clock synchronization field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 5905 Network Time Protocol (`NTP`)
//! headers in FrameAssembly `.fasm` specifications. It recognizes the `NTP` protocol keyword, leap
//! indicators (`LI`), protocol version numbers (`VN`), association modes (`MODE`), clock stratum
//! levels (`STRATUM`), polling intervals (`POLL`), clock precision (`PRECISION`), reference clock
//! identifiers (`REFID`), and 64-bit transmit timestamps (`TX_TIMESTAMP`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_i32, parse_str_val, parse_u32, parse_u64, tag, ParsedField, Stream};

/// Parses an NTP protocol declaration or time synchronization field.
pub(crate) fn parse_ntp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ntp).map(|(_, s)| ParsedField::Protocol(Protocol::Ntp, (s.start, s.len()))),
            (tag(Token::Li), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("LI", v, (s.start, s.end - s.start))),
            (tag(Token::Vn), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VN", v, (s.start, s.end - s.start))),
            (tag(Token::Mode), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("MODE", v, (s.start, s.end - s.start))),
            (tag(Token::Stratum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STRATUM", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Poll), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("POLL", v, (s.start, s.end - s.start))),
            (tag(Token::Precision), cut_err(parse_i32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PRECISION", v as u32, (s.start, s.end - s.start))
            }),
            (tag(Token::RefId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("REFID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TxTimestamp), cut_err(parse_u64)).map(|((_, s), v)| {
                ParsedField::L7U64Field("TX_TIMESTAMP", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
