//! Real-time Transport Control Protocol (RTCP, RFC 3550) Layer 7 media feedback field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 3550 `rtcp` real-time media
//! quality and session control packets in FrameAssembly `.frasm` specifications. It recognizes
//! the `rtcp` protocol keyword, packet type shorthands (`sr`, `rr`, `sdes`, `bye`, `app`) and
//! numeric `pt` codes (`200..=204`), synchronization source IDs (`ssrc`), Sender Report statistics
//! (`timestamp`, `packets`, `octets`), Receiver Report loss/jitter counters (`fraction`, `lost`,
//! `jitter`, `seqnum`), SDES/APP names (`cname`), and BYE `reason` strings.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses bare `app` for RTCP `PT=204` while backtracking when followed by a Syslog `app "<str>"`.
fn parse_rtcp_app_flag<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    if input
        .get(1)
        .is_some_and(|(t, _, _)| matches!(t, Token::StringLit(_)))
    {
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let (_, s) = tag(Token::App).parse_next(input)?;
    Ok(ParsedField::L7U32Field("PT", 204, (s.start, s.len())))
}

/// Parses an RTCP protocol declaration or media control feedback field.
pub(crate) fn parse_rtcp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Rtcp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Rtcp, (s.start, s.len()))),
            tag(Token::Sr).map(|(_, s)| ParsedField::L7U32Field("PT", 200, (s.start, s.len()))),
            tag(Token::Rr).map(|(_, s)| ParsedField::L7U32Field("PT", 201, (s.start, s.len()))),
            tag(Token::Sdes).map(|(_, s)| ParsedField::L7U32Field("PT", 202, (s.start, s.len()))),
            tag(Token::Bye).map(|(_, s)| ParsedField::L7U32Field("PT", 203, (s.start, s.len()))),
            parse_rtcp_app_flag,
            (tag(Token::Pt), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("PT", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Ssrc), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("SSRC", v, (s.start, s.end - s.start))),
            (tag(Token::Timestamp), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TIMESTAMP", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Packets), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PACKETS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Octets), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OCTETS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Fraction), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FRACTION", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Lost), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("LOST", v, (s.start, s.end - s.start))),
            (tag(Token::Jitter), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("JITTER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cname), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("CNAME", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Reason), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("REASON", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
