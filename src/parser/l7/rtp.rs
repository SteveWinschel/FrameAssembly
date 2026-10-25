//! Real-time Transport Protocol (RTP) Layer 7 media streaming header field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 3550 `RTP` real-time audio and
//! video transport packets in FrameAssembly `.fasm` specifications. It recognizes the `RTP`
//! protocol keyword, payload type codes (`PT`), media sampling timestamps (`TIMESTAMP`),
//! synchronization source identifiers (`SSRC`), marker bits (`MARKER`), and sequence numbers
//! (`SEQ`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_u32, tag, ParsedField, Stream};

/// Parses an RTP protocol declaration or media packet header field.
pub(crate) fn parse_rtp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        tag(Token::Rtp).map(|(_, s)| ParsedField::Protocol(Protocol::Rtp, (s.start, s.len()))),
        (tag(Token::Pt), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("PT", v, (s.start, s.end - s.start))),
        (tag(Token::Timestamp), cut_err(parse_u32)).map(|((_, s), v)| {
            ParsedField::L7U32Field("TIMESTAMP", v, (s.start, s.end - s.start))
        }),
        (tag(Token::Ssrc), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("SSRC", v, (s.start, s.end - s.start))),
        (tag(Token::Marker), cut_err(parse_u32))
            .map(|((_, s), v)| ParsedField::L7U32Field("MARKER", v, (s.start, s.end - s.start))),
    ))
    .parse_next(input)
}
