//! PROFINET IO Real-Time and Context Manager (`profinet`, IEC 61158-6-10) parser combinator.
//!
//! This module implements the `winnow` parser combinator for PROFINET IO frames across native
//! Layer 2 Ethernet (`0x8892`) and UDP Context Manager (`34964`). It recognizes the `profinet`
//! protocol keyword, 16-bit Real-Time `frameid`, cyclic `cycle` counter, `datastatus`, and
//! `transferstatus` bytes, explicit `service` names alongside bare shorthand service keywords
//! (`read`, `write`, `get`, `set`, `release`, `connect`), DCP transaction `xid`, and `request` /
//! `response` direction flags.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses a PROFINET protocol declaration or PN-RT / PN-DCP / PNIO-CM field.
pub(crate) fn parse_profinet_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Profinet)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Profinet, (s.start, s.len()))),
            (tag(Token::FrameId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PN_FRAME_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cycle), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PN_CYCLE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::DataStatus), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PN_DATA_STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TransferStatus), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PN_TRANSFER_STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Xid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("PN_XID", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Service), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("PN_SERVICE", v, (s.start, s.end - s.start))
            }),
            tag(Token::Request)
                .map(|(_, s)| ParsedField::L7Flag("PN_REQUEST", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("PN_RESPONSE", (s.start, s.len()))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("PN_SERVICE", "read", (s.start, s.len()))),
            tag(Token::Write).map(|(_, s)| {
                ParsedField::L7StringField("PN_SERVICE", "write", (s.start, s.len()))
            }),
            tag(Token::Get)
                .map(|(_, s)| ParsedField::L7StringField("PN_SERVICE", "get", (s.start, s.len()))),
            tag(Token::Set)
                .map(|(_, s)| ParsedField::L7StringField("PN_SERVICE", "set", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Release).map(|(_, s)| {
                ParsedField::L7StringField("PN_SERVICE", "release", (s.start, s.len()))
            }),
            tag(Token::Connect).map(|(_, s)| {
                ParsedField::L7StringField("PN_SERVICE", "connect", (s.start, s.len()))
            }),
        )),
    ))
    .parse_next(input)
}
