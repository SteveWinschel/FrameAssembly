//! Precision Time Protocol (IEEE 1588 PTPv2) Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for IEEE 1588 Precision Time Protocol
//! (`PTP`) packets in FrameAssembly `.fasm` specifications. It recognizes the `PTP` protocol
//! keyword, explicit message types (`MSG_TYPE`), shorthand message flags (`SYNC`, `DELAY_REQ`,
//! `FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE`), PTP domain numbers (`DOMAIN`), sequence identifiers
//! (`SEQ_ID`), and 8-byte grandmaster/port clock identities (`CLOCK_ID`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses a PTP protocol declaration or timestamp field.
pub(crate) fn parse_ptp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Ptp).map(|(_, s)| ParsedField::Protocol(Protocol::Ptp, (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            tag(Token::Sync).map(|(_, s)| ParsedField::L7Flag("SYNC", (s.start, s.len()))),
            tag(Token::DelayReq).map(|(_, s)| ParsedField::L7Flag("DELAY_REQ", (s.start, s.len()))),
            tag(Token::FollowUp).map(|(_, s)| ParsedField::L7Flag("FOLLOW_UP", (s.start, s.len()))),
        )),
        alt((
            tag(Token::DelayResp)
                .map(|(_, s)| ParsedField::L7Flag("DELAY_RESP", (s.start, s.len()))),
            tag(Token::Announce).map(|(_, s)| ParsedField::L7Flag("ANNOUNCE", (s.start, s.len()))),
            (tag(Token::Domain), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("DOMAIN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::SeqId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ClockId), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("CLOCK_ID", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
