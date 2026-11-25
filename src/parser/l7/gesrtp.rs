//! GE Fanuc Service Request Transport Protocol (GE-SRTP) Layer 7 field parser.
//!
//! This module implements the `winnow` combinator parser for GE Series 90 and PACSystems `gesrtp`
//! frames over TCP port 18245 in FrameAssembly `.frasm` specifications. It recognizes the `gesrtp`
//! protocol keyword, packet type shorthands (`init`, `initack`, `request`, `response`) and explicit
//! `type` strings, 16-bit sequence numbers (`seqnum`), service codes (`read`, `write`, `func`),
//! PLC memory segment selectors (`area` via numeric ID or `%R`/`%AI`/`%AQ`/`%I`/`%Q`/`%M`/`%T`/`%G`
//! mnemonics), addresses (`addr`), counts (`count`), inline values (`value`), and response `status` codes.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses a GE-SRTP memory segment mnemonic (`r`, `ai`, `aq`, `i`, `q`, `m`, `t`, `g`, or `u8`) into a segment code.
fn parse_gesrtp_area<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    parse_any_str
        .verify_map(|raw| {
            let trimmed = raw.trim();
            if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
                && let Ok(v) = u8::from_str_radix(hex, 16)
            {
                return Some(u32::from(v));
            }
            if let Ok(v) = trimmed.parse::<u8>() {
                return Some(u32::from(v));
            }
            match trimmed
                .to_ascii_uppercase()
                .replace(['%', '_', '-'], "")
                .as_str()
            {
                "R" => Some(0x08),
                "AI" => Some(0x10),
                "AQ" => Some(0x12),
                "T" => Some(0x14),
                "I" => Some(0x16),
                "Q" => Some(0x18),
                "G" => Some(0x1E),
                "M" => Some(0x4C),
                _ => None,
            }
        })
        .parse_next(input)
}

/// Parses a GE-SRTP protocol declaration or PLC service request/response field.
pub(crate) fn parse_gesrtp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Gesrtp)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Gesrtp, (s.start, s.len()))),
            tag(Token::Init)
                .map(|(_, s)| ParsedField::L7StringField("GESRTP_PTYPE", "init", (s.start, s.len()))),
            tag(Token::InitAck).map(|(_, s)| {
                ParsedField::L7StringField("GESRTP_PTYPE", "initack", (s.start, s.len()))
            }),
            tag(Token::Request).map(|(_, s)| {
                ParsedField::L7StringField("GESRTP_PTYPE", "request", (s.start, s.len()))
            }),
            tag(Token::Response).map(|(_, s)| {
                ParsedField::L7StringField("GESRTP_PTYPE", "response", (s.start, s.len()))
            }),
            (tag(Token::Type), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("GESRTP_PTYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "readsysmem", (s.start, s.len()))),
            tag(Token::Write).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "writesysmem", (s.start, s.len()))
            }),
            (tag(Token::Func), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("SEQ_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Area), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("AREA", v, (s.start, s.end - s.start))),
            (tag(Token::Area), cut_err(parse_gesrtp_area))
                .map(|((_, s), v)| ParsedField::L7U32Field("AREA", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Addr), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Count), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            (tag(Token::Status), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
