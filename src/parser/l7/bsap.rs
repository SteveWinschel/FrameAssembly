//! Bristol Standard Asynchronous Protocol over IP (BSAP-IP) Layer 7 field parser.
//!
//! This module implements the `winnow` combinator parser for Emerson Bristol ControlWave `bsap`
//! messages over UDP or TCP port 1234 in FrameAssembly `.frasm` specifications. It recognizes the
//! `bsap` protocol keyword, function shorthands (`read`, `write`, `poll`) and explicit `func`
//! names or numeric codes, Local/Global RTU node addressing (`dst`, `src`), sequence numbers
//! (`seqnum`), register addresses (`addr`), item counts (`count`), 32-bit `value` fields, and
//! `isresponse` control flags.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Parses a BSAP-IP protocol declaration or RTU telemetry field.
pub(crate) fn parse_bsap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Bsap)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Bsap, (s.start, s.len()))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "read", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "write", (s.start, s.len()))),
            tag(Token::Poll)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "poll", (s.start, s.len()))),
            (tag(Token::Func), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
            (tag(Token::Dst), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("DST", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Src), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("SRC", v, (s.start, s.end - s.start))),
            (tag(Token::SeqNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("BSAP_SEQ", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Count), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("BSAP_COUNT", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
