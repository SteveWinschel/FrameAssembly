//! Distributed Network Protocol 3 (IEEE 1815 DNP3) Layer 7 SCADA protocol field parser.
//!
//! This module implements the `winnow` parser combinator for IEEE 1815 `DNP3` data link,
//! transport, and application layer frames in FrameAssembly `.fasm` specifications. It recognizes
//! the `DNP3` protocol keyword, explicit `FUNC` strings, shorthand application function keywords
//! (`CONFIRM`, `READ`, `WRITE`, `SELECT`, `OPERATE`, `DIRECT_OPERATE`, `UNSOLICITED_RESPONSE`),
//! master/outstation addresses (`SRC`, `DST`), object `GROUP` and `VARIATION` numbers, and data
//! link `CRC` overrides.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Parses a DNP3 protocol declaration or supervisory control field.
pub(crate) fn parse_dnp3_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Dnp3)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Dnp3, (s.start, s.len()))),
            tag(Token::Confirm)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "CONFIRM", (s.start, s.len()))),
            tag(Token::Ident("READ"))
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "READ", (s.start, s.len()))),
            tag(Token::Ident("WRITE"))
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "WRITE", (s.start, s.len()))),
            tag(Token::Select)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "SELECT", (s.start, s.len()))),
            tag(Token::Operate)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "OPERATE", (s.start, s.len()))),
            tag(Token::DirectOperate).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "DIRECT_OPERATE", (s.start, s.len()))
            }),
            tag(Token::UnsolicitedResponse).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "UNSOLICITED_RESPONSE", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Func), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
            (tag(Token::Src), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("SRC", v, (s.start, s.end - s.start))),
            (tag(Token::Dst), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("DST", v, (s.start, s.end - s.start))),
            (tag(Token::Group), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("GROUP", v, (s.start, s.end - s.start))),
            (tag(Token::Variation), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("VARIATION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Crc), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CRC", v, (s.start, s.end - s.start))),
        )),
    ))
    .parse_next(input)
}
