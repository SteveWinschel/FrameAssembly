//! Siemens S7 Communication (S7comm over ISO-on-TCP) Layer 7 PLC protocol field parser.
//!
//! This module implements the `winnow` parser combinator for Siemens `s7comm` TPKT/COTP/S7 frames
//! over TCP port 102 in FrameAssembly `.frasm` specifications. It recognizes the `s7comm` protocol
//! keyword, Remote Operating Service Control types (`rosctr`, e.g., `"JOB"`, `"ACK_DATA"`), PDU
//! reference IDs (`pduref`), explicit `func` names and shorthands (`setupcomm`, `readvar`,
//! `writevar`, `plccontrol`, `szl`), PLC memory areas (`area` as numeric codes or area names
//! `PE`/`I`, `PA`/`Q`, `MK`/`M`, `DB`, `CT`/`C`, `TM`/`T`), data block numbers (`dbnum`),
//! byte/bit offsets (`offset`), and item counts (`count`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Validates an S7comm memory area code or mnemonic (`PE`/`I`, `PA`/`Q`, `MK`/`M`, `DB`, `CT`/`C`, `TM`/`T`, or `u8`).
fn is_valid_s7_area(val: &str) -> bool {
    val.eq_ignore_ascii_case("PE")
        || val.eq_ignore_ascii_case("I")
        || val.eq_ignore_ascii_case("PA")
        || val.eq_ignore_ascii_case("Q")
        || val.eq_ignore_ascii_case("MK")
        || val.eq_ignore_ascii_case("M")
        || val.eq_ignore_ascii_case("DB")
        || val.eq_ignore_ascii_case("CT")
        || val.eq_ignore_ascii_case("C")
        || val.eq_ignore_ascii_case("TM")
        || val.eq_ignore_ascii_case("T")
        || val
            .strip_prefix("0x")
            .or_else(|| val.strip_prefix("0X"))
            .map_or_else(
                || val.parse::<u8>().is_ok(),
                |hex| u8::from_str_radix(hex, 16).is_ok(),
            )
}

/// Parses an S7comm protocol declaration or PLC memory field.
pub(crate) fn parse_s7comm_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::S7comm)
                .map(|(_, s)| ParsedField::Protocol(Protocol::S7comm, (s.start, s.len()))),
            tag(Token::SetupComm)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "SETUP_COMM", (s.start, s.len()))),
            tag(Token::ReadVar)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "READ_VAR", (s.start, s.len()))),
            tag(Token::WriteVar)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "WRITE_VAR", (s.start, s.len()))),
            tag(Token::PlcControl).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "PLC_CONTROL", (s.start, s.len()))
            }),
            tag(Token::Szl)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "SZL", (s.start, s.len()))),
            (tag(Token::Rosctr), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("ROSCTR", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::PduRef), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PDU_REF", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Func), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
            (tag(Token::Area), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("AREA", v, (s.start, s.end - s.start))),
            (tag(Token::Area), cut_err(parse_any_str.verify(is_valid_s7_area)))
                .map(|((_, s), v)| ParsedField::L7StringField("AREA", v, (s.start, s.end - s.start))),
            (tag(Token::DbNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("DB_NUM", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Offset), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OFFSET", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Count), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
