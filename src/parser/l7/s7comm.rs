//! Siemens S7 Communication (S7comm over ISO-on-TCP) Layer 7 PLC protocol field parser.
//!
//! This module implements the `winnow` parser combinator for Siemens `S7COMM` TPKT/COTP/S7 frames
//! over TCP port 102 in FrameAssembly `.fasm` specifications. It recognizes the `S7COMM` protocol
//! keyword, Remote Operating Service Control types (`ROSCTR`, e.g., `"JOB"`, `"ACK_DATA"`), PDU
//! reference IDs (`PDU_REF`), explicit `FUNC` names and shorthands (`SETUP_COMM`, `READ_VAR`,
//! `WRITE_VAR`, `PLC_CONTROL`), PLC memory areas (`AREA` as numeric codes or area names such as
//! `"DB"`), data block numbers (`DB_NUM`), byte/bit offsets (`OFFSET`), and item counts (`COUNT`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

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
            (tag(Token::Area), cut_err(parse_any_str))
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
