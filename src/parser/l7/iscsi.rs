//! Internet Small Computer Systems Interface (iSCSI, RFC 7143) Layer 7 storage field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 7143 `iscsi` block storage
//! session and SCSI command PDUs in FrameAssembly `.frasm` specifications. It recognizes the
//! `iscsi` protocol keyword, PDU command shorthands (`login`, `logout`, `read`, `write`, `nop`,
//! `response`, `data`, `text`), explicit `cmd` and `opcode` overrides, IQN names (`initiator`,
//! `target`), `lun`, Initiator Task Tags (`itt`), sequence numbers (`cmdsn`, `statsn`), SCSI
//! `status`, BHS `flags`, and block/buffer `offset`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Parses an iSCSI protocol declaration or Basic Header Segment (BHS) field.
pub(crate) fn parse_iscsi_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Iscsi)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Iscsi, (s.start, s.len()))),
            tag(Token::Login)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "LOGIN", (s.start, s.len()))),
            tag(Token::Logout)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "LOGOUT", (s.start, s.len()))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "READ", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "WRITE", (s.start, s.len()))),
            tag(Token::Nop)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "NOP", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "RESPONSE", (s.start, s.len()))),
        )),
        alt((
            tag(Token::Data)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "DATA", (s.start, s.len()))),
            tag(Token::Text)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "TEXT", (s.start, s.len()))),
            (tag(Token::Cmd), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
            (tag(Token::Opcode), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("OPCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Initiator), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("INITIATOR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Target), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("ISCSI_TARGET", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Lun), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("LUN", v, (s.start, s.end - s.start))),
        )),
        alt((
            (tag(Token::Itt), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ITT", v, (s.start, s.end - s.start))),
            (tag(Token::Cmdsn), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CMDSN", v, (s.start, s.end - s.start))),
            (tag(Token::Statsn), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATSN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Status), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATUS", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Flags), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("FLAGS", v, (s.start, s.end - s.start))),
            (tag(Token::Offset), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OFFSET", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
