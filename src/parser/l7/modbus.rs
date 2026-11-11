//! Modbus TCP Layer 7 industrial automation and SCADA register field parser.
//!
//! This module implements the `winnow` parser combinator for `modbus` Application Protocol (`MBAP`)
//! frames over TCP port 502 in FrameAssembly `.fasm` specifications. It recognizes the `modbus`
//! protocol keyword, MBAP transaction IDs (`txid`), protocol IDs (`protoid`), slave unit IDs
//! (`unitid`), explicit `func` names, shorthand function keywords (`readcoils`,
//! `readdiscreteinputs`, `readholdingregisters`, `readinputregisters`, `writesinglecoil`,
//! `writesingleregister`, `writemultipleregisters`), starting addresses (`addr`), register
//! counts (`count`), register values (`value`), and `isresponse` flags.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_any_str, parse_u32, tag, ParsedField, Stream};

/// Parses a Modbus protocol declaration or register field.
pub(crate) fn parse_modbus_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Modbus)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Modbus, (s.start, s.len()))),
            tag(Token::ReadCoils)
                .map(|(_, s)| ParsedField::L7StringField("FUNC", "READ_COILS", (s.start, s.len()))),
            tag(Token::ReadDiscreteInputs).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "READ_DISCRETE_INPUTS", (s.start, s.len()))
            }),
            tag(Token::ReadHoldingRegisters).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "READ_HOLDING_REGISTERS", (s.start, s.len()))
            }),
            tag(Token::ReadInputRegisters).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "READ_INPUT_REGISTERS", (s.start, s.len()))
            }),
            tag(Token::WriteSingleCoil).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "WRITE_SINGLE_COIL", (s.start, s.len()))
            }),
            tag(Token::WriteSingleRegister).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "WRITE_SINGLE_REGISTER", (s.start, s.len()))
            }),
            tag(Token::WriteMultipleRegisters).map(|(_, s)| {
                ParsedField::L7StringField("FUNC", "WRITE_MULTIPLE_REGISTERS", (s.start, s.len()))
            }),
        )),
        alt((
            (tag(Token::Txid), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TXID", v, (s.start, s.end - s.start))),
            (tag(Token::ProtoId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PROTO_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::UnitId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("UNITID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Func), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("FUNC", v, (s.start, s.end - s.start))),
            (tag(Token::Addr), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Count), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))),
            (tag(Token::Value), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
        )),
    ))
    .parse_next(input)
}
