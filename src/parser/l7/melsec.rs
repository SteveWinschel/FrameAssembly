//! Mitsubishi MELSEC MC Protocol / SLMP Binary 3E Layer 7 field parser.
//!
//! This module implements the `winnow` parser combinator for Mitsubishi `melsec` Binary 3E
//! frames over TCP and UDP port 5000 in FrameAssembly `.frasm` specifications. It recognizes the
//! `melsec` protocol keyword, command selectors (`read`, `write`, `cmd`), response flags and
//! completion codes (`response`, `isresponse`, `endcode`, `errcode`), subcommands (`subcmd`),
//! routing headers (`network`, `pc`, `io`, `station`, `timer`), device type codes (`device` as
//! `d`, `m`, `x`, `y`, `w`, `r`, `b`, `l`, `zr`, `sd`, `sm`, or `u8`), 24-bit head addresses
//! (`addr`), point counts (`count`), and register values (`value`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Resolves a MELSEC device mnemonic (`D`, `M`, `X`, `Y`, `W`, `R`, `B`, `L`, `ZR`, `SD`, `SM`)
/// or numeric `u8` string into an 8-bit binary device code.
fn resolve_melsec_device_code(raw: &str) -> Option<u32> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "D" => Some(0xA8),
        "M" => Some(0x90),
        "X" => Some(0x9C),
        "Y" => Some(0x9D),
        "W" => Some(0xB4),
        "R" => Some(0xAF),
        "B" => Some(0xA0),
        "L" => Some(0x92),
        "ZR" => Some(0xB0),
        "SD" => Some(0xA9),
        "SM" => Some(0x91),
        _ => {
            if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok().map(u32::from)
            } else {
                raw.parse::<u8>().ok().map(u32::from)
            }
        }
    }
}

/// Parses a MELSEC device identifier as either a numeric `u32` or a mnemonic string.
fn parse_melsec_device_val<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    alt((
        parse_u32,
        parse_any_str.verify_map(resolve_melsec_device_code),
    ))
    .parse_next(input)
}

/// Parses a MELSEC MC 3E / SLMP protocol declaration or register access field.
pub(crate) fn parse_melsec_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Melsec)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Melsec, (s.start, s.len()))),
            tag(Token::Read)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "READ", (s.start, s.len()))),
            tag(Token::Write)
                .map(|(_, s)| ParsedField::L7StringField("CMD", "WRITE", (s.start, s.len()))),
            tag(Token::Response)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            tag(Token::IsResponse)
                .map(|(_, s)| ParsedField::L7Flag("IS_RESPONSE", (s.start, s.len()))),
            (tag(Token::Cmd), cut_err(parse_any_str))
                .map(|((_, s), v)| ParsedField::L7StringField("CMD", v, (s.start, s.end - s.start))),
            (tag(Token::Subcmd), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_SUBCMD", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Network), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_NETWORK", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Pc), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_PC", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Io), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_IO", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Station), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_STATION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Timer), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_TIMER", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Device), cut_err(parse_melsec_device_val)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_DEVICE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Addr), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_ADDR", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Count), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            (tag(Token::Endcode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_ENDCODE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MELSEC_ENDCODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
