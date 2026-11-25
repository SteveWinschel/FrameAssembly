//! Omron Factory Interface Network Service (FINS) Layer 7 PLC protocol field parser.
//!
//! This module implements the `winnow` parser combinator for Omron `fins` frames over UDP and
//! TCP port 9600 in FrameAssembly `.frasm` specifications. It recognizes the `fins` protocol
//! keyword, command shorthands (`read`, `write`, `cmd`), response selectors (`response`,
//! `isresponse`, `errcode`), FINS routing fields (`icf`, `dna`, `da1`, `da2`, `sna`, `sa1`, `sa2`,
//! `sid`), PLC memory areas (`area` as named codes `dm`, `cio`, `wr`, `hr`, `ar`, `dmbit`,
//! `ciobit`, `wrbit`, `hrbit`, `arbit` or `u8`), starting addresses (`addr`), item counts
//! (`count`), and register values (`value`).

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{ParsedField, Stream, parse_any_str, parse_u32, tag};

/// Resolves a named Omron FINS memory area mnemonic into its 8-bit area code.
fn resolve_fins_area_name(raw: &str) -> Option<u32> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "DM" => Some(0x82),
        "CIO" => Some(0xB0),
        "WR" => Some(0xB1),
        "HR" => Some(0xB2),
        "AR" => Some(0xB3),
        "DMBIT" => Some(0x02),
        "CIOBIT" => Some(0x30),
        "WRBIT" => Some(0x31),
        "HRBIT" => Some(0x32),
        "ARBIT" => Some(0x33),
        _ => {
            if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok().map(u32::from)
            } else {
                raw.parse::<u8>().ok().map(u32::from)
            }
        }
    }
}

/// Parses an Omron FINS memory area argument as either a numeric `u32` or a canonical mnemonic.
fn parse_fins_area_val<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    alt((
        parse_u32,
        parse_any_str.verify_map(resolve_fins_area_name),
    ))
    .parse_next(input)
}

/// Parses an Omron FINS protocol declaration or PLC memory access field.
pub(crate) fn parse_fins_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Fins)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Fins, (s.start, s.len()))),
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
        )),
        alt((
            (tag(Token::Icf), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_ICF", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Dna), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_DNA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Da1), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_DA1", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Da2), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_DA2", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Sna), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_SNA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Sa1), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_SA1", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Sa2), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_SA2", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Sid), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_SID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Area), cut_err(parse_fins_area_val)).map(|((_, s), v)| {
                ParsedField::L7U32Field("FINS_AREA", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Addr), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("ADDR", v, (s.start, s.end - s.start))),
            (tag(Token::Count), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("COUNT", v, (s.start, s.end - s.start))),
            (tag(Token::Value), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            (tag(Token::ErrCode), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("ERRCODE", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
