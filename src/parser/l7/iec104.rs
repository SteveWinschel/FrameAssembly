//! IEC 60870-5-104 (Telecontrol APCI and ASDU) Layer 7 grid protocol field parser.
//!
//! This module implements the `winnow` parser combinator for IEC 60870-5-104 (`iec104`) frames
//! over TCP port 2404 in FrameAssembly `.frasm` specifications. It recognizes the `iec104` protocol
//! keyword, APCI U-frame and S-frame shorthands (`startdt`, `stopdt`, `testfr`, `sframe`),
//! explicit `msgtype` selectors, `confirm` flags, 15-bit APCI sequence numbers (`txseq`, `rxseq`),
//! ASDU type identifiers (`typeid`), cause-of-transmission codes (`cot` as integer or mnemonic),
//! common addresses (`ca`), 24-bit information object addresses (`ioa`), integer values (`value`),
//! and IEEE 754 single-precision floating-point values (`real`).

use core::str::FromStr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_raw_string_lit, parse_u32, tag,
};

/// Parses an IEC 60870-5-104 Cause of Transmission (`cot`) from a `0..=63` integer or mnemonic string.
fn parse_iec104_cot<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    if let Ok(v) = parse_u32(input) {
        if v <= 63 {
            return Ok(v);
        }
        return Err(ErrMode::Backtrack(ContextError::new()));
    }
    let saved = *input;
    let raw = parse_any_str(input)?;
    let norm = raw.trim().to_ascii_lowercase().replace(['_', '-'], "");
    let code = match norm.as_str() {
        "per" | "periodic" | "cyc" => 1,
        "back" | "background" => 2,
        "spont" | "spontaneous" => 3,
        "init" => 4,
        "req" | "request" => 5,
        "act" | "activation" => 6,
        "actcon" | "activationconfirm" => 7,
        "deact" | "deactivation" => 8,
        "deactcon" | "deactivationconfirm" => 9,
        "actterm" | "activationtermination" => 10,
        "interrog" | "interro" | "inrogen" => 20,
        _ => {
            *input = saved;
            return Err(ErrMode::Backtrack(ContextError::new()));
        }
    };
    Ok(code)
}

/// Parses a finite single-precision floating-point value for IEC 104 `M_ME_NC_1` (`real`),
/// supporting positive/negative integers, decimal floats, and quoted numeric strings.
fn parse_iec104_real_bits<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<(u32, usize)> {
    let bt = || ErrMode::Backtrack(ContextError::new());
    let Some((tok, span, _)) = input.first().cloned() else {
        return Err(bt());
    };
    match tok {
        Token::StringLit(_) => {
            let saved = *input;
            let raw = parse_raw_string_lit(input).map_err(|_| bt())?;
            let val = f32::from_str(raw.trim()).ok().filter(|v| v.is_finite());
            match val {
                Some(f) => Ok((f.to_bits(), span.end)),
                None => {
                    *input = saved;
                    Err(bt())
                }
            }
        }
        Token::Number(n) => {
            if let Some((Token::OidStr(frac), frac_sp, _)) = input.get(1)
                && span.end == frac_sp.start
                && frac.starts_with('.')
                && frac.len() > 1
                && frac[1..].bytes().all(|b| b.is_ascii_digit())
            {
                let combined = alloc::format!("{n}{frac}");
                if let Ok(f) = f32::from_str(&combined)
                    && f.is_finite()
                {
                    let end = frac_sp.end;
                    *input = &input[2..];
                    return Ok((f.to_bits(), end));
                }
            }
            let f = f32::from_str(n).ok().filter(|v| v.is_finite()).ok_or_else(bt)?;
            *input = &input[1..];
            Ok((f.to_bits(), span.end))
        }
        Token::OidStr(s) => {
            let f = f32::from_str(s).ok().filter(|v| v.is_finite()).ok_or_else(bt)?;
            *input = &input[1..];
            Ok((f.to_bits(), span.end))
        }
        _ => Err(bt()),
    }
}

/// Parses an IEC 60870-5-104 protocol declaration or APCI/ASDU modifier field.
pub(crate) fn parse_iec104_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Iec104)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Iec104, (s.start, s.len()))),
            tag(Token::StartDt).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "startdtact", (s.start, s.len()))
            }),
            tag(Token::StopDt).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "stopdtact", (s.start, s.len()))
            }),
            tag(Token::TestFr).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "testfract", (s.start, s.len()))
            }),
            tag(Token::Sframe)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "sframe", (s.start, s.len()))),
            tag(Token::Confirm).map(|(_, s)| ParsedField::L7Flag("CONFIRM", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::TxSeq), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TX_SEQ", v, (s.start, s.end - s.start))
            }),
            (tag(Token::RxSeq), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("RX_SEQ", v, (s.start, s.end - s.start))
            }),
            (tag(Token::TypeId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("TYPE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Cot), cut_err(parse_iec104_cot))
                .map(|((_, s), v)| ParsedField::L7U32Field("COT", v, (s.start, s.end - s.start))),
            (tag(Token::Ca), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("CA", v, (s.start, s.end - s.start))),
            (tag(Token::Ioa), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("IOA", v, (s.start, s.end - s.start))),
            (tag(Token::Value), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            (tag(Token::Real), cut_err(parse_iec104_real_bits)).map(|((_, s), (bits, end))| {
                ParsedField::L7U32Field("REAL_VALUE", bits, (s.start, end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
