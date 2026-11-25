//! Building Automation and Control Networks (BACnet/IP) Layer 7 protocol field parser.
//!
//! This module implements the `winnow` parser combinator for ASHRAE 135 `bacnet` BVLL/NPDU/APDU
//! frames over UDP port 47808 in FrameAssembly `.frasm` specifications. It recognizes the `bacnet`
//! protocol keyword, unconfirmed and confirmed service flags (`whois`, `iam`, `readproperty`,
//! `writeproperty`, `complexack`), APDU invoke IDs (`invokeid`), object types (`objecttype`),
//! object instances (`objectinstance`), property identifiers (`propertyid`), unsigned property
//! values (`value`), and IEEE 754 single-precision float values (`real`).

use core::str::FromStr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_raw_string_lit, parse_u32, tag, ParsedField, Stream};

/// Parses a finite single-precision floating-point value for BACnet `real`, supporting
/// positive/negative integers, decimal floats (including split `-12` + `.5` tokens), and quoted strings.
fn parse_bacnet_real_bits<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<(u32, usize)> {
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

/// Parses a BACnet protocol declaration or object property field.
pub(crate) fn parse_bacnet_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Bacnet)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Bacnet, (s.start, s.len()))),
            tag(Token::Whois).map(|(_, s)| ParsedField::L7Flag("WHO_IS", (s.start, s.len()))),
            tag(Token::IAm).map(|(_, s)| ParsedField::L7Flag("I_AM", (s.start, s.len()))),
            tag(Token::ReadProperty)
                .map(|(_, s)| ParsedField::L7Flag("READ_PROPERTY", (s.start, s.len()))),
            tag(Token::WriteProperty)
                .map(|(_, s)| ParsedField::L7Flag("WRITE_PROPERTY", (s.start, s.len()))),
            tag(Token::ComplexAck)
                .map(|(_, s)| ParsedField::L7Flag("COMPLEX_ACK", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::InvokeId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("INVOKE_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ObjectType), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OBJECT_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ObjectInstance), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("OBJECT_INSTANCE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::PropertyId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PROPERTY_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Value), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("VALUE", v, (s.start, s.end - s.start))),
            (tag(Token::Real), cut_err(parse_bacnet_real_bits)).map(|((_, s), (bits, end))| {
                ParsedField::L7U32Field("REAL_VALUE", bits, (s.start, end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
