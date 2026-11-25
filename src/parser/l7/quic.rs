//! QUIC (RFC 9000) Layer 7 encrypted transport protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 9000 `quic` long-header and
//! short-header packets in FrameAssembly `.frasm` specifications. It recognizes the `quic` protocol
//! keyword, packet type flags (`initial`, `zerortt`, `handshake`, `retry`, `short`), protocol
//! versions (`version`), destination and source connection IDs (`dcid`, `scid` as numeric or
//! 0..=20-byte hex string literals), retry/initial tokens (`token`), and packet numbers (`pktnum`).

use alloc::vec::Vec;
use core::str::FromStr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{parse_ident, parse_raw_string_lit, parse_str_val, parse_u32, tag, ParsedField, Stream};

/// Decodes even-length QUIC hex characters (`0..=40` hex digits = `0..=20` bytes).
fn decode_quic_hex(raw: &str) -> Option<Vec<u8>> {
    let clean = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if !clean.is_ascii()
        || clean.len() > 40
        || !clean.len().is_multiple_of(2)
        || !clean.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for pair in clean.as_bytes().as_chunks::<2>().0 {
        let pair_str = core::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair_str, 16).ok()?);
    }
    Some(bytes)
}

/// Parses a QUIC Connection ID (`dcid` / `scid`) validating `<= 20` bytes when supplied as hex.
fn parse_quic_cid<'i, 'a>(
    input: &mut Stream<'i, 'a>,
    u64_key: &'static str,
    bytes_key: &'static str,
    kw_start: usize,
) -> PResult<ParsedField<'a>> {
    let bt = || ErrMode::Backtrack(ContextError::new());
    let Some((tok, val_span, _)) = input.first().cloned() else {
        return Err(bt());
    };
    let field_span = (kw_start, val_span.end - kw_start);
    match tok {
        Token::Number(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bt());
                }
                if hex.len() <= 16 {
                    let v = u64::from_str_radix(hex, 16).map_err(|_| bt())?;
                    *input = &input[1..];
                    return Ok(ParsedField::L7U64Field(u64_key, v, field_span));
                }
                let bytes = decode_quic_hex(hex).ok_or_else(bt)?;
                *input = &input[1..];
                Ok(ParsedField::L7BytesField(bytes_key, bytes, field_span))
            } else {
                let v = u64::from_str(s).map_err(|_| bt())?;
                *input = &input[1..];
                Ok(ParsedField::L7U64Field(u64_key, v, field_span))
            }
        }
        Token::StringLit(_) => {
            let saved = *input;
            let raw = parse_raw_string_lit(input).map_err(|_| bt())?;
            let bytes = decode_quic_hex(raw).ok_or_else(|| {
                *input = saved;
                bt()
            })?;
            Ok(ParsedField::L7BytesField(bytes_key, bytes, field_span))
        }
        _ => {
            let saved = *input;
            let s = parse_ident(input)?;
            let bytes = decode_quic_hex(s).ok_or_else(|| {
                *input = saved;
                bt()
            })?;
            Ok(ParsedField::L7BytesField(bytes_key, bytes, field_span))
        }
    }
}

/// Parses a QUIC protocol declaration or packet field.
pub(crate) fn parse_quic_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Quic)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Quic, (s.start, s.len()))),
            tag(Token::Initial).map(|(_, s)| ParsedField::L7Flag("INITIAL", (s.start, s.len()))),
            tag(Token::ZeroRtt).map(|(_, s)| ParsedField::L7Flag("ZERO_RTT", (s.start, s.len()))),
            tag(Token::Handshake)
                .map(|(_, s)| ParsedField::L7Flag("HANDSHAKE", (s.start, s.len()))),
            tag(Token::Retry).map(|(_, s)| ParsedField::L7Flag("RETRY", (s.start, s.len()))),
            tag(Token::Short).map(|(_, s)| ParsedField::L7Flag("SHORT", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Version), parse_u32).map(|((_, s), v)| {
                ParsedField::L7U32Field("VERSION", v, (s.start, s.end - s.start))
            }),
            move |input: &mut Stream<'i, 'a>| {
                let (_, s) = tag(Token::Dcid).parse_next(input)?;
                let kw_start = s.start;
                cut_err(move |i: &mut Stream<'i, 'a>| {
                    parse_quic_cid(i, "DCID", "QUIC_DCID", kw_start)
                })
                .parse_next(input)
            },
            move |input: &mut Stream<'i, 'a>| {
                let (_, s) = tag(Token::Scid).parse_next(input)?;
                let kw_start = s.start;
                cut_err(move |i: &mut Stream<'i, 'a>| {
                    parse_quic_cid(i, "SCID", "QUIC_SCID", kw_start)
                })
                .parse_next(input)
            },
            (tag(Token::Token), parse_str_val).map(|((_, s), v)| {
                ParsedField::L7StringField("TOKEN", v, (s.start, s.end - s.start))
            }),
            (tag(Token::PktNum), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("PKT_NUM", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
