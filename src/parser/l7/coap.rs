//! Constrained Application Protocol (CoAP) Layer 7 IoT REST protocol field parser.
//!
//! This module implements the `winnow` parser combinator for RFC 7252 `coap` constrained RESTful
//! exchanges in FrameAssembly `.frasm` specifications. It recognizes the `coap` protocol keyword,
//! message types (`con`, `non`, `ack`, `rst`, or `msgtype`), method/response codes (`code` or
//! shorthands `get`, `post`, `put`, `delete`, `created`, `changed`, `notfound`), 16-bit message
//! IDs (`msgid`), ASCII/hex client tokens (`token`, up to 8 bytes), `uripath` options, and
//! `contentformat` IDs.

use alloc::vec::Vec;
use core::str::FromStr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::ident::unescape_bytes;
use crate::parser::{
    parse_any_str, parse_ident, parse_raw_string_lit, parse_str_val, parse_u32, tag, ParsedField,
    Stream,
};

/// Decodes a non-empty hexadecimal string (`<= 16` chars / `<= 8` bytes) into CoAP token octets.
fn decode_coap_hex_digits(hex: &str, allow_odd: bool) -> Option<Vec<u8>> {
    if !hex.is_ascii() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if !allow_odd && !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len().div_ceil(2));
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    if bytes.len() % 2 == 1 {
        let hi = core::str::from_utf8(&bytes[..1]).ok()?;
        out.push(u8::from_str_radix(hi, 16).ok()?);
        i = 1;
    }
    while i < bytes.len() {
        let pair = core::str::from_utf8(&bytes[i..i + 2]).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
        i += 2;
    }
    Some(out)
}

/// Parses an RFC 7252 CoAP token (`0..=8` bytes) from a numeric/hex integer, quoted string, or identifier.
fn parse_coap_token<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<u8>> {
    let bt = || ErrMode::Backtrack(ContextError::new());
    let Some((tok, _, _)) = input.first() else {
        return Err(bt());
    };
    match tok {
        Token::Number(s) => {
            let s = *s;
            if s.starts_with('-') {
                return Err(bt());
            }
            let bytes = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                if hex.is_empty() {
                    return Err(bt());
                }
                decode_coap_hex_digits(hex, true).ok_or_else(bt)?
            } else {
                let v = u64::from_str(s).map_err(|_| bt())?;
                if v == 0 {
                    alloc::vec![0]
                } else {
                    let be = v.to_be_bytes();
                    let lead = be.iter().take_while(|&&b| b == 0).count();
                    be[lead..].to_vec()
                }
            };
            *input = &input[1..];
            Ok(bytes)
        }
        Token::StringLit(_) => {
            let saved = *input;
            let raw = parse_raw_string_lit(input).map_err(|_| bt())?;
            let bytes = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"))
            {
                decode_coap_hex_digits(hex, false).ok_or_else(|| {
                    *input = saved;
                    bt()
                })?
            } else {
                let b = unescape_bytes(raw).map_err(|_| {
                    *input = saved;
                    bt()
                })?;
                if b.len() > 8 {
                    *input = saved;
                    return Err(bt());
                }
                b
            };
            Ok(bytes)
        }
        _ => {
            let saved = *input;
            let s = parse_ident(input)?;
            if s.len() > 8 {
                *input = saved;
                return Err(bt());
            }
            Ok(s.as_bytes().to_vec())
        }
    }
}

/// Parses a CoAP protocol declaration or RESTful option field.
pub(crate) fn parse_coap_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Coap)
                .map(|(_, s)| ParsedField::Protocol(Protocol::Coap, (s.start, s.len()))),
            tag(Token::Con)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "CON", (s.start, s.len()))),
            tag(Token::Non)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "NON", (s.start, s.len()))),
            tag(Token::Ack)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ACK", (s.start, s.len()))),
            tag(Token::Rst)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "RST", (s.start, s.len()))),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            tag(Token::Get)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "GET", (s.start, s.len()))),
            tag(Token::Post)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "POST", (s.start, s.len()))),
            tag(Token::Put)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "PUT", (s.start, s.len()))),
            tag(Token::Delete)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "DELETE", (s.start, s.len()))),
            tag(Token::Created)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "CREATED", (s.start, s.len()))),
            tag(Token::Changed)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "CHANGED", (s.start, s.len()))),
            tag(Token::NotFound)
                .map(|(_, s)| ParsedField::L7StringField("CODE", "NOT_FOUND", (s.start, s.len()))),
        )),
        alt((
            (tag(Token::Code), parse_any_str)
                .map(|((_, s), v)| ParsedField::L7StringField("CODE", v, (s.start, s.end - s.start))),
            (tag(Token::MsgId), parse_u32)
                .map(|((_, s), v)| ParsedField::L7U32Field("MSGID", v, (s.start, s.end - s.start))),
            (tag(Token::Token), parse_coap_token).map(|((_, s), bytes)| {
                ParsedField::L7BytesField("COAP_TOKEN", bytes, (s.start, s.end - s.start))
            }),
            (tag(Token::UriPath), cut_err(parse_str_val)).map(|((_, s), v)| {
                ParsedField::L7StringField("URI_PATH", v, (s.start, s.end - s.start))
            }),
            (tag(Token::ContentFormat), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CONTENT_FORMAT", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
