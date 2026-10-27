//! Identifier, contextual keyword, and string escape parsing utilities for FrameAssembly.
//!
//! Because FrameAssembly defines over 640 case-insensitive protocol names and modifier keywords,
//! users may freely choose any casing or contextual names (such as `dns`, `ms`, `get`, or `server`)
//! for `HOST` and `FLOW` identifiers and unquoted barewords. This module provides
//! [`parse_spanned_ident`], [`parse_ident`], [`parse_any_str`], and [`unescape_string`] to resolve
//! zero-copy source-spanned identifiers, string-like arguments, and C-style hex/Unicode escape
//! sequences (`\r`, `\n`, `\t`, `\\`, `\"`, `\'`, `\xHH`, `\uXXXX`).

use alloc::string::{String, ToString};
use winnow::ModalResult as PResult;
use winnow::combinator::alt;
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::Spanned;
use crate::lexer::Token;

use super::{Stream, parse_raw_string_lit};

/// Helper to parse an identifier or contextual keyword, returning its zero-copy spanned slice.
pub(crate) fn parse_spanned_ident<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Spanned<&'a str>> {
    let (_t, span, slice) = any
        .verify(|(t, _, _)| {
            !matches!(
                t,
                Token::RightArrow
                    | Token::LeftArrow
                    | Token::LBrace
                    | Token::RBrace
                    | Token::LParen
                    | Token::RParen
                    | Token::Comma
                    | Token::StringLit(_)
                    | Token::IpAddress(_)
                    | Token::MacAddress(_)
                    | Token::OidStr(_)
                    | Token::Number(_)
            )
        })
        .parse_next(input)?;

    Ok(Spanned::new(slice, (span.start, span.end - span.start)))
}

/// Helper to parse an identifier token and extract its string value.
pub(crate) fn parse_ident<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    parse_spanned_ident.map(|s| s.node).parse_next(input)
}

/// Helper to parse any string-like token (quoted string, identifier, keyword, number, IP, MAC, or OID).
pub(crate) fn parse_any_str<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    alt((
        parse_raw_string_lit,
        parse_ident,
        any.verify_map(|(t, _, _)| match t {
            Token::Number(s)
            | Token::IpAddress(s)
            | Token::MacAddress(s)
            | Token::OidStr(s) => Some(s),
            _ => None,
        }),
    ))
    .parse_next(input)
}

/// Decodes string escape sequences (`\r`, `\n`, `\t`, `\\`, `\"`, `\'`, `\xHH`, `\uXXXX`).
///
/// # Errors
/// Returns an error message if an invalid or incomplete escape sequence is encountered.
pub fn unescape_string(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('x') => {
                    let h1 = chars
                        .next()
                        .ok_or_else(|| "Incomplete \\x escape sequence".to_string())?;
                    let h2 = chars
                        .next()
                        .ok_or_else(|| "Incomplete \\x escape sequence".to_string())?;
                    let mut hex_buf = [0u8; 2];
                    hex_buf[0] = h1 as u8;
                    hex_buf[1] = h2 as u8;
                    let hex_str = core::str::from_utf8(&hex_buf)
                        .map_err(|_| "Invalid ASCII hex digit in \\x".to_string())?;
                    let byte = u8::from_str_radix(hex_str, 16)
                        .map_err(|_| alloc::format!("Invalid hex byte in \\x: {}", hex_str))?;
                    out.push(byte as char);
                }
                Some('u') => {
                    let mut hex_buf = [0u8; 4];
                    for b in &mut hex_buf {
                        let ch = chars
                            .next()
                            .ok_or_else(|| "Incomplete \\u escape sequence".to_string())?;
                        *b = ch as u8;
                    }
                    let hex_str = core::str::from_utf8(&hex_buf)
                        .map_err(|_| "Invalid ASCII hex digit in \\u".to_string())?;
                    let code = u32::from_str_radix(hex_str, 16)
                        .map_err(|_| alloc::format!("Invalid unicode hex in \\u: {}", hex_str))?;
                    let ch = char::from_u32(code)
                        .ok_or_else(|| alloc::format!("Invalid unicode codepoint: {:x}", code))?;
                    out.push(ch);
                }
                Some(other) => out.push(other),
                None => return Err("Dangling backslash at end of string".to_string()),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}
