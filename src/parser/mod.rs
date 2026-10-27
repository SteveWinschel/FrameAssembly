//! Two-phase parser and semantic analyzer for the FrameAssembly domain-specific language.
//!
//! This module implements the syntactic parser and semantic validation pipeline for FrameAssembly
//! `.fasm` specifications using `winnow` parser combinators. Phase 1 consumes a spanned lexical
//! token [`Stream`] produced by [`crate::lexer::lex`] and constructs a strongly typed Abstract
//! Syntax Tree ([`Program`], [`HostDef`], [`FlowDef`], [`FrameStatement`]) via protocol-scoped
//! statement modifier dispatch. Phase 2 executes [`validate_semantics`] to verify endpoint IP
//! family homogeneity, field numeric ranges, duplicate declaration invariants, and cross-protocol
//! modifier rules before bytecode emission.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use core::str::FromStr;

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err, opt, repeat, separated};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::error::CompilerError;
use crate::lexer::Token;

/// Layer 2, Layer 3, Layer 4, and SNMP modifier application.
pub(crate) mod field_apply;
/// Internal field representation and protocol-scoped modifier dispatch.
pub(crate) mod fields;
/// Final FrameStatement synthesis from accumulated FrameBuilder state.
pub(crate) mod finish;
/// Identifier, contextual keyword, and string escape parsers.
pub(crate) mod ident;
/// Layer 2 field parsers.
pub(crate) mod l2;
/// Layer 3 field parsers.
pub(crate) mod l3;
/// Layer 4 field parsers.
pub(crate) mod l4;
/// Layer 7 field parsers.
pub(crate) mod l7;
/// Layer 7 modifier application.
pub(crate) mod l7_apply;
/// SNMP protocol parser (backwards-compatible internal alias).
pub(crate) mod snmp {
    pub(crate) use super::l7::snmp::*;
}
/// Frame statement state accumulation and protocol-scoped parser loop.
pub(crate) mod statement;
/// Semantic validation pass for parsed AST programs.
pub(crate) mod validation;

#[cfg(test)]
mod tests;

pub(crate) use fields::ParsedField;
pub(crate) use ident::{parse_any_str, parse_ident, parse_spanned_ident};
pub use ident::unescape_string;
pub(crate) use statement::parse_frame_statement;
pub use validation::validate_semantics;

/// A stream of lexical tokens mapped to their source spans and zero-copy source slices.
///
/// Used extensively throughout the parser combinators.
pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)];

/// Helper to match a specific token (case-insensitively for identifier tags), returning the token and its source span.
pub(crate) fn tag<'i, 'a: 'i>(
    expected: Token<'a>,
) -> impl Parser<Stream<'i, 'a>, (Token<'a>, core::ops::Range<usize>), ErrMode<ContextError>> {
    any.verify_map(
        move |(t, span, _): (Token<'a>, core::ops::Range<usize>, &'a str)| {
            let matches = match (&t, &expected) {
                (Token::Ident(a), Token::Ident(b)) => a.eq_ignore_ascii_case(b),
                _ => t == expected,
            };
            if matches { Some((t, span)) } else { None }
        },
    )
}

/// Helper to parse a raw string literal token and extract its inner value without quotes.
pub(crate) fn parse_raw_string_lit<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    let (t, _, _) = any
        .verify(|(t, _, _)| matches!(t, Token::StringLit(_)))
        .parse_next(input)?;
    match t {
        Token::StringLit(s) => Ok(s
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(s)),
        _ => unreachable!(),
    }
}

/// Helper to parse a string literal and decode its escape sequences.
pub(crate) fn parse_string_lit<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<String> {
    let raw = parse_raw_string_lit(input)?;
    unescape_string(raw).map_err(|_| winnow::error::ErrMode::Cut(ContextError::new()))
}

/// Parses a raw hex payload string into bytes.
pub(crate) fn parse_hex_payload<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<u8>> {
    let raw = parse_raw_string_lit(input)?;
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !clean.len().is_multiple_of(2) {
        return Err(winnow::error::ErrMode::Cut(ContextError::new()));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let b = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| winnow::error::ErrMode::Cut(ContextError::new()))?;
        bytes.push(b);
    }
    Ok(bytes)
}

/// Helper to parse a string value that might be a quoted string, an identifier, or a keyword.
pub(crate) fn parse_str_val<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<&'a str> {
    alt((parse_raw_string_lit, parse_ident)).parse_next(input)
}

/// Helper to parse raw hex bytes from either a hex string or hex numeric literal.
pub(crate) fn parse_hex_bytes<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Vec<u8>> {
    alt((
        parse_hex_payload,
        parse_u64.map(|v| {
            let b = v.to_be_bytes();
            let leading = b.iter().take_while(|&&x| x == 0).count();
            if leading == 8 {
                alloc::vec![0]
            } else {
                b[leading..].to_vec()
            }
        }),
    ))
    .parse_next(input)
}

/// Parses an IP address from a token stream.
pub(crate) fn parse_ip<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<IpAddr> {
    any.verify_map(|(t, _, _)| match t {
        Token::IpAddress(s) | Token::OidStr(s) => IpAddr::from_str(s).ok(),
        _ => None,
    })
    .parse_next(input)
}

/// Parses a MAC address from a token stream.
pub(crate) fn parse_mac<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<[u8; 6]> {
    any.verify_map(|(t, _, _)| {
        if let Token::MacAddress(s) = t {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                let mut mac = [0u8; 6];
                for i in 0..6 {
                    mac[i] = u8::from_str_radix(parts[i], 16).ok()?;
                }
                Some(mac)
            } else {
                None
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u8` integer supporting decimal and hex.
pub(crate) fn parse_u8<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u8> {
    any.verify_map(|(t, _, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok()
            } else {
                u8::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u16` integer supporting decimal and hex.
pub(crate) fn parse_u16<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u16> {
    any.verify_map(|(t, _, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u16::from_str_radix(hex, 16).ok()
            } else {
                u16::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u32` integer and returns its span, supporting decimal and hex.
pub(crate) fn parse_spanned_u32<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<(u32, (usize, usize))> {
    any.verify_map(|(t, span, _): (Token<'a>, core::ops::Range<usize>, &'a str)| {
        if let Token::Number(s) = t {
            let val = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                u32::from_str(s).ok()
            }?;
            Some((val, (span.start, span.end - span.start)))
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u32` integer.
pub(crate) fn parse_u32<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u32> {
    parse_spanned_u32.map(|(v, _)| v).parse_next(input)
}

/// Parses an `i32` signed integer.
pub(crate) fn parse_i32<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<i32> {
    any.verify_map(|(t, _, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                i32::from_str_radix(hex, 16).ok()
            } else {
                i32::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `u64` unsigned integer.
pub(crate) fn parse_u64<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<u64> {
    any.verify_map(|(t, _, _)| {
        if let Token::Number(s) = t {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                u64::from_str(s).ok()
            }
        } else {
            None
        }
    })
    .parse_next(input)
}

/// Parses a `HOST` block definition with precision `cut_err`.
pub(crate) fn parse_host_def<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<HostDef<'a>> {
    let (_, host_kw_span) = tag(Token::Host).parse_next(input)?;
    let name_spanned = cut_err(parse_spanned_ident).parse_next(input)?;
    let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;

    let mut ip = None;
    let mut mac = None;

    let _: Vec<()> = repeat(
        0..,
        alt((
            (tag(Token::Ip), cut_err(parse_ip)).map(|(_, i)| ip = Some(i)),
            (tag(Token::Mac), cut_err(parse_mac)).map(|(_, m)| mac = Some(m)),
        )),
    )
    .parse_next(input)?;

    let (_, rbrace_span) = cut_err(tag(Token::RBrace)).parse_next(input)?;

    if let Some(ip) = ip {
        Ok(HostDef {
            name: name_spanned.node,
            ip,
            mac,
            span: (host_kw_span.start, rbrace_span.end - host_kw_span.start),
        })
    } else {
        Err(winnow::error::ErrMode::Cut(ContextError::new()))
    }
}

/// Parses a packet direction arrow (`->` or `<-`).
pub(crate) fn parse_direction<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Direction> {
    alt((
        tag(Token::RightArrow).value(Direction::LeftToRight),
        tag(Token::LeftArrow).value(Direction::RightToLeft),
    ))
    .parse_next(input)
}

/// Parses a `FLOW` block definition with precision `cut_err`.
pub(crate) fn parse_flow_def<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<FlowDef<'a>> {
    let (_, flow_kw_span) = tag(Token::Flow).parse_next(input)?;
    let name = cut_err(parse_spanned_ident).parse_next(input)?;
    let _ = cut_err(tag(Token::LParen)).parse_next(input)?;

    let params: Vec<&'a str> =
        cut_err(separated(0.., parse_ident, tag(Token::Comma))).parse_next(input)?;

    let _ = cut_err(tag(Token::RParen)).parse_next(input)?;
    let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;

    let statements: Vec<FrameStatement<'a>> =
        cut_err(repeat(0.., parse_frame_statement)).parse_next(input)?;

    let (_, rbrace_span) = cut_err(tag(Token::RBrace)).parse_next(input)?;

    Ok(FlowDef {
        name: name.node,
        params,
        statements,
        span: (flow_kw_span.start, rbrace_span.end - flow_kw_span.start),
    })
}

/// Parses a single argument passed to a flow invocation.
pub(crate) fn parse_argument<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Argument<'a>> {
    let var = parse_ident(input)?;
    Ok(Argument::Variable(var))
}

/// Parses a flow invocation (e.g. `tcp_handshake(client, server)`).
pub(crate) fn parse_template_invocation<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<TemplateInvocation<'a>> {
    let name_spanned = parse_spanned_ident(input)?;
    let _ = tag(Token::LParen).parse_next(input)?;

    let args: Vec<Argument<'a>> =
        separated(0.., parse_argument, tag(Token::Comma)).parse_next(input)?;

    let (_, rparen_span) = tag(Token::RParen).parse_next(input)?;
    Ok(TemplateInvocation {
        name: name_spanned.node,
        args,
        span: (
            name_spanned.span.0,
            rparen_span.end - name_spanned.span.0,
        ),
    })
}

/// Parses a statement inside the `COMPILE` block (loop or single invocation) with precision `cut_err`.
pub(crate) fn parse_run_statement<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<RunStatement<'a>> {
    if opt(tag(Token::Loop)).parse_next(input)?.is_some() {
        let count = cut_err(parse_u32).parse_next(input)?;
        let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;
        let invocations: Vec<TemplateInvocation<'a>> =
            cut_err(repeat(0.., parse_template_invocation)).parse_next(input)?;
        let _ = cut_err(tag(Token::RBrace)).parse_next(input)?;
        Ok(RunStatement::Loop(count, invocations))
    } else {
        let inv = parse_template_invocation(input)?;
        Ok(RunStatement::Invocation(inv))
    }
}

/// Parses the entire `COMPILE` block with precision `cut_err`.
pub(crate) fn parse_compile_block<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<Vec<RunStatement<'a>>> {
    let _ = tag(Token::Compile).parse_next(input)?;
    let _ = cut_err(tag(Token::LBrace)).parse_next(input)?;
    let statements: Vec<RunStatement<'a>> =
        cut_err(repeat(0.., parse_run_statement)).parse_next(input)?;
    let _ = cut_err(tag(Token::RBrace)).parse_next(input)?;
    Ok(statements)
}

/// Represents a top-level construct parsed from the file.
pub(crate) enum TopLevel<'a> {
    /// A host definition.
    Host(HostDef<'a>),
    /// A flow definition.
    Flow(FlowDef<'a>),
    /// The compile block.
    Compile(Vec<RunStatement<'a>>),
}

/// Parses a single top-level construct (`HOST`, `FLOW`, or `COMPILE`).
pub(crate) fn parse_top_level<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<TopLevel<'a>> {
    alt((
        parse_host_def.map(TopLevel::Host),
        parse_flow_def.map(TopLevel::Flow),
        parse_compile_block.map(TopLevel::Compile),
    ))
    .parse_next(input)
}

/// Parses all top level constructs and constructs the [`Program`].
pub(crate) fn parse_all<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Program<'a>> {
    let mut hosts = Vec::new();
    let mut flows = Vec::new();
    let mut compile_block = None;

    let top_levels: Vec<TopLevel<'a>> = repeat(0.., parse_top_level).parse_next(input)?;

    for tl in top_levels {
        match tl {
            TopLevel::Host(h) => hosts.push(h),
            TopLevel::Flow(f) => flows.push(f),
            TopLevel::Compile(c) => {
                if compile_block.is_some() {
                    return Err(winnow::error::ErrMode::Cut(ContextError::new()));
                }
                compile_block = Some(c);
            }
        }
    }

    if let Some(compile_block) = compile_block {
        Ok(Program {
            hosts,
            flows,
            compile_block,
        })
    } else {
        Err(winnow::error::ErrMode::Cut(ContextError::new()))
    }
}

/// Parses a complete FrameAssembly program from a source string and validates semantic invariants.
///
/// # Examples
/// ```
/// use frameassembly::parser::parse_program;
///
/// let input = "HOST client { IP 10.0.0.1 }\nCOMPILE {}";
/// let program = parse_program(input).unwrap();
/// assert_eq!(program.hosts.len(), 1);
/// ```
///
/// # Errors
/// Returns [`CompilerError::ParseError`] or [`CompilerError::SemanticError`] if:
/// * The input contains syntax errors.
/// * The tokens do not match the expected grammar.
/// * There are unexpected trailing tokens after the program block.
/// * Semantic rules (ranges, mixed IP versions, duplicate declarations) are violated.
pub fn parse_program<'a>(input_str: &'a str) -> Result<Program<'a>, CompilerError> {
    let raw_tokens = crate::lexer::lex(input_str)?;
    let tokens: Vec<(Token<'a>, core::ops::Range<usize>, &'a str)> = raw_tokens
        .into_iter()
        .map(|(t, span)| {
            let slice = &input_str[span.clone()];
            (t, span, slice)
        })
        .collect();
    let mut stream: Stream<'_, 'a> = &tokens;

    let program = match parse_all.parse_next(&mut stream) {
        Ok(program) => {
            if !stream.is_empty() {
                let span = stream[0].1.clone();
                return Err(CompilerError::ParseError {
                    message: "Unexpected tokens at end of file".to_string(),
                    src: input_str.to_string(),
                    span: (span.start, span.end - span.start),
                });
            }
            program
        }
        Err(e) => {
            let offset = if stream.is_empty() {
                input_str.len()..input_str.len()
            } else {
                stream[0].1.clone()
            };
            return Err(CompilerError::ParseError {
                message: alloc::format!("Syntax error: {:?}", e),
                src: input_str.to_string(),
                span: (offset.start, offset.end - offset.start),
            });
        }
    };

    validate_semantics(&program, input_str)?;

    Ok(program)
}
