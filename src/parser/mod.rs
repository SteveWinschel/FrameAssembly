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
use winnow::combinator::{alt, cut_err, repeat, separated};
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::any;

use crate::ast::*;
use crate::error::CompilerError;
use crate::lexer::Token;

pub(crate) mod field_apply;
pub(crate) mod fields;
pub(crate) mod finish;
pub(crate) mod ident;
pub(crate) mod l2;
pub(crate) mod l3;
pub(crate) mod l4;
pub(crate) mod l7;
pub(crate) mod l7_apply;
pub(crate) mod snmp {
    //! SNMP protocol parser (backwards-compatible internal alias).
    pub(crate) use super::l7::snmp::*;
}
pub(crate) mod statement;
pub(crate) mod validation;

#[cfg(test)]
mod tests;

pub(crate) use fields::ParsedField;
pub(crate) use ident::{parse_any_str, parse_ident, parse_spanned_ident};
pub use ident::unescape_string;
pub(crate) use statement::parse_frame_statement;
pub use validation::{protocol_requires_ip, validate_semantics};

/// A stream of lexical tokens mapped to their source spans and zero-copy source slices.
///
/// Used extensively throughout the parser combinators.
pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)];

/// Helper to match a specific token, returning the token and its source span.
pub(crate) fn tag<'i, 'a: 'i>(
    expected: Token<'a>,
) -> impl Parser<Stream<'i, 'a>, (Token<'a>, core::ops::Range<usize>), ErrMode<ContextError>> {
    any.verify_map(
        move |(t, span, _): (Token<'a>, core::ops::Range<usize>, &'a str)| {
            if t == expected { Some((t, span)) } else { None }
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

/// Parses a MAC address string in colon (`00:1a:2b:3c:4d:5e`), hyphen (`00-1A-2B-3C-4D-5E`),
/// or Cisco dotted-quad (`001a.2b3c.4d5e`) format into a 6-byte array.
pub(crate) fn parse_mac_bytes(s: &str) -> Option<[u8; 6]> {
    if s.contains(':') || s.contains('-') {
        let sep = if s.contains(':') { ':' } else { '-' };
        let mut mac = [0u8; 6];
        let mut count = 0usize;
        for part in s.split(sep) {
            if count >= 6 || part.is_empty() || part.len() > 2 {
                return None;
            }
            mac[count] = u8::from_str_radix(part, 16).ok()?;
            count += 1;
        }
        (count == 6).then_some(mac)
    } else if s.contains('.') {
        let mut mac = [0u8; 6];
        let mut count = 0usize;
        for part in s.split('.') {
            if count >= 3 || part.len() != 4 {
                return None;
            }
            let word = u16::from_str_radix(part, 16).ok()?;
            let [hi, lo] = word.to_be_bytes();
            mac[count * 2] = hi;
            mac[count * 2 + 1] = lo;
            count += 1;
        }
        (count == 3).then_some(mac)
    } else {
        None
    }
}

/// Parses a MAC address from a token stream.
pub(crate) fn parse_mac<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<[u8; 6]> {
    any.verify_map(|(t, _, _)| {
        if let Token::MacAddress(s) = t {
            parse_mac_bytes(s)
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

    let (): () = repeat(
        0..,
        alt((
            (tag(Token::Ip), cut_err(parse_ip)).map(|(_, i)| ip = Some(i)),
            (tag(Token::Mac), cut_err(parse_mac)).map(|(_, m)| mac = Some(m)),
        )),
    )
    .parse_next(input)?;

    let saved_before_rbrace = *input;
    let (_, rbrace_span) = cut_err(tag(Token::RBrace)).parse_next(input)?;

    if ip.is_some() || mac.is_some() {
        Ok(HostDef {
            name: name_spanned.node,
            ip,
            mac,
            span: (host_kw_span.start, rbrace_span.end - host_kw_span.start),
        })
    } else {
        *input = saved_before_rbrace;
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

/// Parses a statement inside the `compile` block (inline frame statement or single flow invocation) with precision `cut_err`.
pub(crate) fn parse_run_statement<'i, 'a>(
    input: &mut Stream<'i, 'a>,
) -> PResult<RunStatement<'a>> {
    if input.len() >= 2 && matches!(input[1].0, Token::RightArrow | Token::LeftArrow) {
        parse_frame_statement(input).map(|f| RunStatement::Frame(alloc::boxed::Box::new(f)))
    } else {
        parse_template_invocation(input).map(RunStatement::Invocation)
    }
}

/// Parses the entire `compile` block with precision `cut_err`.
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

    while !input.is_empty() {
        let saved = *input;
        let tl = cut_err(parse_top_level).parse_next(input)?;
        match tl {
            TopLevel::Host(h) => hosts.push(h),
            TopLevel::Flow(f) => flows.push(f),
            TopLevel::Compile(c) => {
                if compile_block.is_some() {
                    *input = saved;
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

/// Tracks which top-level block the parser was inside when a syntax error occurred.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnclosingBlock<'a> {
    /// Outside any top-level block.
    None,
    /// Inside `host <name> { ... }`.
    Host {
        /// Declared host name.
        name: &'a str,
        /// Whether an `ip` or `mac` field has been seen inside this `host` block.
        has_ip_or_mac: bool,
    },
    /// Inside `flow <name>(...) { ... }`.
    Flow,
    /// Inside `compile { ... }`.
    Compile,
}

/// Suggests a canonical v2.0.0 strict-lowercase `.fasm` keyword for common typos or muscle-memory aliases.
fn suggest_canonical_keyword(raw: &str) -> Option<&'static str> {
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "sport" | "source_port" | "sourceport" | "srcprot" => return Some("srcport"),
        "dport" | "dest_port" | "destport" | "destination_port" | "dstprot" => {
            return Some("dstport");
        }
        "ackno" | "ack_number" | "acknumber" | "acknowledgment" => return Some("acknum"),
        "seq_num" | "seqnum" | "seqno" | "sequence_number" => return Some("seq"),
        "hoplimit" | "hop_limit" | "hlim" => return Some("ttl"),
        "tos" | "traffic_class" | "trafficclass" | "tclass" => return Some("dscp"),
        "cos" | "dot1p" => return Some("pcp"),
        "vlan_id" | "vlanid" | "vid" => return Some("vlan"),
        "svlan" | "outer_vlan" | "outervlan" => return Some("qinq"),
        "cvlan" | "inner_vlan_id" | "innervlanid" => return Some("innervlan"),
        "snmp" | "snmpv2" | "snmpv2c" => return Some("snmp2"),
        "snmpv1" => return Some("snmp1"),
        "snmpv3" => return Some("snmp3"),
        "icmpv6" | "ping" => return Some("icmp"),
        "dhcpv6" | "dhcpv4" => return Some("dhcp"),
        "request_id" | "requestid" => return Some("reqid"),
        "boots" => return Some("engineboots"),
        "dest_mac" | "destmac" => return Some("dstmac"),
        "dest_ip" | "destip" => return Some("dstip"),
        "paylaod" | "paylod" => return Some("payload"),
        "complie" | "compil" | "run" => return Some("compile"),
        "hots" | "hsot" | "endpoint" | "node" => return Some("host"),
        "flwo" | "folw" => return Some("flow"),
        _ => {}
    }

    const CANDIDATES: &[&str] = &[
        "host", "flow", "compile", "ip", "mac", "wait", "payload", "hexpayload", "srcport",
        "dstport", "srcmac", "dstmac", "ttl", "dscp", "ecn", "vlan", "pcp", "dei", "qinq",
        "innervlan", "mpls", "seq", "acknum", "win", "mss", "wscale", "sackperm", "tsval",
        "tsecr", "urgent", "syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr", "tcp", "udp",
        "sctp", "icmp", "ndp", "arp", "dns", "mdns", "dhcp", "http", "http2", "tls", "quic",
        "snmp1", "snmp2", "snmp3", "varbind", "engineid", "engineboots", "enginetime", "reqid",
        "hosthdr", "modbus", "bgp", "ospf", "vxlan", "wireguard",
    ];

    if lower.len() < 3 {
        return None;
    }

    let mut best: Option<(&'static str, usize)> = None;
    for &cand in CANDIDATES {
        if cand.len().abs_diff(lower.len()) > 2 {
            continue;
        }
        let dist = edit_distance(&lower, cand);
        if dist > 0 && dist <= 2 && best.is_none_or(|(_, d)| dist < d) {
            best = Some((cand, dist));
        }
    }
    best.map(|(c, _)| c)
}

/// Computes the Levenshtein edit distance between two ASCII strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b_bytes.len()).collect();
    let mut curr = alloc::vec![0usize; b_bytes.len() + 1];
    for (i, &ca) in a_bytes.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b_bytes.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        core::mem::swap(&mut prev, &mut curr);
    }
    prev[b_bytes.len()]
}

/// Builds a plain-English syntax error message and `(start, len)` byte span for network technicians.
fn diagnose_parse_error<'a>(
    tokens: &[(Token<'a>, core::ops::Range<usize>, &'a str)],
    err_idx: usize,
    input_str: &'a str,
) -> (String, (usize, usize)) {
    let mut brace_depth = 0usize;
    let mut enclosing = EnclosingBlock::None;
    let mut compile_count = 0usize;

    let limit = err_idx.min(tokens.len());
    for i in 0..limit {
        let (t, _, slice) = &tokens[i];
        match t {
            Token::Host if brace_depth == 0 => {
                let name = tokens.get(i + 1).map_or("<host>", |n| n.2);
                enclosing = EnclosingBlock::Host {
                    name,
                    has_ip_or_mac: false,
                };
            }
            Token::Flow if brace_depth == 0 => {
                enclosing = EnclosingBlock::Flow;
            }
            Token::Compile if brace_depth == 0 => {
                enclosing = EnclosingBlock::Compile;
            }
            Token::Ip | Token::Mac => {
                if let EnclosingBlock::Host { name, .. } = enclosing {
                    enclosing = EnclosingBlock::Host {
                        name,
                        has_ip_or_mac: true,
                    };
                }
            }
            Token::LBrace => {
                brace_depth += 1;
            }
            Token::RBrace => {
                brace_depth = brace_depth.saturating_sub(1);
                if brace_depth == 0 {
                    if enclosing == EnclosingBlock::Compile {
                        compile_count += 1;
                    }
                    enclosing = EnclosingBlock::None;
                }
            }
            _ => {
                let _ = slice;
            }
        }
    }

    if err_idx >= tokens.len() {
        let eof_pos = tokens.last().map_or(input_str.len(), |t| t.1.end);
        let msg = if enclosing == EnclosingBlock::None && compile_count == 0 {
            "Syntax error: missing 'compile { ... }' block at the end of the file. Every .fasm file must include a compile block to generate packets (for example: compile { my_flow(client, server) })".to_string()
        } else {
            "Syntax error: unexpected end of file (check for a missing closing '}' or incomplete packet statement)".to_string()
        };
        return (msg, (eof_pos, 0));
    }

    let (tok, span_range, raw_slice) = &tokens[err_idx];
    let raw_slice = *raw_slice;
    let span = (span_range.start, span_range.end - span_range.start);
    let lower = raw_slice.to_ascii_lowercase();

    // 1. Duplicate compile block
    if *tok == Token::Compile && brace_depth == 0 && compile_count >= 1 {
        return (
            "Syntax error: duplicate 'compile' block. A .fasm file can only have one compile { ... } block — place all flow calls inside a single compile block".to_string(),
            span,
        );
    }

    // 2. Packet statement written outside a flow or compile block
    let next_is_arrow = tokens
        .get(err_idx + 1)
        .is_some_and(|t| matches!(t.0, Token::RightArrow | Token::LeftArrow));
    if enclosing != EnclosingBlock::Flow
        && enclosing != EnclosingBlock::Compile
        && (matches!(tok, Token::RightArrow | Token::LeftArrow) || next_is_arrow)
    {
        return (
            alloc::format!(
                "Syntax error: packet statement starting at '{}' is outside a flow block. Wrap packet lines inside 'flow my_flow(a, b) {{ ... }}' and call the flow inside 'compile {{ my_flow(host1, host2) }}'",
                raw_slice
            ),
            span,
        );
    }

    // 3. flow missing parameter list `(a, b)`
    if *tok == Token::LBrace && err_idx >= 2 && tokens[err_idx - 2].0 == Token::Flow {
        let flow_name = tokens[err_idx - 1].2;
        return (
            alloc::format!(
                "Syntax error: flow '{}' is missing its endpoint parameter list '(a, b)' before '{{'. Write: flow {}(c, s) {{ ... }}",
                flow_name,
                flow_name
            ),
            span,
        );
    }

    // 4. Inside a host block
    if let EnclosingBlock::Host {
        name,
        has_ip_or_mac,
    } = enclosing
    {
        if *tok == Token::RBrace && !has_ip_or_mac {
            return (
                alloc::format!(
                    "Syntax error: host '{}' must specify at least an 'IP <address>' or 'MAC <address>' field. Example: host {} {{ ip 10.0.0.1 }} or host {} {{ mac 00:11:22:33:44:55 }}",
                    name,
                    name,
                    name
                ),
                span,
            );
        }
        if matches!(
            lower.as_str(),
            "ipv4" | "ipv6" | "ip4" | "ip6" | "addr" | "address"
        ) {
            return (
                alloc::format!(
                    "Syntax error: unexpected '{}' in host '{}'. FrameAssembly uses 'ip' for both IPv4 and IPv6 addresses (for example: ip 10.0.0.1 or ip 2001:db8::1)",
                    raw_slice,
                    name
                ),
                span,
            );
        }
        if matches!(
            lower.as_str(),
            "mask" | "netmask" | "subnet" | "subnet_mask" | "prefix" | "cidr"
        ) {
            return (
                alloc::format!(
                    "Syntax error: unexpected '{}' in host '{}'. Subnet masks are not used in host blocks (only 'ip <address>' and optional 'mac <address>')",
                    raw_slice,
                    name
                ),
                span,
            );
        }
        if err_idx >= 1 && tokens[err_idx - 1].0 == Token::Ip {
            return (
                alloc::format!(
                    "Syntax error: invalid IP address '{}' after 'ip'. Expected a valid IPv4 (e.g. 10.0.0.1) or IPv6 (e.g. 2001:db8::1) address",
                    raw_slice
                ),
                span,
            );
        }
        if err_idx >= 1 && tokens[err_idx - 1].0 == Token::Mac {
            return (
                alloc::format!(
                    "Syntax error: invalid MAC address '{}' after 'mac'. Expected colon (00:1a:2b:3c:4d:5e), hyphen (00-1A-2B-3C-4D-5E), or Cisco dotted (001a.2b3c.4d5e) format",
                    raw_slice
                ),
                span,
            );
        }
    }

    // 5. v2.0.0 self-healing diagnostics for removed `loop` and non-lowercase / `_` / `-` keywords
    if matches!(tok, Token::Ident(_)) {
        if raw_slice.eq_ignore_ascii_case("loop") {
            return (
                alloc::format!(
                    "Syntax error: unexpected '{}'. The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile {{ ... }}'.",
                    raw_slice
                ),
                span,
            );
        }
        if let Some(kw) = crate::lexer::suggest_v2_lowercase_keyword(raw_slice) {
            return (
                alloc::format!(
                    "Syntax error: unexpected '{}'. Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace '{}' with '{}'.",
                    raw_slice,
                    raw_slice,
                    kw
                ),
                span,
            );
        }
    }

    // 6. Inside a compile block (e.g. bare flow name without arguments)
    if enclosing == EnclosingBlock::Compile && err_idx >= 1 {
        let prev = &tokens[err_idx - 1];
        if *tok == Token::RBrace
            && !matches!(prev.0, Token::LBrace | Token::RParen | Token::Compile)
        {
            return (
                alloc::format!(
                    "Syntax error: flow call '{}' inside compile is missing its host arguments in parentheses — for example: {}(client, server)",
                    prev.2,
                    prev.2
                ),
                (prev.1.start, prev.1.end - prev.1.start),
            );
        }
    }

    // 7. Common networking aliases and muscle-memory mistakes
    if matches!(lower.as_str(), "sport" | "source_port" | "sourceport") {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier (such as srcport, dstport, seq, acknum, win, or tcp flags). Did you mean 'srcport'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "dport" | "dest_port" | "destport" | "destination_port"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier (such as srcport, dstport, seq, acknum, win, or tcp flags). Did you mean 'dstport'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(tok, Token::Number(_)) && err_idx >= 1 && tokens[err_idx - 1].0 == Token::Ack {
        return (
            alloc::format!(
                "Syntax error: unexpected number '{}' after 'ack'. In .fasm, 'ack' alone is a TCP flag; did you mean 'acknum {}' to set the acknowledgment number?",
                raw_slice,
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "ackno" | "ack_number" | "acknumber" | "acknowledgment"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'acknum <number>'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(lower.as_str(), "hoplimit" | "hop_limit" | "hlim") {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. FrameAssembly uses 'ttl' for both IPv4 Time-to-Live and IPv6 Hop Limit (for example: ttl 64 or ttl 255)",
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "tos" | "traffic_class" | "trafficclass" | "tclass"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'dscp <0..63>' (or 'ecn <0..3>')?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(lower.as_str(), "cos" | "dot1p") {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'pcp <0..7>' (with 'vlan <id>') for 802.1p Class of Service?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "vlan_id" | "vlanid" | "vid" | "svlan" | "cvlan" | "outer_vlan" | "outervlan"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'vlan <id>' or 'qinq <outer> innervlan <inner>'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(tok, Token::Number(_)) && err_idx >= 2 && tokens[err_idx - 2].0 == Token::Qinq {
        return (
            alloc::format!(
                "Syntax error: missing 'innervlan' keyword before inner VLAN ID '{}'. Write: qinq {} innervlan {}",
                raw_slice,
                tokens[err_idx - 1].2,
                raw_slice
            ),
            span,
        );
    }
    if *tok == Token::Host
        && matches!(enclosing, EnclosingBlock::Flow | EnclosingBlock::Compile)
    {
        return (
            "Syntax error: unexpected 'host' inside a flow packet statement. Did you mean 'hosthdr \"<hostname>\"' for the HTTP Host header?".to_string(),
            span,
        );
    }
    if *tok == Token::Wait
        && matches!(enclosing, EnclosingBlock::Flow | EnclosingBlock::Compile)
    {
        return (
            "Syntax error: standalone 'wait' line is not supported. Place 'wait <duration>' at the end of a packet statement (for example: c -> s tcp syn wait 5ms)".to_string(),
            span,
        );
    }
    if let Token::Number(num_str) = tok
        && num_str.starts_with('-')
    {
        let prev_kw = if err_idx >= 1 {
            tokens[err_idx - 1].2
        } else {
            "field"
        };
        return (
            alloc::format!(
                "Syntax error: invalid negative number '{}' after '{}'. Expected a non-negative integer",
                raw_slice,
                prev_kw
            ),
            span,
        );
    }

    if let Some(suggestion) = suggest_canonical_keyword(raw_slice) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier. Did you mean '{}'?",
                raw_slice,
                suggestion
            ),
            span,
        );
    }

    (
        alloc::format!(
            "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier (such as srcport, dstport, seq, acknum, win, or tcp flags)",
            raw_slice
        ),
        span,
    )
}

/// Parses a complete FrameAssembly program from a source string and validates semantic invariants.
///
/// # Examples
/// ```
/// use frameassembly::parser::parse_program;
///
/// let input = "host client { ip 10.0.0.1 }\ncompile {}";
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
                let err_idx = tokens.len() - stream.len();
                let (message, span) = diagnose_parse_error(&tokens, err_idx, input_str);
                return Err(CompilerError::ParseError {
                    message,
                    src: input_str.to_string(),
                    span,
                });
            }
            program
        }
        Err(_) => {
            let err_idx = tokens.len() - stream.len();
            let (message, span) = diagnose_parse_error(&tokens, err_idx, input_str);
            return Err(CompilerError::ParseError {
                message,
                src: input_str.to_string(),
                span,
            });
        }
    };

    validate_semantics(&program, input_str)?;

    Ok(program)
}
