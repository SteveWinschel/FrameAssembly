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

    let _: Vec<()> = repeat(
        0..,
        alt((
            (tag(Token::Ip), cut_err(parse_ip)).map(|(_, i)| ip = Some(i)),
            (tag(Token::Mac), cut_err(parse_mac)).map(|(_, m)| mac = Some(m)),
        )),
    )
    .parse_next(input)?;

    let saved_before_rbrace = *input;
    let (_, rbrace_span) = cut_err(tag(Token::RBrace)).parse_next(input)?;

    if let Some(ip) = ip {
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
    /// Inside `HOST <name> { ... }`.
    Host {
        /// Declared host name.
        name: &'a str,
        /// Whether an `IP` field has been seen inside this `HOST` block.
        has_ip: bool,
    },
    /// Inside `FLOW <name>(...) { ... }`.
    Flow,
    /// Inside `COMPILE { ... }`.
    Compile,
}

/// Suggests a canonical `.fasm` keyword for common typos or muscle-memory aliases.
fn suggest_canonical_keyword(raw: &str) -> Option<&'static str> {
    let upper = raw.to_ascii_uppercase();
    match upper.as_str() {
        "SPORT" | "SRC_PORT" | "SOURCE_PORT" | "SRCPROT" => return Some("SRCPORT"),
        "DPORT" | "DST_PORT" | "DEST_PORT" | "DESTINATION_PORT" | "DSTPROT" => {
            return Some("DSTPORT");
        }
        "ACK_NUM" | "ACKNO" | "ACK_NUMBER" | "ACKNOWLEDGMENT" => return Some("ACKNUM"),
        "SEQ_NUM" | "SEQNO" | "SEQUENCE_NUMBER" => return Some("SEQ"),
        "HOPLIMIT" | "HOP_LIMIT" | "HLIM" => return Some("TTL"),
        "TOS" | "TRAFFIC_CLASS" | "TRAFFICCLASS" | "TCLASS" => return Some("DSCP"),
        "COS" | "DOT1P" => return Some("PCP"),
        "VLAN_ID" | "VLANID" | "VID" => return Some("VLAN"),
        "SVLAN" | "OUTER_VLAN" => return Some("QINQ"),
        "CVLAN" | "INNER_VLAN_ID" => return Some("INNER_VLAN"),
        "SNMP" | "SNMPV2" | "SNMPV2C" => return Some("SNMP2"),
        "SNMPV1" => return Some("SNMP1"),
        "SNMPV3" => return Some("SNMP3"),
        "ICMPV6" | "PING" => return Some("ICMP"),
        "DHCPV6" | "DHCPV4" => return Some("DHCP"),
        "REQ_ID" | "REQUEST_ID" => return Some("REQID"),
        "ENGINE_ID" => return Some("ENGINEID"),
        "ENGINE_BOOTS" | "BOOTS" => return Some("ENGINEBOOTS"),
        "ENGINE_TIME" => return Some("ENGINETIME"),
        "SYS_UP_TIME" | "SYS_UPTIME" => return Some("SYSUPTIME"),
        "VAR_BIND" => return Some("VARBIND"),
        "SRC_MAC" => return Some("SRCMAC"),
        "DST_MAC" | "DEST_MAC" => return Some("DSTMAC"),
        "SRC_IP" => return Some("SRCIP"),
        "DST_IP" | "DEST_IP" => return Some("DSTIP"),
        "PAYLAOD" | "PAYLOD" => return Some("PAYLOAD"),
        "HEX_PAYLOAD" => return Some("HEXPAYLOAD"),
        "COMPLIE" | "COMPIL" | "RUN" => return Some("COMPILE"),
        "HOTS" | "HSOT" | "ENDPOINT" | "NODE" => return Some("HOST"),
        "FLWO" | "FOLW" => return Some("FLOW"),
        _ => {}
    }

    const CANDIDATES: &[&str] = &[
        "HOST", "FLOW", "COMPILE", "LOOP", "IP", "MAC", "WAIT", "PAYLOAD", "HEXPAYLOAD",
        "SRCPORT", "DSTPORT", "SRCMAC", "DSTMAC", "TTL", "DSCP", "ECN", "VLAN", "PCP", "DEI",
        "QINQ", "INNER_VLAN", "MPLS", "SEQ", "ACKNUM", "WIN", "MSS", "WSCALE", "SACK_PERM",
        "TSVAL", "TSECR", "URGENT", "SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR",
        "TCP", "UDP", "SCTP", "ICMP", "NDP", "ARP", "DNS", "MDNS", "DHCP", "HTTP", "HTTP2",
        "TLS", "QUIC", "SNMP1", "SNMP2", "SNMP3", "VARBIND", "ENGINEID", "ENGINEBOOTS",
        "ENGINETIME", "REQID", "HOST_HDR", "MODBUS", "BGP", "OSPF", "VXLAN", "WIREGUARD",
    ];

    if upper.len() < 3 {
        return None;
    }

    let mut best: Option<(&'static str, usize)> = None;
    for &cand in CANDIDATES {
        if cand.len().abs_diff(upper.len()) > 2 {
            continue;
        }
        let dist = edit_distance(&upper, cand);
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
                    has_ip: false,
                };
            }
            Token::Flow if brace_depth == 0 => {
                enclosing = EnclosingBlock::Flow;
            }
            Token::Compile if brace_depth == 0 => {
                enclosing = EnclosingBlock::Compile;
            }
            Token::Ip => {
                if let EnclosingBlock::Host { name, .. } = enclosing {
                    enclosing = EnclosingBlock::Host { name, has_ip: true };
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
            "Syntax error: missing 'COMPILE { ... }' block at the end of the file. Every .fasm file must include a COMPILE block to generate packets (for example: COMPILE { my_flow(client, server) })".to_string()
        } else {
            "Syntax error: unexpected end of file (check for a missing closing '}' or incomplete packet statement)".to_string()
        };
        return (msg, (eof_pos, 0));
    }

    let (tok, span_range, raw_slice) = &tokens[err_idx];
    let raw_slice = *raw_slice;
    let span = (span_range.start, span_range.end - span_range.start);
    let lower = raw_slice.to_ascii_lowercase();

    // 1. Duplicate COMPILE block
    if *tok == Token::Compile && brace_depth == 0 && compile_count >= 1 {
        return (
            "Syntax error: duplicate 'COMPILE' block. A .fasm file can only have one COMPILE { ... } block — place all flow calls inside a single COMPILE block".to_string(),
            span,
        );
    }

    // 2. Packet statement written outside a FLOW block
    let next_is_arrow = tokens
        .get(err_idx + 1)
        .is_some_and(|t| matches!(t.0, Token::RightArrow | Token::LeftArrow));
    if enclosing != EnclosingBlock::Flow
        && (matches!(tok, Token::RightArrow | Token::LeftArrow) || next_is_arrow)
    {
        return (
            alloc::format!(
                "Syntax error: packet statement starting at '{}' is outside a FLOW block. Wrap packet lines inside 'FLOW my_flow(a, b) {{ ... }}' and call the flow inside 'COMPILE {{ my_flow(host1, host2) }}'",
                raw_slice
            ),
            span,
        );
    }

    // 3. FLOW missing parameter list `(a, b)`
    if *tok == Token::LBrace && err_idx >= 2 && tokens[err_idx - 2].0 == Token::Flow {
        let flow_name = tokens[err_idx - 1].2;
        return (
            alloc::format!(
                "Syntax error: FLOW '{}' is missing its endpoint parameter list '(a, b)' before '{{'. Write: FLOW {}(c, s) {{ ... }}",
                flow_name,
                flow_name
            ),
            span,
        );
    }

    // 4. Inside a HOST block
    if let EnclosingBlock::Host { name, has_ip } = enclosing {
        if *tok == Token::RBrace && !has_ip {
            return (
                alloc::format!(
                    "Syntax error: HOST '{}' is missing a required 'IP <address>' field. Example: HOST {} {{ IP 10.0.0.1 }}",
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
                    "Syntax error: unexpected '{}' in HOST '{}'. FrameAssembly uses 'IP' for both IPv4 and IPv6 addresses (for example: IP 10.0.0.1 or IP 2001:db8::1)",
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
                    "Syntax error: unexpected '{}' in HOST '{}'. Subnet masks are not used in HOST blocks (only 'IP <address>' and optional 'MAC <address>')",
                    raw_slice,
                    name
                ),
                span,
            );
        }
        if err_idx >= 1 && tokens[err_idx - 1].0 == Token::Ip {
            return (
                alloc::format!(
                    "Syntax error: invalid IP address '{}' after 'IP'. Expected a valid IPv4 (e.g. 10.0.0.1) or IPv6 (e.g. 2001:db8::1) address",
                    raw_slice
                ),
                span,
            );
        }
        if err_idx >= 1 && tokens[err_idx - 1].0 == Token::Mac {
            return (
                alloc::format!(
                    "Syntax error: invalid MAC address '{}' after 'MAC'. Expected colon (00:1a:2b:3c:4d:5e), hyphen (00-1A-2B-3C-4D-5E), or Cisco dotted (001a.2b3c.4d5e) format",
                    raw_slice
                ),
                span,
            );
        }
    }

    // 5. Inside a COMPILE block (e.g. bare flow name without arguments)
    if enclosing == EnclosingBlock::Compile && err_idx >= 1 {
        let prev = &tokens[err_idx - 1];
        if *tok == Token::RBrace
            && !matches!(prev.0, Token::LBrace | Token::RParen | Token::Compile)
        {
            return (
                alloc::format!(
                    "Syntax error: flow call '{}' inside COMPILE is missing its host arguments in parentheses — for example: {}(client, server)",
                    prev.2,
                    prev.2
                ),
                (prev.1.start, prev.1.end - prev.1.start),
            );
        }
    }

    // 6. Common networking aliases and muscle-memory mistakes
    if matches!(lower.as_str(), "sport" | "src_port" | "source_port") {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier (such as SRCPORT, DSTPORT, SEQ, ACKNUM, WIN, or TCP flags). Did you mean 'SRCPORT'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "dport" | "dst_port" | "dest_port" | "destination_port"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier (such as SRCPORT, DSTPORT, SEQ, ACKNUM, WIN, or TCP flags). Did you mean 'DSTPORT'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(tok, Token::Number(_)) && err_idx >= 1 && tokens[err_idx - 1].0 == Token::Ack {
        return (
            alloc::format!(
                "Syntax error: unexpected number '{}' after 'ACK'. In .fasm, 'ACK' alone is a TCP flag; did you mean 'ACKNUM {}' to set the acknowledgment number?",
                raw_slice,
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "ack_num" | "ackno" | "ack_number" | "acknowledgment"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'ACKNUM <number>'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(lower.as_str(), "hoplimit" | "hop_limit" | "hlim") {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. FrameAssembly uses 'TTL' for both IPv4 Time-to-Live and IPv6 Hop Limit (for example: TTL 64 or TTL 255)",
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
                "Syntax error: unexpected token '{}'. Did you mean 'DSCP <0..63>' (or 'ECN <0..3>')?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(lower.as_str(), "cos" | "dot1p") {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'PCP <0..7>' (with 'VLAN <id>') for 802.1p Class of Service?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(
        lower.as_str(),
        "vlan_id" | "vlanid" | "vid" | "svlan" | "cvlan" | "outer_vlan"
    ) {
        return (
            alloc::format!(
                "Syntax error: unexpected token '{}'. Did you mean 'VLAN <id>' or 'QINQ <outer> INNER_VLAN <inner>'?",
                raw_slice
            ),
            span,
        );
    }
    if matches!(tok, Token::Number(_)) && err_idx >= 2 && tokens[err_idx - 2].0 == Token::Qinq {
        return (
            alloc::format!(
                "Syntax error: missing 'INNER_VLAN' keyword before inner VLAN ID '{}'. Write: QINQ {} INNER_VLAN {}",
                raw_slice,
                tokens[err_idx - 1].2,
                raw_slice
            ),
            span,
        );
    }
    if *tok == Token::Host && enclosing == EnclosingBlock::Flow {
        return (
            "Syntax error: unexpected 'HOST' inside a FLOW packet statement. Did you mean 'HOST_HDR \"<hostname>\"' for the HTTP Host header?".to_string(),
            span,
        );
    }
    if *tok == Token::Wait && enclosing == EnclosingBlock::Flow {
        return (
            "Syntax error: standalone 'WAIT' line is not supported. Place 'WAIT <duration>' at the end of a packet statement (for example: c -> s TCP SYN WAIT 5ms)".to_string(),
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
            "Syntax error: unexpected token '{}', expected a valid statement or protocol modifier (such as SRCPORT, DSTPORT, SEQ, ACKNUM, WIN, or TCP flags)",
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
