# Winnow 1.0+ Production Reference Patterns

This reference document provides production-ready, fully-documented, and compile-verified Rust code templates covering `winnow 1.0+` for high-performance zero-copy lexing, two-phase AST parsing, Pratt expression evaluation, binary protocol decoding, stateful recursion control, and `miette` diagnostic integration.

---

## 1. Two-Phase Lexer Bridge (`logos` + `TokenSlice` + `Location` + `ContainsToken`)

In production language parsers and domain-specific compilers (such as `frameassembly`), lexing and parsing are split into two decoupled phases:
1. `logos` scans raw UTF-8 source text into a flat vector of token variants paired with byte spans `Range<usize>`.
2. `winnow::stream::TokenSlice` wraps the token array, enabling zero-copy combinator parsing where `.span()` automatically calculates accurate multi-token byte ranges in the original source code.

```rust
//! Two-phase lexer-parser bridge connecting logos and winnow.

use core::ops::Range;
use winnow::combinator::{cut_err, opt, preceded, seq};
use winnow::error::{ContextError, ErrMode, ModalResult, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::{ContainsToken, Location, TokenSlice};
use winnow::token::{any, literal};

/// Lexical token kinds emitted by the tokenizer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind<'a> {
    /// The `HOST` keyword starting a host definition.
    Host,
    /// The `FLOW` keyword starting a flow definition.
    Flow,
    /// The `COMPILE` keyword starting a compilation block.
    Compile,
    /// Identifier token holding a borrowed string slice.
    Ident(&'a str),
    /// IPv4 literal token holding raw string representation.
    Ipv4(&'a str),
    /// IPv6 literal token holding raw string representation.
    Ipv6(&'a str),
    /// MAC address literal token.
    Mac(&'a str),
    /// Unsigned 64-bit integer literal.
    Integer(u64),
    /// Quoted string literal.
    StringLiteral(&'a str),
    /// Left parenthesis `(`.
    LParen,
    /// Right parenthesis `)`.
    RParen,
    /// Left curly brace `{`.
    LBrace,
    /// Right curly brace `}`.
    RBrace,
    /// Comma `,`.
    Comma,
    /// Semicolon `;`.
    Semi,
    /// Right arrow `->` for forward flow direction.
    ArrowRight,
    /// Left arrow `<-` for reverse flow direction.
    ArrowLeft,
    /// Protocol name token (e.g., `TCP`, `UDP`, `SNMP3`).
    Protocol(&'a str),
}

/// Token paired with its exact source byte range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpannedToken<'a> {
    /// The discriminated token kind.
    pub kind: TokenKind<'a>,
    /// Byte range `start..end` in the original source string.
    pub span: Range<usize>,
}

impl<'a> SpannedToken<'a> {
    /// Creates a new spanned token.
    ///
    /// # Arguments
    /// * `kind` - Discriminated token variant.
    /// * `span` - Source byte offset range.
    #[inline]
    pub fn new(kind: TokenKind<'a>, span: Range<usize>) -> Self {
        Self { kind, span }
    }
}

/// Implements `Location` so winnow combinators (`.span()`, `.with_span()`)
/// track accurate source byte ranges across token sequences.
impl Location for SpannedToken<'_> {
    #[inline(always)]
    fn previous_token_end(&self) -> usize {
        self.span.end
    }

    #[inline(always)]
    fn current_token_start(&self) -> usize {
        self.span.start
    }
}

/// Enables `literal(TokenKind::...)` on `TokenSlice<'t, SpannedToken<'a>>`.
impl<'a> PartialEq<TokenKind<'a>> for SpannedToken<'a> {
    #[inline(always)]
    fn eq(&self, other: &TokenKind<'a>) -> bool {
        self.kind == *other
    }
}

/// Enables `one_of([...])` on `TokenSlice<'t, SpannedToken<'a>>`.
impl<'t, 'a> ContainsToken<&'t SpannedToken<'a>> for TokenKind<'a> {
    #[inline(always)]
    fn contains_token(&self, token: &'t SpannedToken<'a>) -> bool {
        *self == token.kind
    }
}

/// Stream type alias for pre-lexed token slices.
pub type TokenStream<'t, 'a> = TokenSlice<'t, SpannedToken<'a>>;

/// Parses an identifier token, returning its inner string slice.
///
/// # Arguments
/// * `input` - Stream of pre-lexed spanned tokens.
///
/// # Returns
/// Borrowed string slice of the matched identifier.
pub fn parse_ident<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<&'a str> {
    any.verify_map(|t: &SpannedToken<'a>| match t.kind {
        TokenKind::Ident(s) => Some(s),
        _ => None,
    })
    .context(StrContext::Expected(StrContextValue::Description("identifier")))
    .parse_next(input)
}

/// Parses an unsigned integer literal token.
///
/// # Arguments
/// * `input` - Stream of pre-lexed spanned tokens.
///
/// # Returns
/// Decoded 64-bit unsigned integer value.
pub fn parse_integer<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<u64> {
    any.verify_map(|t: &SpannedToken<'a>| match t.kind {
        TokenKind::Integer(n) => Some(n),
        _ => None,
    })
    .context(StrContext::Expected(StrContextValue::Description("integer literal")))
    .parse_next(input)
}
```

---

## 2. High-Performance Declarative DSL AST Parsing (`HOST`, `FLOW`, `COMPILE`)

Production grammar rules using `seq!`, `cut_err`, `repeat`, and `opt` to construct validated AST nodes with full source byte spans for canonical FrameAssembly syntax (`HOST <id> { IP <ip> [MAC <mac>] }` and `FLOW <id>(<params>) { <src> -> <dst> <PROTO> ... }`).

```rust
//! Declarative AST parser for canonical FrameAssembly structural blocks.

use core::ops::Range;
use winnow::combinator::{alt, cut_err, opt, repeat, separated, seq};
use winnow::error::{ModalResult, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::token::literal;

use super::{parse_ident, SpannedToken, TokenKind, TokenStream};

/// AST node representing an evaluated host endpoint definition.
///
/// Syntax mapping: `HOST <name> { IP <ip> [MAC <mac>] }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDef<'a> {
    /// Host name identifier.
    pub name: &'a str,
    /// Configured IPv4 or IPv6 address string.
    pub ip: Option<&'a str>,
    /// Configured MAC address string.
    pub mac: Option<&'a str>,
    /// Full source byte span for diagnostic reporting.
    pub span: Range<usize>,
}

/// AST node representing a parameterized traffic flow block.
///
/// Syntax mapping: `FLOW <name>(<param1>, <param2>) { <statements> }`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowDef<'a> {
    /// Flow name identifier.
    pub name: &'a str,
    /// Flow endpoint parameter names.
    pub params: Vec<&'a str>,
    /// List of ordered packet statements inside the flow.
    pub statements: Vec<PacketStmt<'a>>,
    /// Source byte span of the entire flow block.
    pub span: Range<usize>,
}

/// Packet flow direction arrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDirection {
    /// Left-to-right (`->`): Caller sends to Callee.
    Forward,
    /// Right-to-left (`<-`): Callee sends to Caller.
    Reverse,
}

/// AST node representing a single packet transmission statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketStmt<'a> {
    /// Caller host parameter identifier.
    pub src_host: &'a str,
    /// Callee host parameter identifier.
    pub dst_host: &'a str,
    /// Transmission direction (`->` or `<-`).
    pub direction: FlowDirection,
    /// Protocol name (e.g., `TCP`, `DNS`, `SNMP3`).
    pub protocol: &'a str,
    /// Raw payload string if defined.
    pub payload: Option<&'a str>,
    /// Source byte span of the statement.
    pub span: Range<usize>,
}

/// Parses a space-separated host attribute (`IP <ip>` or `MAC <mac>`).
enum HostAttr<'a> {
    /// IP address setting.
    Ip(&'a str),
    /// MAC address setting.
    Mac(&'a str),
}

/// Parses an individual host attribute (`IP <ip>` or `MAC <mac>`).
fn parse_host_attr<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<HostAttr<'a>> {
    let key = parse_ident.parse_next(input)?;
    match key {
        "IP" => {
            let ip_str = cut_err(parse_ident)
                .context(StrContext::Expected(StrContextValue::Description("IPv4 or IPv6 address")))
                .parse_next(input)?;
            Ok(HostAttr::Ip(ip_str))
        }
        "MAC" => {
            let mac_str = cut_err(parse_ident)
                .context(StrContext::Expected(StrContextValue::Description("MAC address")))
                .parse_next(input)?;
            Ok(HostAttr::Mac(mac_str))
        }
        _ => Err(winnow::error::ErrMode::from_input(input)),
    }
}

/// Parses a complete `HOST <name> { IP <ip> [MAC <mac>] }` definition block.
pub fn parse_host_def<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<HostDef<'a>> {
    seq!(
        _: literal(TokenKind::Host),
        cut_err(parse_ident),
        _: cut_err(literal(TokenKind::LBrace)),
        cut_err(repeat(1.., parse_host_attr)),
        _: cut_err(literal(TokenKind::RBrace)),
    )
    .with_span()
    .context(StrContext::Label("host definition"))
    .map(|((name, attrs), span): ((&'a str, Vec<HostAttr<'a>>), Range<usize>)| {
        let mut ip = None;
        let mut mac = None;
        for attr in attrs {
            match attr {
                HostAttr::Ip(v) => ip = Some(v),
                HostAttr::Mac(v) => mac = Some(v),
            }
        }
        HostDef { name, ip, mac, span }
    })
    .parse_next(input)
}

/// Parses a packet transmission arrow (`->` or `<-`).
fn parse_direction<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<FlowDirection> {
    alt((
        literal(TokenKind::ArrowRight).value(FlowDirection::Forward),
        literal(TokenKind::ArrowLeft).value(FlowDirection::Reverse),
    ))
    .parse_next(input)
}

/// Parses a single packet statement: `client -> server TCP [PAYLOAD "data"]`.
pub fn parse_packet_stmt<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<PacketStmt<'a>> {
    seq!(
        parse_ident,
        cut_err(parse_direction),
        cut_err(parse_ident),
        cut_err(parse_ident),
        opt(parse_ident),
    )
    .with_span()
    .context(StrContext::Label("packet statement"))
    .map(|((src, dir, dst, proto, payload), span)| PacketStmt {
        src_host: src,
        dst_host: dst,
        direction: dir,
        protocol: proto,
        payload,
        span,
    })
    .parse_next(input)
}

/// Parses a complete `FLOW <name>(<params>) { <statement>... }` definition block.
pub fn parse_flow_def<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<FlowDef<'a>> {
    seq!(
        _: literal(TokenKind::Flow),
        cut_err(parse_ident),
        _: cut_err(literal(TokenKind::LParen)),
        cut_err(separated(1.., parse_ident, literal(TokenKind::Comma))),
        _: cut_err(literal(TokenKind::RParen)),
        _: cut_err(literal(TokenKind::LBrace)),
        cut_err(repeat(0.., parse_packet_stmt)),
        _: cut_err(literal(TokenKind::RBrace)),
    )
    .with_span()
    .context(StrContext::Label("flow block"))
    .map(|((name, params, stmts), span)| FlowDef {
        name,
        params,
        statements: stmts,
        span,
    })
    .parse_next(input)
}
```

---

## 3. Canonical Space-Separated L3 Modifier Extraction & Shared-Keyword `cut_err` Dispatch

In FrameAssembly's canonical space-separated syntax (`TTL 64 DSCP 46 ECN 2 DF MF FLOWLABEL 0x12345`), modifiers are never separated by `=` or `:`. This pattern demonstrates:
1. Canonical space-separated `<KEYWORD> <VALUE>` and 0-argument flag (`DF`, `MF`) extraction with checkpoint rewind on non-L3 tokens.
2. Zero-allocation `let (): () = repeat(0.., ...).parse_next(input)?;` accumulation into unit `()` rather than `Vec<()>`.
3. Safe shared-keyword `cut_err(alt((...)))` dispatch when a keyword (such as `VERSION` or `TOKEN`) accepts either an integer or a string literal.

```rust
//! Canonical space-separated field parsing, zero-allocation `()` repeat sinks,
//! and shared-keyword `cut_err(alt((...)))` disambiguation.

use winnow::combinator::{alt, cut_err, repeat};
use winnow::error::{ErrMode, ModalResult, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::Stream as _;
use winnow::token::any;

use super::{parse_ident, parse_integer, SpannedToken, TokenKind, TokenStream};

/// Evaluated Layer 3 IP header modifiers (`TTL 64 DSCP 46 ECN 2 DF MF FLOWLABEL 0x12345`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct L3Modifiers {
    /// IPv4 / IPv6 Time-To-Live / Hop Limit (`TTL <u8>`).
    pub ttl: Option<u8>,
    /// Differentiated Services Code Point (`DSCP <u8>`, 6 bits).
    pub dscp: Option<u8>,
    /// Explicit Congestion Notification (`ECN <u8>`, 2 bits).
    pub ecn: Option<u8>,
    /// IPv4 Don't Fragment 0-argument bit flag (`DF`).
    pub df: bool,
    /// IPv4 More Fragments 0-argument bit flag (`MF`).
    pub mf: bool,
    /// 20-bit IPv6 Flow Label (`FLOWLABEL <u32>`).
    pub flow_label: Option<u32>,
}

/// Polymorphic value for a shared keyword (e.g., `TOKEN <u64>` vs `TOKEN "<str>"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedTokenValue<'a> {
    /// Numeric token ID (e.g., CoAP 32-bit token).
    Numeric(u64),
    /// String bearer/session token (e.g., HTTP/Influx token).
    Bearer(&'a str),
}

/// Parses a single canonical space-separated L3 modifier (`<KEYWORD> [<VALUE>]`).
///
/// Rewinds the `TokenStream` checkpoint if the identifier is not an L3 modifier
/// (such as the protocol token `TCP` or `UDP` that follows L3 modifiers).
fn parse_l3_field<'t, 'a>(
    input: &mut TokenStream<'t, 'a>,
    mods: &mut L3Modifiers,
) -> ModalResult<()> {
    let start = input.checkpoint();
    let field_name = parse_ident.parse_next(input)?;

    match field_name {
        "TTL" => {
            let val = cut_err(parse_integer)
                .context(StrContext::Expected(StrContextValue::Description("8-bit TTL (0..=255)")))
                .parse_next(input)?;
            mods.ttl = Some(val as u8);
            Ok(())
        }
        "DSCP" => {
            let val = cut_err(parse_integer)
                .context(StrContext::Expected(StrContextValue::Description("6-bit DSCP (0..=63)")))
                .parse_next(input)?;
            mods.dscp = Some((val & 0x3F) as u8);
            Ok(())
        }
        "ECN" => {
            let val = cut_err(parse_integer)
                .context(StrContext::Expected(StrContextValue::Description("2-bit ECN (0..=3)")))
                .parse_next(input)?;
            mods.ecn = Some((val & 0x03) as u8);
            Ok(())
        }
        "DF" => {
            mods.df = true;
            Ok(())
        }
        "MF" => {
            mods.mf = true;
            Ok(())
        }
        "FLOWLABEL" => {
            let val = cut_err(parse_integer)
                .context(StrContext::Expected(StrContextValue::Description("20-bit Flow Label")))
                .parse_next(input)?;
            mods.flow_label = Some((val & 0x000F_FFFF) as u32);
            Ok(())
        }
        _ => {
            input.reset(&start);
            Err(ErrMode::from_input(input))
        }
    }
}

/// Parses a sequence of space-separated L3 modifiers using a zero-allocation `()` repeat sink.
pub fn parse_l3_modifiers<'t, 'a>(input: &mut TokenStream<'t, 'a>) -> ModalResult<L3Modifiers> {
    let mut mods = L3Modifiers::default();
    // Bind to `()` (`Accumulate<()>`) so `repeat` performs zero heap allocations!
    let (): () = repeat(0.., |s: &mut TokenStream<'t, 'a>| parse_l3_field(s, &mut mods))
        .parse_next(input)?;
    Ok(mods)
}

/// Parses a shared keyword (`TOKEN <int>` or `TOKEN "<str>"`) safely by placing `alt`
/// *inside* a single `cut_err` after consuming the keyword token once.
pub fn parse_shared_token_modifier<'t, 'a>(
    input: &mut TokenStream<'t, 'a>,
) -> ModalResult<SharedTokenValue<'a>> {
    let start = input.checkpoint();
    let kw = parse_ident.parse_next(input)?;
    if kw != "TOKEN" {
        input.reset(&start);
        return Err(ErrMode::from_input(input));
    }

    let parse_str_lit = any.verify_map(|t: &SpannedToken<'a>| match t.kind {
        TokenKind::StringLiteral(s) => Some(SharedTokenValue::Bearer(s)),
        _ => None,
    });

    cut_err(alt((
        parse_integer.map(SharedTokenValue::Numeric),
        parse_str_lit,
    )))
    .context(StrContext::Label("TOKEN modifier"))
    .context(StrContext::Expected(StrContextValue::Description(
        "integer token ID or quoted string token",
    )))
    .parse_next(input)
}
```

---

## 4. Built-In Pratt Precedence Climbing Expression Parser (`combinator::expression`)

`winnow::combinator::expression` provides $O(1)$ operator precedence climbing with prefix, postfix, and infix associativity control:

```rust
//! Pratt expression parser for filter conditions and arithmetic offsets.

use winnow::ascii::{digit1, space0};
use winnow::combinator::{
    cut_err, delimited, dispatch, expression, fail, peek, Empty, Infix, Postfix, Prefix,
};
use winnow::error::{ContextError, ModalResult, StrContext};
use winnow::prelude::*;
use winnow::token::{any, take};

/// Evaluated expression AST node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Literal integer scalar.
    Val(i64),
    /// Variable identifier reference.
    Var(String),
    /// Arithmetic negation `-x`.
    Neg(Box<Expr>),
    /// Factorial postfix `x!`.
    Factorial(Box<Expr>),
    /// Addition `x + y`.
    Add(Box<Expr>, Box<Expr>),
    /// Subtraction `x - y`.
    Sub(Box<Expr>, Box<Expr>),
    /// Multiplication `x * y`.
    Mul(Box<Expr>, Box<Expr>),
    /// Division `x / y`.
    Div(Box<Expr>, Box<Expr>),
    /// Exponentiation `x ** y` (right-associative).
    Pow(Box<Expr>, Box<Expr>),
    /// Equality comparison `x == y` (non-associative).
    Eq(Box<Expr>, Box<Expr>),
}

/// Parses an expression using Pratt precedence climbing.
///
/// # Arguments
/// * `input` - Input text stream.
///
/// # Returns
/// Constructed AST expression tree.
pub fn parse_expr<'i>(input: &mut &'i str) -> ModalResult<Expr> {
    expression(delimited(
        space0,
        dispatch! { peek(any);
            '(' => delimited('(', cut_err(parse_expr), cut_err(')')),
            '0'..='9' => digit1.parse_to::<i64>().map(Expr::Val),
            _ => fail.context(StrContext::Label("operand")),
        },
        space0,
    ))
    .current_precedence_level(0)
    .prefix(delimited(
        space0,
        dispatch! { any;
            '-' => Prefix(12, |_: &mut &str, a| Ok(Expr::Neg(Box::new(a)))),
            '+' => Prefix(12, |_: &mut &str, a| Ok(a)),
            _ => fail,
        },
        space0,
    ))
    .postfix(delimited(
        space0,
        dispatch! { any;
            '!' => Postfix(15, |_: &mut &str, a| Ok(Expr::Factorial(Box::new(a)))),
            _ => fail,
        },
        space0,
    ))
    .infix(delimited(
        space0,
        dispatch! { any;
            '=' => '='.value(Infix::Neither(2, |_: &mut &str, a, b| Ok(Expr::Eq(Box::new(a), Box::new(b))))),
            '+' => Empty.value(Infix::Left(5, |_: &mut &str, a, b| Ok(Expr::Add(Box::new(a), Box::new(b))))),
            '-' => Empty.value(Infix::Left(5, |_: &mut &str, a, b| Ok(Expr::Sub(Box::new(a), Box::new(b))))),
            '*' => dispatch! { peek(any);
                '*' => '*'.value(Infix::Right(14, |_: &mut &str, a, b| Ok(Expr::Pow(Box::new(a), Box::new(b))))),
                _ => Empty.value(Infix::Left(7, |_: &mut &str, a, b| Ok(Expr::Mul(Box::new(a), Box::new(b))))),
            },
            '/' => Empty.value(Infix::Left(7, |_: &mut &str, a, b| Ok(Expr::Div(Box::new(a), Box::new(b))))),
            _ => fail,
        },
        space0,
    ))
    .parse_next(input)
}
```

---

## 5. Zero-Copy String Unescaping & Hex Byte Stream Decoding

Extracts strings without heap allocation when no escape sequences are present (`Cow::Borrowed`), falling back to `Cow::Owned` only when escapes or hex sequences (`\xHH`) are encountered.

```rust
//! High-performance string and payload unescaper.

use std::borrow::Cow;
use winnow::combinator::{cut_err, delimited, dispatch, empty, fail, opt};
use winnow::error::{ModalResult, StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::token::{any, take, take_till, take_while};

/// Parses a quoted string literal into a `Cow<'i, str>`.
///
/// Fast-paths unescaped strings directly to `Cow::Borrowed(&'i str)` with zero allocations.
///
/// # Arguments
/// * `input` - Mutable string slice stream.
///
/// # Returns
/// Unescaped string content.
pub fn parse_quoted_string<'i>(input: &mut &'i str) -> ModalResult<Cow<'i, str>> {
    let _ = '"'.parse_next(input)?;
    let first_literal = take_till(0.., ['"', '\\']).parse_next(input)?;

    // Fast path: Closing quote follows immediately without any escape characters
    if opt('"').parse_next(input)?.is_some() {
        return Ok(Cow::Borrowed(first_literal));
    }

    // Slow path: Contains escape sequences, allocate String buffer
    let mut owned = String::from(first_literal);
    loop {
        dispatch! { any;
            '"' => return Ok(Cow::Owned(owned)),
            '\\' => {
                let esc = cut_err(parse_escape_char)
                    .context(StrContext::Label("escape sequence"))
                    .parse_next(input)?;
                owned.push(esc);
            }
            _ => unreachable!("take_till stopped at quote or backslash"),
        }
        .parse_next(input)?;

        let chunk = take_till(0.., ['"', '\\']).parse_next(input)?;
        owned.push_str(chunk);
    }
}

/// Parses an escape character following a backslash `\`.
fn parse_escape_char(input: &mut &str) -> ModalResult<char> {
    dispatch! { any;
        '"' => empty.value('"'),
        '\\' => empty.value('\\'),
        'n' => empty.value('\n'),
        'r' => empty.value('\r'),
        't' => empty.value('\t'),
        '0' => empty.value('\0'),
        'x' => {
            take(2usize)
                .verify_map(|hex| u8::from_str_radix(hex, 16).ok().map(|b| b as char))
                .context(StrContext::Expected(StrContextValue::Description("2-digit hex escape (\\xHH)")))
        },
        'u' => delimited(
            '{',
            take_while(1..=6, ('0'..='9', 'a'..='f', 'A'..='F'))
                .verify_map(|hex| u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)),
            '}',
        ),
        _ => fail.context(StrContext::Expected(StrContextValue::Description("valid escape character"))),
    }
    .parse_next(input)
}

/// Parses a raw hex payload string (e.g., `HEX: "01020304aabbcc"`) into a byte vector.
///
/// # Arguments
/// * `input` - Mutable string slice stream.
///
/// # Returns
/// Decoded binary byte vector.
pub fn parse_hex_payload(input: &mut &str) -> ModalResult<Vec<u8>> {
    let _ = '"'.parse_next(input)?;
    let hex_str = take_till(0.., '"').parse_next(input)?;
    let _ = cut_err('"').parse_next(input)?;

    let clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err(winnow::error::ErrMode::from_input(input));
    }

    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| winnow::error::ErrMode::from_input(input))?;
        bytes.push(byte);
    }
    Ok(bytes)
}
```

---

## 6. Stateful Recursion Tracking & Symbol Interning (`Stateful<LocatingSlice<I>, State>`)

Passes execution state through combinators without interior mutability or thread-locals:

```rust
//! Stateful recursion and scope tracking.

use core::ops::Range;
use std::collections::HashMap;
use winnow::combinator::{cut_err, delimited, dispatch, fail, peek};
use winnow::error::{ContextError, ErrMode, ModalResult};
use winnow::prelude::*;
use winnow::stream::{LocatingSlice, Stateful};
use winnow::token::{any, take_while};

/// Mutable compilation context threaded through winnow parsers.
#[derive(Debug, Default)]
pub struct CompilerState {
    /// Current block recursion depth.
    pub recursion_depth: usize,
    /// Maximum permitted recursion depth to guard against stack overflows.
    pub max_depth: usize,
    /// Interned symbol table mapping names to unique IDs.
    pub symbol_table: HashMap<String, u32>,
    /// Monotonically increasing symbol counter.
    pub next_symbol_id: u32,
}

impl CompilerState {
    /// Creates a new compiler state with a depth limit.
    pub fn new(max_depth: usize) -> Self {
        Self {
            recursion_depth: 0,
            max_depth,
            symbol_table: HashMap::new(),
            next_symbol_id: 1,
        }
    }

    /// Interns an identifier string into a unique symbol ID.
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.symbol_table.get(name) {
            id
        } else {
            let id = self.next_symbol_id;
            self.next_symbol_id += 1;
            self.symbol_table.insert(name.to_string(), id);
            id
        }
    }
}

/// Rich stream combining byte span tracking and stateful context.
pub type ContextStream<'i> = Stateful<LocatingSlice<&'i str>, CompilerState>;

/// Parses a nested block while enforcing strict depth limits.
///
/// # Arguments
/// * `input` - Contextual stream.
///
/// # Returns
/// Interned block ID and source span.
pub fn parse_nested_block<'i>(
    input: &mut ContextStream<'i>,
) -> ModalResult<(u32, Range<usize>)> {
    dispatch! { peek(any);
        '{' => {
            if input.state.recursion_depth >= input.state.max_depth {
                return Err(ErrMode::Cut(ContextError::from_input(input)));
            }
            input.state.recursion_depth += 1;
            let res = delimited('{', parse_nested_block, cut_err('}'))
                .with_span()
                .map(|((id, _), span)| (id, span))
                .parse_next(input);
            input.state.recursion_depth -= 1;
            res
        }
        'a'..='z' | 'A'..='Z' => {
            let name = take_while(1.., ('a'..='z', 'A'..='Z', '0'..='9', '_'))
                .parse_next(input)?;
            let id = input.state.intern(name);
            let span = input.span();
            Ok((id, span))
        }
        _ => fail.parse_next(input),
    }
}
```

---

## 7. Binary TLV, Bitfields & Packet Dissection (`length_and_then`, `binary::bits`)

Decodes network packet headers with sub-byte field packing using `winnow::binary::bits`:

```rust
//! Binary packet and TLV stream parser.

use winnow::binary::bits::{bits, take as take_bits};
use winnow::binary::{be_u16, be_u32, length_and_then, u8};
use winnow::combinator::seq;
use winnow::error::{ContextError, ErrMode, ModalResult};
use winnow::prelude::*;
use winnow::token::rest;
use winnow::Bytes;

/// Dissected IPv4-style header structure.
#[derive(Debug, PartialEq, Eq)]
pub struct DissectedHeader<'i> {
    /// 4-bit IP version.
    pub version: u8,
    /// 4-bit Internet Header Length (IHL in 32-bit words).
    pub ihl: u8,
    /// 6-bit DSCP field.
    pub dscp: u8,
    /// 2-bit ECN field.
    pub ecn: u8,
    /// 16-bit total length in bytes.
    pub total_length: u16,
    /// Borrowed payload slice.
    pub payload: &'i [u8],
}

/// Parses a binary packet header and extracts the length-delimited payload.
///
/// # Arguments
/// * `input` - Borrowed binary byte stream.
///
/// # Returns
/// Dissected packet header.
pub fn parse_binary_header<'i>(input: &mut &'i Bytes) -> ModalResult<DissectedHeader<'i>> {
    seq!(DissectedHeader {
        (version, ihl): bits::<_, _, ErrMode<ContextError>, _, _>((
            take_bits(4usize),
            take_bits(4usize),
        )),
        (dscp, ecn): bits::<_, _, ErrMode<ContextError>, _, _>((
            take_bits(6usize),
            take_bits(2usize),
        )),
        total_length: be_u16,
        payload: length_and_then(be_u16, rest),
    })
    .parse_next(input)
}
```

---

## 8. Rich Diagnostic Integration with `miette`

Converts winnow parsing errors directly into rich, color-rendered `miette::Diagnostic` reports:

```rust
//! Bridge converting winnow parsing errors into miette diagnostics.

use core::ops::Range;
use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;
use winnow::error::{ContextError, ParseError};

/// Diagnostic compiler error emitted when syntax parsing fails.
#[derive(Debug, Error, Diagnostic)]
#[error("Syntax error: {message}")]
#[diagnostic(code(frameassembly::parse_error), help("Verify DSL statement syntax"))]
pub struct CompilerParseError {
    /// Descriptive error message.
    pub message: String,
    /// Source file content for rendering snippets.
    #[source_code]
    pub src: NamedSource<String>,
    /// Primary error span highlighted with carets.
    #[label(primary, "Unexpected token or grammar violation")]
    pub span: SourceSpan,
}

impl CompilerParseError {
    /// Constructs a `CompilerParseError` from a winnow `ParseError`.
    ///
    /// # Arguments
    /// * `filename` - Name of the source file.
    /// * `source_text` - Full UTF-8 content of the source file.
    /// * `err` - Parse error produced by `Parser::parse`.
    pub fn from_winnow(
        filename: &str,
        source_text: &str,
        err: ParseError<&str, ContextError>,
    ) -> Self {
        let offset = err.offset();
        let span = SourceSpan::from((offset, 1));
        Self {
            message: format!("Parse failure at byte offset {offset}"),
            src: NamedSource::new(filename, source_text.to_string()).with_language("fasm"),
            span,
        }
    }
}
```
