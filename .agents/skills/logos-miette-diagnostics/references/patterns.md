# Logos 0.14+ & Miette 7.6+ Production Reference Patterns

## 1. Two-Phase Lexing & Diagnostic Pipeline (`logos` + `TokenSlice` + `Location` + `ContainsToken` + `miette`)

When building compilers, language frontends, or network DSLs, combine `logos` for $O(1)$ SIMD lexing and `winnow` for grammar parsing over `TokenSlice`. Implement `Location`, `PartialEq<TokenKind>`, and `ContainsToken` on your spanned token wrapper to unlock native combinators (`literal`, `one_of`, `.span()`, `.with_span()`), then map token offsets directly into `miette::Diagnostic` error frames.

```rust
//! Complete two-phase compiler pipeline: `logos` -> `winnow` -> `miette`.

use core::ops::Range;
use logos::Logos;
use miette::{Diagnostic, GraphicalReportHandler, NamedSource, SourceSpan};
use winnow::combinator::{cut_err, opt, seq};
use winnow::error::{StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::{ContainsToken, Location, TokenSlice};
use winnow::token::{any, literal};

/// Lexer token kinds recognized by `logos 0.14.4`.
///
/// Exact `logos-codegen 0.14.4` default priority formula (`Mir::priority`):
/// - `#[token("...")]`: `2 * bytes.len()` (`"s"` = 2, `"let"` = 6)
/// - `Mir::Class(_)` (`[a-z]`, `[0-9]`): `2` per required class
/// - `Mir::Loop(_)` (`*`, repeating tail of `+`) and `Mir::Maybe(_)` (`?`): `0`
/// Because `Ident` (`[a-zA-Z_][a-zA-Z0-9_]*`) has default priority `2 + 0 = 2`,
/// it ties with 1-byte tokens (`#[token("s")]`, priority `2`) unless given `priority = 1`.
/// Similarly, `OidStr` (`\.?[0-9]+(\.[0-9]+)*`, default `0 + 2 + 0 = 2`) ties with
/// `Int` (`[0-9]+`, default `2`) unless given `priority = 3`.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
#[logos(skip r"[ \t\r\n\f]+")]
#[logos(skip r"//[^\r\n]*")]
pub enum TokenKind<'s> {
    /// Keyword `let` (default priority = 6)
    #[token("let")]
    Let,
    /// Keyword `mut` (default priority = 6)
    #[token("mut")]
    Mut,
    /// Single-character unit token `s` (default priority = 2; outranks `Ident` priority = 1)
    #[token("s")]
    UnitSeconds,
    /// Equals sign `=`
    #[token("=")]
    Equals,
    /// Semicolon `;`
    #[token(";")]
    Semi,
    /// Plus operator `+`
    #[token("+")]
    Plus,
    /// Minus operator `-`
    #[token("-")]
    Minus,
    /// Dotted ASN.1 OID literal (explicit `priority = 3` outranks `Int` default priority `2`)
    #[regex(r"\.?[0-9]+(\.[0-9]+)+", priority = 3)]
    OidStr(&'s str),
    /// Generic identifier (explicit `priority = 1` yields to 1-char keywords like `"s"`)
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", priority = 1)]
    Ident(&'s str),
    /// Integer literal (`Mir::Class([0-9])` + `Mir::Loop` = `2 + 0 = 2`)
    #[regex(r"[0-9]+", priority = 2)]
    Int(&'s str),
}

/// Token paired with its byte span in the original source code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpannedToken<'s> {
    /// Token category
    pub kind: TokenKind<'s>,
    /// Byte range `start..end` in original source
    pub span: Range<usize>,
}

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

impl<'s> PartialEq<TokenKind<'s>> for SpannedToken<'s> {
    #[inline(always)]
    fn eq(&self, other: &TokenKind<'s>) -> bool {
        self.kind == *other
    }
}

impl<'t, 's> ContainsToken<&'t SpannedToken<'s>> for TokenKind<'s> {
    #[inline(always)]
    fn contains_token(&self, token: &'t SpannedToken<'s>) -> bool {
        *self == token.kind
    }
}

impl<'t, 's, const N: usize> ContainsToken<&'t SpannedToken<'s>> for [TokenKind<'s>; N] {
    #[inline(always)]
    fn contains_token(&self, token: &'t SpannedToken<'s>) -> bool {
        self.contains(&token.kind)
    }
}

/// Stream alias for winnow parsers consuming pre-lexed tokens.
pub type Stream<'t, 's> = TokenSlice<'t, SpannedToken<'s>>;

/// AST statement node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LetStatement<'s> {
    /// Variable identifier
    pub name: &'s str,
    /// Mutable flag
    pub is_mut: bool,
    /// Assigned integer value
    pub value: i64,
    /// Source span of the entire statement
    pub span: Range<usize>,
}

/// Rich compilation error rendered by miette.
#[derive(Diagnostic, Debug)]
#[diagnostic(code(compiler::syntax_error), help("Verify grammar and syntax rules."))]
pub struct SpannedCompilerError {
    /// Formatted message
    pub message: String,
    /// Named source file and content
    #[source_code]
    pub src: NamedSource<String>,
    /// Underlined span in source
    #[label("{label}")]
    pub span: SourceSpan,
    /// Span label text
    pub label: String,
}

impl core::fmt::Display for SpannedCompilerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SpannedCompilerError {}

/// Parse identifier token.
pub fn parse_ident<'t, 's>(input: &mut Stream<'t, 's>) -> ModalResult<&'s str> {
    any.verify_map(|t: &SpannedToken<'s>| match t.kind {
        TokenKind::Ident(s) => Some(s),
        _ => None,
    })
    .context(StrContext::Expected(StrContextValue::Description("variable identifier")))
    .parse_next(input)
}

/// Parse integer token.
pub fn parse_int<'t, 's>(input: &mut Stream<'t, 's>) -> ModalResult<i64> {
    any.verify_map(|t: &SpannedToken<'s>| match t.kind {
        TokenKind::Int(s) => s.parse::<i64>().ok(),
        _ => None,
    })
    .context(StrContext::Expected(StrContextValue::Description("integer literal")))
    .parse_next(input)
}

/// Parse `let [mut] <ident> = <int>;` statement with exact byte span capture.
pub fn parse_let<'t, 's>(input: &mut Stream<'t, 's>) -> ModalResult<LetStatement<'s>> {
    seq!(
        _: literal(TokenKind::Let),
        opt(literal(TokenKind::Mut)).map(|m| m.is_some()),
        cut_err(parse_ident),
        _: cut_err(literal(TokenKind::Equals))
            .context(StrContext::Expected(StrContextValue::CharLiteral('='))),
        cut_err(parse_int),
        _: cut_err(literal(TokenKind::Semi))
            .context(StrContext::Expected(StrContextValue::CharLiteral(';'))),
    )
    .with_span()
    .map(|((is_mut, name, value), span)| LetStatement {
        name,
        is_mut,
        value,
        span,
    })
    .context(StrContext::Label("let binding statement"))
    .parse_next(input)
}

/// Full execution pipeline: lex -> parse -> convert error to miette diagnostic.
pub fn compile_pipeline<'s>(
    filename: &str,
    source: &'s str,
) -> Result<LetStatement<'s>, SpannedCompilerError> {
    // Stage 1: Lexing
    let mut lexer = TokenKind::lexer(source);
    let mut tokens = Vec::new();

    while let Some(res) = lexer.next() {
        match res {
            Ok(kind) => tokens.push(SpannedToken {
                kind,
                span: lexer.span(),
            }),
            Err(_) => {
                let span = lexer.span();
                return Err(SpannedCompilerError {
                    message: "Lexical analysis failed: unrecognized token".to_string(),
                    src: NamedSource::new(filename, source.to_string()),
                    span: SourceSpan::from(span),
                    label: "Invalid token here".to_string(),
                });
            }
        }
    }

    // Stage 2: Parsing via TokenSlice
    let stream = TokenSlice::new(&tokens);
    match parse_let.parse(stream) {
        Ok(stmt) => Ok(stmt),
        Err(err) => {
            // Stage 3: Error span mapping & miette diagnostic synthesis
            let token_idx = err.offset();
            let span = if token_idx < tokens.len() {
                tokens[token_idx].span.clone()
            } else if let Some(last) = tokens.last() {
                last.span.end..last.span.end
            } else {
                0..0
            };

            let expected_desc = err
                .inner()
                .context()
                .filter_map(|ctx| match ctx {
                    StrContext::Expected(exp) => Some(exp.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(", ");

            let label = if expected_desc.is_empty() {
                "Syntax error here".to_string()
            } else {
                format!("Expected {}", expected_desc)
            };

            Err(SpannedCompilerError {
                message: format!("Parsing error: {}", err.inner()),
                src: NamedSource::new(filename, source.to_string()),
                span: SourceSpan::from(span),
                label,
            })
        }
    }
}

/// Render a diagnostic to string using GraphicalReportHandler.
pub fn render_diagnostic_report(diag: &SpannedCompilerError) -> String {
    let handler = GraphicalReportHandler::default();
    let mut buf = String::new();
    let _ = handler.render_report(&mut buf, diag);
    buf
}
```

---

## 2. Advanced Logos State, Extras, Subpatterns & Lexer Morphing

Use `#[logos(subpattern)]` to eliminate duplicate regexes, `#[logos(extras = S)]` to track nesting or comment metrics, `FilterResult` to conditionally accept or reject tokens, and `lexer.morph::<T>()` to switch lexer modes when entering embedded sub-dialects (such as template strings or documentation blocks).

```rust
//! Advanced Logos state, extras, subpatterns, filter results, and multi-dialect lexer morphing.

use logos::{FilterResult, Lexer, Logos};

/// Custom error emitted when lexical analysis fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LexError {
    /// Generic invalid or unrecognized token
    #[default]
    InvalidToken,
    /// Unclosed delimited string literal or block
    UnclosedBlock,
    /// Invalid numeric or hexadecimal literal format
    InvalidLiteral,
}

/// Persistent state threaded through the lexer via `extras`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LexerState {
    /// Current nesting depth of braces
    pub brace_depth: usize,
    /// Total count of comments processed
    pub comment_count: usize,
}

/// Convenience alias for callback filter results.
pub type LexFilter = FilterResult<(), LexError>;

/// Primary code token enum with subpatterns and stateful extras.
#[derive(Logos, Clone, Debug, PartialEq, Eq)]
#[logos(extras = LexerState)]
#[logos(error = LexError)]
#[logos(skip r"[ \t\n\f\r]+")]
#[logos(subpattern hex_digit = r"[0-9a-fA-F]")]
#[logos(subpattern hex_byte = r"(?&hex_digit){2}")]
#[logos(subpattern ident = r"[a-zA-Z_][a-zA-Z0-9_]*")]
pub enum MainToken<'s> {
    /// Keyword `func`
    #[token("func", priority = 10)]
    Func,
    /// Keyword `return`
    #[token("return", priority = 10)]
    Return,
    /// Identifier matching named subpattern
    #[regex(r"(?&ident)", |lex| lex.slice(), priority = 1)]
    Ident(&'s str),
    /// Hexadecimal byte sequence (e.g. `0x1A2B`)
    #[regex(r"0x(?&hex_byte)+", |lex| lex.slice(), priority = 5)]
    HexBytes(&'s str),
    /// Left curly brace `{` (tracks nesting depth)
    #[token("{", |lex| {
        lex.extras.brace_depth += 1;
        LexFilter::Emit(())
    })]
    OpenBrace,
    /// Right curly brace `}` (tracks nesting depth)
    #[token("}", |lex| {
        if lex.extras.brace_depth > 0 {
            lex.extras.brace_depth -= 1;
            LexFilter::Emit(())
        } else {
            LexFilter::Error(LexError::UnclosedBlock)
        }
    })]
    CloseBrace,
    /// Opening quote of an interpolated string template
    #[token("f\"", priority = 10)]
    InterpolatedStringStart,
    /// Line comment counted via logos::Skip
    #[regex(r"//[^\r\n]*", |lex| {
        lex.extras.comment_count += 1;
        logos::Skip
    })]
    Comment,
}

/// Specialized token enum for lexing the contents of interpolated strings.
#[derive(Logos, Clone, Debug, PartialEq, Eq)]
#[logos(extras = LexerState)]
#[logos(error = LexError)]
pub enum TemplateToken<'s> {
    /// Raw string text chunk within template
    #[regex(r#"([^"\\{}]|\\.)+"#, |lex| lex.slice(), priority = 1)]
    Text(&'s str),
    /// Interpolated expression delimiter `{`
    #[token("{", priority = 5)]
    ExprStart,
    /// Interpolated expression closing delimiter `}`
    #[token("}", priority = 5)]
    ExprEnd,
    /// Closing quote of the template string
    #[token("\"", priority = 10)]
    StringEnd,
}

/// Token stream item produced by the multi-dialect lexer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CombinedToken<'s> {
    /// Regular code token
    Main(MainToken<'s>),
    /// Literal text chunk inside template string
    TemplateText(&'s str),
    /// Embedded expression start marker inside template
    TemplateExprOpen,
    /// Embedded expression end marker inside template
    TemplateExprClose,
}

/// Lex a mixed input string containing code and string interpolation via morphing.
pub fn lex_with_morphing<'s>(source: &'s str) -> Result<Vec<CombinedToken<'s>>, LexError> {
    let mut lexer = MainToken::lexer(source);
    let mut output = Vec::new();

    while let Some(res) = lexer.next() {
        match res? {
            MainToken::InterpolatedStringStart => {
                // Morph into template lexer while preserving input position & extras
                let mut template_lexer: Lexer<'s, TemplateToken<'s>> = lexer.morph();
                let mut string_closed = false;

                while let Some(tpl_res) = template_lexer.next() {
                    match tpl_res? {
                        TemplateToken::Text(txt) => {
                            output.push(CombinedToken::TemplateText(txt));
                        }
                        TemplateToken::ExprStart => {
                            output.push(CombinedToken::TemplateExprOpen);
                        }
                        TemplateToken::ExprEnd => {
                            output.push(CombinedToken::TemplateExprClose);
                        }
                        TemplateToken::StringEnd => {
                            string_closed = true;
                            break;
                        }
                    }
                }

                if !string_closed {
                    return Err(LexError::UnclosedBlock);
                }

                // Morph back into main code lexer
                lexer = template_lexer.morph();
            }
            token => output.push(CombinedToken::Main(token)),
        }
    }

    Ok(output)
}
```

---

## 3. Rich Multi-Span Diagnostics, Collections, Forwarding & Deterministic CI Snapshot Testing

Construct rich, expressive diagnostics with `#[derive(Diagnostic)]` in `miette 7.6.0`. Demonstrate primary caret labels (`#[label(primary, "...")]`), contextual declaration labels (`#[label("...")]`), multi-span dynamic collections (`#[label(collection, "...")]`), `#[diagnostic(forward(field))]`, `#[diagnostic_source]`, `LabeledSpan::at_offset`, `SourceOffset::from_location`, and deterministic CI snapshot rendering via `GraphicalTheme::unicode_nocolor()`.

```rust
//! Rich multi-span diagnostics, collections, forwarding, and deterministic CI report rendering in `miette 7.6.0`.

use miette::{
    Diagnostic, GraphicalReportHandler, GraphicalTheme, JSONReportHandler, LabeledSpan,
    NamedSource, NarratableReportHandler, SourceOffset, SourceSpan,
};

/// Primary error representing an incompatible type assignment.
#[derive(Diagnostic, Debug)]
#[diagnostic(
    code(compiler::type_mismatch),
    help("Ensure variable assignments match the inferred or declared type."),
    url(docsrs)
)]
pub struct TypeMismatchError {
    /// Formatted error description
    pub message: String,
    /// Expected type name
    pub expected: String,
    /// Actual encountered type name
    pub found: String,
    /// Associated source file code frame
    #[source_code]
    pub src: NamedSource<String>,
    /// Primary underline marking the offending assignment
    #[label(primary, "expected `{expected}`, but found `{found}`")]
    pub assignment_span: SourceSpan,
    /// Contextual underline marking where the variable was first declared
    #[label("variable original declaration here")]
    pub declaration_span: SourceSpan,
    /// Collection of related or previous assignment spans
    #[label(collection, "prior incompatible assignments")]
    pub prior_assignments: Vec<SourceSpan>,
}

impl core::fmt::Display for TypeMismatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TypeMismatchError {}

/// Wrapper diagnostic demonstrating `#[diagnostic(forward(inner))]` and `#[diagnostic_source]`.
#[derive(Diagnostic, Debug)]
#[diagnostic(code(compiler::module_failure), forward(inner))]
pub struct ModuleCompilationError {
    /// Module name where compilation failed
    pub module_name: String,
    /// Inner diagnostic whose `source_code` and `labels` are forwarded automatically
    #[diagnostic_source]
    pub inner: TypeMismatchError,
}

impl core::fmt::Display for ModuleCompilationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "in module `{}`: {}", self.module_name, self.inner)
    }
}

impl std::error::Error for ModuleCompilationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

/// Top-level compilation diagnostic aggregating multiple related errors and warnings.
#[derive(Diagnostic, Debug)]
#[diagnostic(code(compiler::batch_failure))]
pub struct BatchCompilationError {
    /// Error summary message
    pub summary: String,
    /// Shared source frame
    #[source_code]
    pub src: NamedSource<String>,
    /// List of related type mismatch errors
    #[related]
    pub type_errors: Vec<TypeMismatchError>,
    /// Dynamic help advice
    #[help]
    pub advice: Option<String>,
}

impl core::fmt::Display for BatchCompilationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.summary)
    }
}

impl std::error::Error for BatchCompilationError {}

/// Helper constructing an EOF caret label or a 1-indexed `(line, column)` span.
pub fn build_eof_or_line_col_spans(source: &str, line: usize, col: usize) -> (LabeledSpan, SourceSpan) {
    let eof_caret = LabeledSpan::at_offset(source.len(), "unexpected end of input");
    let offset = SourceOffset::from_location(source, line, col);
    let point_span = SourceSpan::from((offset.offset(), 1usize));
    (eof_caret, point_span)
}

/// Renders a diagnostic deterministically for CI snapshot tests (`unicode_nocolor`, 80 cols, no OSC-8 links).
pub fn render_deterministic_snapshot<D: Diagnostic>(diagnostic: &D) -> String {
    let handler = GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor())
        .with_width(80)
        .with_links(false)
        .with_context_lines(2);
    let mut output = String::new();
    handler
        .render_report(&mut output, diagnostic)
        .expect("rendering to String is infallible");
    output
}

/// Renders a diagnostic as structured JSON (for IDE/LSP integration) or narratable plain text.
pub fn render_json_and_narratable<D: Diagnostic>(diagnostic: &D) -> (String, String) {
    let mut json_buf = String::new();
    JSONReportHandler::new()
        .render_report(&mut json_buf, diagnostic)
        .expect("infallible String fmt");

    let mut text_buf = String::new();
    NarratableReportHandler::new()
        .render_report(&mut text_buf, diagnostic)
        .expect("infallible String fmt");

    (json_buf, text_buf)
}
```

---

## 4. Byte-Stream & Binary Protocol Lexing with Spanned Diagnostics

When parsing binary packets, network frames, or file headers, configure `logos` to tokenize over raw byte slices `&[u8]` using `#[logos(source = [u8])]`. Format byte offsets cleanly into hex-dumped `miette` source frames.

```rust
//! Binary protocol and byte-stream lexing with spanned diagnostics using `#[logos(source = [u8])]`.

use core::ops::Range;
use logos::Logos;
use miette::{Diagnostic, NamedSource, SourceSpan};

/// Binary error emitted when parsing raw packet frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BinaryLexError {
    /// Generic invalid or malformed packet byte sequence
    #[default]
    MalformedHeader,
    /// Unexpected EOF before packet payload completed
    UnexpectedEof,
}

/// Binary packet tokens lexed over raw byte slices `&[u8]`.
#[derive(Logos, Clone, Debug, PartialEq, Eq)]
#[logos(source = [u8])]
#[logos(error = BinaryLexError)]
pub enum PacketToken<'s> {
    /// Frame preamble / magic bytes `b"FASM"`
    #[token(b"FASM", priority = 10)]
    Preamble,
    /// Type-Length-Value header tag for IPv4 payload
    #[token(b"\x08\x00", priority = 5)]
    EtherTypeIpv4,
    /// Type-Length-Value header tag for IPv6 payload
    #[token(b"\x86\xDD", priority = 5)]
    EtherTypeIpv6,
    /// Type-Length-Value header tag for 802.1Q VLAN tag
    #[token(b"\x81\x00", priority = 5)]
    EtherTypeVlan,
    /// Delimiter byte separating packet sections (`0x00`)
    #[token(b"\x00")]
    NullDelimiter,
    /// Raw uninterpreted byte payload
    #[regex(b"[\x01-\xFF]+", |lex| lex.slice(), priority = 1)]
    Payload(&'s [u8]),
}

/// Token paired with its byte range in the raw packet buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpannedBinaryToken<'s> {
    /// Discriminated binary token variant
    pub kind: PacketToken<'s>,
    /// Byte offset range `start..end` in the raw buffer
    pub span: Range<usize>,
}

/// Rich diagnostic error reporting wire parsing failures on binary streams.
#[derive(Diagnostic, Debug)]
#[diagnostic(
    code(wire::binary_framing_error),
    help("Verify packet header structure and protocol alignment.")
)]
pub struct BinaryPacketError {
    /// Error message detailing the failure
    pub message: String,
    /// Formatted hex dump representation of the packet
    #[source_code]
    pub hex_dump: NamedSource<String>,
    /// Offending byte range mapped into the hex dump
    #[label("malformed wire sequence here")]
    pub span: SourceSpan,
}

impl core::fmt::Display for BinaryPacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BinaryPacketError {}

/// Lex a raw byte buffer into spanned binary tokens.
pub fn lex_binary_packet<'s>(
    packet_name: &str,
    bytes: &'s [u8],
) -> Result<Vec<SpannedBinaryToken<'s>>, BinaryPacketError> {
    let mut lexer = PacketToken::lexer(bytes);
    let mut tokens = Vec::new();

    while let Some(res) = lexer.next() {
        match res {
            Ok(kind) => tokens.push(SpannedBinaryToken {
                kind,
                span: lexer.span(),
            }),
            Err(_) => {
                let span = lexer.span();
                // Render bytes as a readable hex dump string for diagnostic source display
                let hex_repr: String = bytes
                    .iter()
                    .map(|b| format!("{:02X} ", b))
                    .collect();

                // Map byte span into character offset in the hex string (each byte is 3 chars: "XX ")
                let char_start = span.start * 3;
                let char_len = (span.end - span.start) * 3;

                return Err(BinaryPacketError {
                    message: format!(
                        "Invalid binary packet token at byte offset {}..{}",
                        span.start, span.end
                    ),
                    hex_dump: NamedSource::new(packet_name, hex_repr),
                    span: SourceSpan::from((char_start, char_len)),
                });
            }
        }
    }

    Ok(tokens)
}
```

---

## 5. Pratt Operator Precedence Expression Parsing with Lexed Tokens & Error Diagnostics

Feed a pre-lexed token stream into `winnow::combinator::expression` to construct an operator-precedence parser with prefix, postfix, and infix associativity. Wrap syntax errors with exact token byte ranges and descriptive `miette` diagnostic frames.

```rust
//! Pratt operator precedence expression parsing over pre-lexed `logos` tokens with `miette` diagnostics.

use core::ops::Range;
use logos::Logos;
use miette::{Diagnostic, NamedSource, SourceSpan};
use winnow::combinator::{cut_err, delimited, dispatch, empty, expression, fail, peek, Infix, Postfix, Prefix};
use winnow::error::{StrContext, StrContextValue};
use winnow::prelude::*;
use winnow::stream::{ContainsToken, Location, TokenSlice};
use winnow::token::{any, literal};

/// Arithmetic and expression tokens recognized by logos.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
#[logos(skip r"[ \t\n\f\r]+")]
pub enum ExprToken<'s> {
    /// Integer literal
    #[regex(r"[0-9]+", |lex| lex.slice(), priority = 2)]
    Number(&'s str),
    /// Variable identifier
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice(), priority = 1)]
    Ident(&'s str),
    /// Addition operator `+`
    #[token("+")]
    Plus,
    /// Subtraction or negation operator `-`
    #[token("-")]
    Minus,
    /// Multiplication operator `*`
    #[token("*")]
    Star,
    /// Division operator `/`
    #[token("/")]
    Slash,
    /// Exponentiation operator `^`
    #[token("^")]
    Caret,
    /// Factorial operator `!`
    #[token("!")]
    Bang,
    /// Left parenthesis `(`
    #[token("(")]
    LParen,
    /// Right parenthesis `)`
    #[token(")")]
    RParen,
}

/// Token paired with source byte span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpannedExprToken<'s> {
    /// Token kind
    pub kind: ExprToken<'s>,
    /// Byte range in input
    pub span: Range<usize>,
}

impl Location for SpannedExprToken<'_> {
    #[inline(always)]
    fn previous_token_end(&self) -> usize {
        self.span.end
    }
    #[inline(always)]
    fn current_token_start(&self) -> usize {
        self.span.start
    }
}

impl<'s> PartialEq<ExprToken<'s>> for SpannedExprToken<'s> {
    #[inline(always)]
    fn eq(&self, other: &ExprToken<'s>) -> bool {
        self.kind == *other
    }
}

impl<'t, 's> ContainsToken<&'t SpannedExprToken<'s>> for ExprToken<'s> {
    #[inline(always)]
    fn contains_token(&self, token: &'t SpannedExprToken<'s>) -> bool {
        *self == token.kind
    }
}

/// Stream type alias for expression parsing.
pub type ExprStream<'t, 's> = TokenSlice<'t, SpannedExprToken<'s>>;

/// Binary operator categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    /// Addition `+`
    Add,
    /// Subtraction `-`
    Sub,
    /// Multiplication `*`
    Mul,
    /// Division `/`
    Div,
    /// Exponentiation `^`
    Pow,
}

/// Expression abstract syntax tree (AST) node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AstExpr<'s> {
    /// Numeric constant
    Number(i64),
    /// Variable reference
    Variable(&'s str),
    /// Unary negation `-x`
    Negate(Box<AstExpr<'s>>),
    /// Unary factorial `x!`
    Factorial(Box<AstExpr<'s>>),
    /// Binary operation `lhs op rhs`
    Binary(Box<AstExpr<'s>>, BinaryOp, Box<AstExpr<'s>>),
}

/// Rich diagnostic error reporting expression parsing failures.
#[derive(Diagnostic, Debug)]
#[diagnostic(code(parser::expression_error), help("Verify operand and operator syntax."))]
pub struct ExpressionDiagnostic {
    /// Error message
    pub message: String,
    /// Source frame
    #[source_code]
    pub src: NamedSource<String>,
    /// Offending token span
    #[label("{label}")]
    pub span: SourceSpan,
    /// Label text
    pub label: String,
}

impl core::fmt::Display for ExpressionDiagnostic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ExpressionDiagnostic {}

/// Parse atomic operand (number, variable, or parenthesized sub-expression).
fn parse_atom<'t, 's>(input: &mut ExprStream<'t, 's>) -> ModalResult<AstExpr<'s>> {
    dispatch! { peek(any.map(|t: &SpannedExprToken<'s>| t.kind));
        ExprToken::Number(_) => any.verify_map(|t: &SpannedExprToken<'s>| match t.kind {
            ExprToken::Number(num) => num.parse::<i64>().ok().map(AstExpr::Number),
            _ => None,
        }),
        ExprToken::Ident(_) => any.verify_map(|t: &SpannedExprToken<'s>| match t.kind {
            ExprToken::Ident(id) => Some(AstExpr::Variable(id)),
            _ => None,
        }),
        ExprToken::LParen => delimited(
            literal(ExprToken::LParen),
            cut_err(parse_expression),
            cut_err(literal(ExprToken::RParen))
                .context(StrContext::Expected(StrContextValue::CharLiteral(')'))),
        ),
        _ => fail.context(StrContext::Label("operand (number, identifier, or parenthesized expression)")),
    }
    .parse_next(input)
}

/// Parse full expression with operator precedence climbing via winnow::combinator::expression.
pub fn parse_expression<'t, 's>(input: &mut ExprStream<'t, 's>) -> ModalResult<AstExpr<'s>> {
    expression(parse_atom)
        .current_precedence_level(0)
        .prefix(dispatch! { any.map(|t: &SpannedExprToken<'s>| t.kind);
            ExprToken::Minus => empty.value(Prefix(12, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>| {
                Ok(AstExpr::Negate(Box::new(a)))
            })),
            _ => fail,
        })
        .postfix(dispatch! { any.map(|t: &SpannedExprToken<'s>| t.kind);
            ExprToken::Bang => empty.value(Postfix(15, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>| {
                Ok(AstExpr::Factorial(Box::new(a)))
            })),
            _ => fail,
        })
        .infix(dispatch! { any.map(|t: &SpannedExprToken<'s>| t.kind);
            ExprToken::Plus => empty.value(Infix::Left(5, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>, b: AstExpr<'s>| {
                Ok(AstExpr::Binary(Box::new(a), BinaryOp::Add, Box::new(b)))
            })),
            ExprToken::Minus => empty.value(Infix::Left(5, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>, b: AstExpr<'s>| {
                Ok(AstExpr::Binary(Box::new(a), BinaryOp::Sub, Box::new(b)))
            })),
            ExprToken::Star => empty.value(Infix::Left(7, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>, b: AstExpr<'s>| {
                Ok(AstExpr::Binary(Box::new(a), BinaryOp::Mul, Box::new(b)))
            })),
            ExprToken::Slash => empty.value(Infix::Left(7, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>, b: AstExpr<'s>| {
                Ok(AstExpr::Binary(Box::new(a), BinaryOp::Div, Box::new(b)))
            })),
            ExprToken::Caret => empty.value(Infix::Right(14, |_: &mut ExprStream<'t, 's>, a: AstExpr<'s>, b: AstExpr<'s>| {
                Ok(AstExpr::Binary(Box::new(a), BinaryOp::Pow, Box::new(b)))
            })),
            _ => fail,
        })
        .parse_next(input)
}

/// Compile and evaluate an expression string into an AST with rich diagnostic error reporting.
pub fn compile_expression<'s>(
    filename: &str,
    source: &'s str,
) -> Result<AstExpr<'s>, ExpressionDiagnostic> {
    let mut lexer = ExprToken::lexer(source);
    let mut tokens = Vec::new();

    while let Some(res) = lexer.next() {
        match res {
            Ok(kind) => tokens.push(SpannedExprToken {
                kind,
                span: lexer.span(),
            }),
            Err(_) => {
                let span = lexer.span();
                return Err(ExpressionDiagnostic {
                    message: "Unrecognized character in expression".to_string(),
                    src: NamedSource::new(filename, source.to_string()),
                    span: SourceSpan::from(span),
                    label: "Unexpected character here".to_string(),
                });
            }
        }
    }

    let stream = TokenSlice::new(&tokens);
    match parse_expression.parse(stream) {
        Ok(expr) => Ok(expr),
        Err(err) => {
            let token_idx = err.offset();
            let span = if token_idx < tokens.len() {
                tokens[token_idx].span.clone()
            } else if let Some(last) = tokens.last() {
                last.span.end..last.span.end
            } else {
                0..0
            };

            Err(ExpressionDiagnostic {
                message: format!("Expression syntax error: {}", err.inner()),
                src: NamedSource::new(filename, source.to_string()),
                span: SourceSpan::from(span),
                label: "Error in expression evaluation here".to_string(),
            })
        }
    }
}
```
