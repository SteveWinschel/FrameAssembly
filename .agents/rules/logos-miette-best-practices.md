---
trigger: glob
globs: "src/lexer/**/*.rs, src/error.rs, src/parser/**/*.rs, tests/**/*.rs"
description: "Logos 0.14.4 zero-copy lexing, exact priority disambiguation formula, and Miette 7.6.0 diagnostic reporting and CI snapshot testing rules."
---

# Logos 0.14.4 & Miette 7.6.0 Architecture & Best Practices

Always enforce these modern, zero-allocation, high-performance, and idiomatic `logos` (`0.14.4`), `miette` (`7.6.0`), and two-phase `winnow` (`1.0.4+`) integration rules when designing, implementing, or refactoring lexers, parsers, and compiler error diagnostics in Rust:

## 1. Logos 0.14.4 Lexer Definition, Exact Priority Formula & CRLF Guardrails
- **`#[derive(Logos)]` & Zero-Allocation Slices**:
  - Define token enums with `#[derive(Logos)]` borrowing the input lifetime `'a` (e.g., `Ident(&'a str)`, `StringLit(&'a str)`). Never allocate `String` or `Vec` inside lexer callbacks; store zero-copy slices (`lex.slice()`) and defer unescaping or allocation to parsing/semantic passes.
- **Exact `logos-codegen 0.14.4` Default Priority Formula (`Mir::priority`)**:
  - `logos` compiles all `#[token]` and `#[regex]` rules into a unified deterministic finite automaton (DFA). Equal-length pattern overlaps with identical priority fail at **compile time**.
  - **CRITICAL FORMULA (`Mir::Class` scores `2`, NOT `1`!)**:
    - `#[token("...")]`: $\text{priority} = 2 \times \text{bytes.len()}$ (e.g., `#[token("s")]` = $2$, `#[token("ns")]` = $4$, `#[token("TCP")]` = $6$).
    - `Mir::Literal(bytes)`: $2 \times \text{chars.count()}$.
    - `Mir::Class(_)` (any character class `[a-z]`, `[0-9]`, `\d`, `.`): **`2` per required character class**!
    - `Mir::Loop(_)` (`*`, or the repeating tail of `+` which lowers to `Concat(head, Loop(head))`): **`0`**.
    - `Mir::Maybe(_)` (`?` optional): **`0`**.
    - `Mir::Concat(items)`: $\sum \text{priority}(item)$.
    - `Mir::Alternation(branches)`: $\min(\text{priority}(branch))$.
  - **Real FrameAssembly Priority Disambiguation Examples**:
    - `#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*")]` (`Ident`): `Concat(Class, Loop(Class))` = $2 + 0 = 2$. Because 1-byte unit tokens `#[token("s")]` and `#[token("m")]` also have priority $2 \times 1 = 2$, `Ident` **MUST** set explicit `priority = 1` (`#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", priority = 1)]`) so 1-char keywords win!
    - `#[regex(r"\.?[0-9]+(\.[0-9]+)*")]` (`OidStr`): `Maybe(\.)` ($0$) + `Class([0-9])` ($2$) + `Loop` ($0$) = $2$, which collides with `#[regex(r"[0-9]+")]` (`IntLit`, priority $2$). `OidStr` **MUST** set explicit `priority = 3` (`#[regex(r"\.?[0-9]+(\.[0-9]+)*", priority = 3)]`).
    - Multi-class fixed-prefix patterns like IPv4 (`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`) score $2+2+2+2+2+2+2 = 14$ and MAC addresses score $34$, naturally outranking `OidStr` ($3$) and `IntLit` ($2$).
- **CRLF-Safe Whitespace & Comment Skipping**:
  - Always include `\r` inside the whitespace skip character class:
    ```rust
    #[logos(skip r"[ \t\r\n\f]+")]
    #[logos(skip r"//[^\r\n]*")]
    ```
  - **QA Note**: Omitting `\r` (e.g., `#[logos(skip r"[ \t\n\f]+")]` in `src/lexer/mod.rs:24`) causes bare `\r\n` line endings on Windows/CRLF files to fail lexical analysis unless preceded by a `//.*` comment!
- **Subpatterns (`#[logos(subpattern name = r"...")]`) & Case Folding**:
  - Factor shared regex fragments into enum-level subpatterns referenced via `(?&name)`.
  - Use `ignore(ascii_case)` for ASCII protocol keywords (`#[token("tcp", ignore(ascii_case))]`), reserving `ignore(case)` only when full Unicode case-folding tables are required.
- **`logos 0.14.4` vs `0.15+` Version Guardrail**:
  - This workspace pins `logos = "0.14.4"`. Stick strictly to `0.14.4` attribute and callback signatures (`#[logos(skip ...)]`, `#[logos(error = E)]`, `#[logos(extras = S)]`, `lexer.morph::<T>()`, `FilterResult<T, E>`). Never hallucinate `0.15+`/`0.16+` attribute syntax changes.

## 2. Callbacks, Stateful Extras, Morphing & Custom Lex Errors
- **Supported Callback Return Types (`CallbackResult`)**:
  - `T` (emits `Variant(T)`), `bool` (`true` emits unit variant, `false` emits error), `Option<T>`, `Result<T, E>`, `logos::Skip`, `logos::Filter<T>`, `logos::FilterResult<T, E>`.
  - Keep callbacks $O(1)$ and allocation-free (`lex.slice()`, integer radix parsing).
- **Lexer Inspection & UTF-8 Safety**:
  - Use `lexer.slice()`, `lexer.span()` (`Range<usize>`), `lexer.remainder()`, and `lexer.bump(n)`. When lexing `&str`, `lexer.bump(n)` must land on a valid UTF-8 boundary. For binary protocols, set `#[logos(source = [u8])]`.
- **Extras (`#[logos(extras = S)]`), Morphing (`lexer.morph()`) & Custom Errors (`#[logos(error = E)]`)**:
  - Track delimiter depth or lexer state in `lexer.extras`. Transition between sub-grammars with `lexer.morph::<SubToken>()`.
  - Specify `#[logos(error = LexError)]` where `LexError: Default + Clone + PartialEq + Eq + Debug` and iterate via `Token::lexer(src).spanned()` to capture `(Result<Token<'a>, LexError>, Range<usize>)`.

## 3. Two-Phase Integration: Bridging Logos with Winnow (`TokenSlice`)
- **Spanned Token Stream & Triad of Bridge Traits**:
  - Collect `(Token<'a>, Range<usize>)` into `Vec<SpannedToken<'a>>` and wrap in `winnow::stream::TokenSlice::new(&tokens)`.
  - Implement:
    1. `winnow::stream::Location for SpannedToken<'_>`: `previous_token_end(&self) -> usize { self.span.end }` and `current_token_start(&self) -> usize { self.span.start }`, enabling `.span()` and `.with_span()` across multi-token AST rules.
    2. `PartialEq<Token<'a>> for SpannedToken<'a>`: enables `winnow::token::literal(Token::Host)`.
    3. `ContainsToken<&'t SpannedToken<'a>> for Token<'a>` and `[Token<'a>; N]`: enables `one_of` and `take_while`.
- **Translating Token Index Offsets to Source Byte Spans (EOF Guard)**:
  - `ParseError::offset()` on a `TokenSlice` returns the **token index**, NOT a byte offset! Always guard against `offset >= tokens.len()` (unexpected EOF):
    ```rust
    let span = if offset < tokens.len() {
        tokens[offset].span.clone()
    } else if let Some(last) = tokens.last() {
        last.span.end..last.span.end
    } else {
        0..0
    };
    ```

## 4. Miette 7.6.0 Diagnostic Derivation, Span Invariants & Forwarding
- **`#[derive(Diagnostic)]` & Metadata Attributes**:
  - Annotate compiler errors with `#[derive(Error, Diagnostic, Debug)]` and `#[diagnostic(code(frameassembly::lexer::invalid_token), help("..."), url(docsrs))]` (or `severity(Warning | Advice)`).
- **`NamedSource` & Syntax Highlighting**:
  - Store source text in `#[source_code] pub src: NamedSource<String>` (or `Arc<NamedSource<String>>` when shared across multi-error batches), constructed via `NamedSource::new(filename, source).with_language("frameassembly")`.
- **`SourceSpan` Construction & The `(offset, length)` Invariant**:
  - **CRITICAL INVARIANT**: `SourceSpan::from((usize, usize))` is `(byte_offset, byte_length)`, **NOT** `(start, end)`!
  - Always convert `Range<usize>` directly via `SourceSpan::from(span.start..span.end)` or `LabeledSpan::new_with_span(label, span.start..span.end)`.
  - For zero-length EOF spans (`last.span.end..last.span.end`), use `SourceSpan::from(eof_offset..eof_offset)` or `LabeledSpan::at_offset(eof_offset, "unexpected end of input")` so `miette` renders a clean single-column caret.
  - When converting `(line, column)` coordinates to byte offsets, use `SourceOffset::from_location(source_str, line_1_indexed, col_1_indexed)`.
- **Label Hierarchy, Collections, Related Errors & Forwarding**:
  - Mark the primary failure locus with `#[label(primary, "{label}")]` and secondary context spans with `#[label("declared here")]`.
  - Annotate dynamic multi-span lists (`Vec<SourceSpan>` / `Vec<LabeledSpan>`) with `#[label(collection, "conflicting definitions")]`.
  - Aggregate batch compiler errors with `#[related] pub errors: Vec<SpannedCompilerError>`.
  - Wrap inner diagnostics transparently with `#[diagnostic(transparent)]` on enum variants, or delegate source/labels to a specific struct field via `#[diagnostic(forward(inner_diag))]` and `#[diagnostic_source]`.

## 5. Deterministic CI Snapshot Testing with `GraphicalReportHandler`
- **Never Rely on Ambient Terminal Detection in Tests**:
  - For deterministic unit and snapshot tests across local terminals and CI runners, configure `GraphicalReportHandler` with `GraphicalTheme::unicode_nocolor()`, fixed width, and disabled OSC-8 hyperlinks:
    ```rust
    use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme};

    pub fn render_deterministic_diagnostic(diag: &dyn Diagnostic) -> String {
        let handler = GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor())
            .with_width(80)
            .with_links(false)
            .with_context_lines(2);
        let mut out = String::new();
        handler.render_report(&mut out, diag).expect("infallible String fmt");
        out
    }
    ```
  - For machine-readable IDE/LSP output or screen-reader accessibility, use `miette::JSONReportHandler` or `miette::NarratableReportHandler`.

## 6. Anti-Patterns & Performance Pitfalls

| Anti-Pattern | Why It Fails | Modern Idiomatic Solution (`logos 0.14.4` / `miette 7.6.0`) |
| :--- | :--- | :--- |
| Assuming `Mir::Class` (`[a-z]`) has priority `1` | `Mir::Class` scores **`2`**, tying with 1-byte `#[token("s")]` ($2$) | Set explicit `priority = 1` on `Ident` and `priority = 3` on `OidStr` |
| Omitting `\r` in `#[logos(skip r"[ \t\n\f]+")]` | Bare `\r\n` (CRLF) fails lexing with an unrecognized token error | Always use `#[logos(skip r"[ \t\r\n\f]+")]` |
| `SourceSpan::from((span.start, span.end))` | Tuple `(usize, usize)` means `(offset, length)`, stretching underline to `start + end` | Always use `SourceSpan::from(span.start..span.end)` |
| Unbounded `tokens[err.offset()]` on parse failure | On unexpected EOF, `err.offset() == tokens.len()`, panicking out-of-bounds | Clamp to `tokens.last().map(\|t\| t.span.end..t.span.end).unwrap_or(0..0)` |
| Using `GraphicalReportHandler::default()` in tests | Varies output by TTY, `NO_COLOR`, terminal width, and OSC-8 link support | Use `GraphicalTheme::unicode_nocolor()`, `.with_width(80)`, `.with_links(false)` |
| Allocating `String` inside `#[regex]` callbacks | Degrades lexer throughput and allocates on speculative/discarded tokens | Yield `&'a str` (`lex.slice()`) and unescape lazily in parser/semantic pass |
