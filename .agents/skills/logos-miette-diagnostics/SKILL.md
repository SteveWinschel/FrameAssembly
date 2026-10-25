---
name: logos-miette-diagnostics
description: Comprehensive guide, API selection matrix, and production code templates for high-performance lexing, parsing, and rich diagnostic error reporting in Rust with logos 0.14+, miette 7.6+, and winnow 1.0+ (including two-phase TokenSlice bridge, subpatterns, morphing, GraphicalReportHandler, and multi-span diagnostics).
---

# Logos 0.14.4 & Miette 7.6.0 Diagnostics Engineering Skill

Use this skill when designing, implementing, debugging, or optimizing lexers, parsers, and diagnostic error reporters using `logos` (`0.14.4`), `miette` (`7.6.0`), and their two-phase integration with `winnow` (`1.0.4+`) in Rust.

## 1. Quick API Selection Matrix

| Lexing / Diagnostic Goal | Idiomatic Modern API (`logos 0.14.4` / `miette 7.6.0`) | Avoid (Legacy / Suboptimal / Anti-Pattern) |
| :--- | :--- | :--- |
| Token definition & zero-copy slices | `#[derive(Logos)]` with `&'a str` fields (`lex.slice()`) | Allocating `String` inside token variants |
| Disambiguate `Ident` vs 1-char tokens (`"s"`, `"m"`) | Explicit `priority = 1` on `Ident` (default is `2`, tying `"s"`) | Assuming `[a-zA-Z_]` has priority `1` (`Mir::Class` = `2`!) |
| Disambiguate `OidStr` vs `IntLit` (`[0-9]+`) | Explicit `priority = 3` on `OidStr` (`\.?[0-9]+(\.[0-9]+)*`) | Leaving both at default priority `2` (compile-time DFA conflict) |
| Cross-platform whitespace skipping | `#[logos(skip r"[ \t\r\n\f]+")]` (includes `\r` for CRLF) | `#[logos(skip r"[ \t\n\f]+")]` (rejects CRLF files!) |
| Reusable regex fragments | `#[logos(subpattern name = r"...")]` + `(?&name)` | Duplicating complex hex/IP/OID regexes across variants |
| Case-insensitive protocol keywords | `#[token("...", ignore(ascii_case))]` | `ignore(case)` (unneeded full Unicode table overhead) |
| Stateful lexing context | `#[logos(extras = S)]` via `lexer.extras` | `RefCell` or global/thread-local mutable state |
| Switching grammar dialects / modes | `lexer.morph::<SubToken>()` | Giant monolithic enum with boolean mode flags |
| Custom lex error with byte spans | `#[logos(error = E)]` + `lexer.spanned()` | Default unit error `()` discarding failure reasons |
| Pre-lexed stream for winnow | `TokenSlice<'t, SpannedToken<'a>>` | Converting tokens back to text or manual cursors |
| Automatic span tracking across tokens | `impl Location for SpannedToken` | Manual span arithmetic across token indices |
| Winnow keyword & set matching | `PartialEq<Token>` + `ContainsToken` (`literal`, `one_of`) | Verbose `any.verify(\|t\| t.kind == Token::X)` |
| Translating parser error to source span | `tokens[err.offset()].span` with `offset < tokens.len()` guard | Unbounded `tokens[err.offset()]` (panics on EOF!) |
| Deriving rich compiler errors | `#[derive(Diagnostic)]` with `#[diagnostic(code(...), url(docsrs))]` | Hand-rolling error formatting strings |
| Delegating diagnostic to inner field | `#[diagnostic(transparent)]` or `#[diagnostic(forward(field))]` | Manual `Diagnostic` trait boilerplate |
| Attaching source code & file context | `#[source_code] src: NamedSource<String>` (`.with_language(...)`) | Raw unnamed string slices without filename |
| Span constructor from `Range<usize>` | `SourceSpan::from(start..end)` | `SourceSpan::from((start, end))` (treats `end` as length!) |
| Zero-length / EOF caret span | `LabeledSpan::at_offset(byte_offset, "unexpected EOF")` | Out-of-bounds byte offset past `source.len()` |
| Highlighting primary & secondary spans | `#[label(primary, "...")]` + `#[label("...")]` | Unmarked labels without visual caret hierarchy |
| Highlighting dynamic span collections | `#[label(collection, "...")] Vec<SourceSpan>` | Flattening multiple error locations to a single span |
| Batch multi-error diagnostics | `#[related] Vec<ChildDiagnostic>` | Aborting on first semantic error |
| Deterministic CI snapshot rendering | `GraphicalTheme::unicode_nocolor()` + `.with_width(80).with_links(false)` | `GraphicalReportHandler::default()` (TTY/width dependent) |
| Machine-readable / screen-reader output | `JSONReportHandler` / `NarratableReportHandler` | Regex-scraping ANSI terminal output |

---

## 2. Exact `logos-codegen 0.14.4` Priority Calculation Rules

`logos-codegen` computes a compile-time specificity score (`Mir::priority`) for every token variant when no explicit `priority = N` is provided. If two patterns can match the same input and have the same priority, compilation fails with a DFA disambiguation error.

| Regex / Token AST Node (`Mir`) | Exact Priority Score Formula | Example & Computed Priority |
| :--- | :--- | :--- |
| `#[token("...")]` | $2 \times \text{bytes.len()}$ | `#[token("s")]` = **2**, `#[token("->")]` = **4**, `#[token("HOST")]` = **8** |
| `Mir::Literal(s)` | $2 \times \text{chars.count()}$ | `r"0x"` = **4** |
| `Mir::Class(_)` (`[a-z]`, `[0-9]`, `\d`, `.`) | **2** per required class | `r"[0-9]"` = **2**, `r"[a-zA-Z_]"` = **2** |
| `Mir::Loop(_)` (`*`, or repeating tail of `+`) | **0** | `r"[0-9]*"` = **0**, `r"[0-9]+"` (`Class` + `Loop`) = **2 + 0 = 2** |
| `Mir::Maybe(_)` (`?` optional) | **0** | `r"\.?"` = **0** |
| `Mir::Concat(items)` | $\sum \text{priority}(item)$ | `r"[a-zA-Z_][a-zA-Z0-9_]*"` = **2 + 0 = 2** |
| `Mir::Alternation(branches)` | $\min(\text{priority}(branch))$ | `r"([0-9]+\.[0-9]+)\|([a-z]+)"` = $\min(6, 2) =$ **2** |

### Why Explicit Priorities Are Required in `frameassembly`:
1. **`Ident` vs 1-Character Unit Tokens (`"s"`, `"m"`)**:
   - `#[token("s")]` (seconds) and `#[token("m")]` (minutes) have priority $2 \times 1 = 2$.
   - `#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*")]` (`Ident`) has `Class` ($2$) + `Loop` ($0$) = $2$.
   - Setting `priority = 1` on `Ident` ensures `"s"` and `"m"` lex as time units (`2 > 1`), while `"sec"` or `"my_var"` lex as `Ident` via longest-match!
2. **`OidStr` vs `IntLit`**:
   - `#[regex(r"[0-9]+")]` (`IntLit`) has priority $2$.
   - `#[regex(r"\.?[0-9]+(\.[0-9]+)*")]` (`OidStr`) has `Maybe(\.)` ($0$) + `Class([0-9])` ($2$) + `Loop` ($0$) = $2$.
   - Setting `priority = 3` on `OidStr` resolves the tie cleanly while keeping it below `Ipv4` (priority $14$) and `Mac` (priority $34$).

---

## 3. Architecture Decision Guide

### 3.1 Two-Phase Bridge Invariants (`logos 0.14.4` -> `winnow 1.0.4 TokenSlice`)
1. **CRLF-Safe Trivia Skipping**: Always use `#[logos(skip r"[ \t\r\n\f]+")]` and `#[logos(skip r"//[^\r\n]*")]`. Omitting `\r` causes CRLF files to fail with an unrecognized token error at line endings.
2. **Span-Aware `Location` Trait**: Implement `winnow::stream::Location` on your spanned token (`previous_token_end -> self.span.end`, `current_token_start -> self.span.start`) so `parser.span()` and `parser.with_span()` compute exact byte ranges across multi-token grammar productions.
3. **EOF Token Index Clamping**: `ParseError::offset()` on `TokenSlice` returns a **token index** (`0..=tokens.len()`). Always check `if idx < tokens.len() { tokens[idx].span.clone() } else { tokens.last().map(|t| t.span.end..t.span.end).unwrap_or(0..0) }`.

### 3.2 Diagnostic Architecture (`miette 7.6.0`)
1. **`SourceSpan` `(offset, length)` Guardrail**: Never pass `(span.start, span.end)` to `SourceSpan::from((usize, usize))`—tuple conversion interprets the second element as **length**, not end offset! Always pass a `Range<usize>` (`SourceSpan::from(span.start..span.end)`).
2. **Deterministic Snapshot Testing**: In tests, construct `GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor()).with_width(80).with_links(false).with_context_lines(2)` so rendered box-drawing diagnostics are 100% identical across developer machines and CI environments.

---

## 4. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations with complete rustdoc documentation:
1. **Two-Phase Lexing & Diagnostic Pipeline**: Complete `logos` -> `TokenSlice` -> `winnow` -> `miette` compilation pipeline with exact priority disambiguation, `Location`, `ContainsToken`, `NamedSource`, `SourceSpan`, and deterministic CI `GraphicalReportHandler`.
2. **Advanced Logos State, Extras, Subpatterns & Lexer Morphing**: Subpattern interpolation `(?&name)`, stateful lexer extras, `FilterResult`, and dialect switching via `lexer.morph::<SubToken>()`.
3. **Rich Multi-Span Diagnostics, Collections, Forwarding & Deterministic CI Snapshot Testing**: `#[derive(Diagnostic)]` with `#[label(primary)]`, `#[label(collection)]`, `#[diagnostic(forward(...))]`, `LabeledSpan::at_offset`, `JSONReportHandler`, and deterministic `unicode_nocolor` snapshot testing.
4. **Byte-Stream & Binary Protocol Lexing with Spanned Diagnostics**: Zero-copy packet lexing over `&[u8]` using `#[logos(source = [u8])]` and binary byte-offset diagnostics.
5. **Pratt Operator Precedence Expression Parsing with Lexed Tokens & Error Diagnostics**: Lexed token stream fed into `winnow::combinator::expression` with `Prefix`, `Postfix`, `Infix::{Left, Right, Neither}`, error recovery with `cut_err`, and conversion to `miette::Diagnostic`.
