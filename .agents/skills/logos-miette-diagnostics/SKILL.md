---
name: logos-miette-diagnostics
description: Comprehensive guide, API selection matrix, and production code templates for high-performance lexing, parsing, and rich diagnostic error reporting in Rust with logos 0.14.4 / 0.16.1+, miette 7.6.0, and winnow 1.0.5+ (including v3.0.0 strict-lowercase [a-z0-9]+ tokens without ignore(ascii_case), 6-tier priority disambiguation, expand_lex_error_span, detect_foreign_fasm, self-healing keyword diagnostics, two-phase TokenSlice/3-tuple Stream bridges, subpatterns, morphing, GraphicalReportHandler, and multi-span diagnostics).
---

# Logos (`0.14.4` -> `0.16.1`) & Miette `7.6.0` Diagnostics Engineering Skill

Use this skill when designing, implementing, debugging, or optimizing lexers, parsers, and diagnostic error reporters using `logos` (`0.14.4` with `0.16.1` forward compatibility), `miette` (`7.6.0`), and their two-phase integration with `winnow` (`1.0.5+`) in Rust.

## 1. Quick API Selection Matrix

| Lexing / Diagnostic Goal | Idiomatic Modern API (`logos 0.14.4` / `0.16.1` & `miette 7.6.0`) | Avoid (Legacy / Suboptimal / Anti-Pattern) |
| :--- | :--- | :--- |
| Token definition & zero-copy slices | `#[derive(Logos)]` with `&'a str` fields (`lex.slice()`) | Allocating `String` inside token variants |
| Strict-lowercase v3.0.0 built-in keywords | `#[token("host")]`, `#[token("echorequest")]`, `#[token("arp")]` (`[a-z0-9]+`, zero `_`, zero `-`, **no** `ignore(ascii_case)`) | `#[token("...", ignore(ascii_case))]`, uppercase/underscored keywords, or removed `Token::Loop` |
| Flexible user identifiers (`host`/`flow`/param) | `#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*", priority = 1)]` (stops cleanly before `->`) | Forbidding `-` or `_` in user-defined `fw-dmz-01` / `core_sw` identifiers |
| Disambiguate `Ident` vs 1-char tokens (`"s"`, `"m"`) | Explicit `priority = 1` on `Ident` + `priority = 2` on `#[token("s", priority = 2)]`, `#[token("m", priority = 2)]` | Assuming `[a-zA-Z_]` has priority `1` (`Mir::Class` = `2`!) |
| Disambiguate `Mac`, `IPv4`, `Number`, `OidStr`, `IPv6`, `Ident` | Explicit 6-tier priority ladder (`6` down to `1` in `src/lexer/mod.rs`) | Leaving overlapping regexes at default priorities (compile-time DFA conflict) |
| Cross-platform whitespace & comment skipping | `#[logos(skip r"[ \t\r\n\f]+")]` + `#[logos(skip r"//[^\r\n]*")]` | `#[logos(skip r"//.*")]` (rejected in `logos 0.15+`/`0.16.1` without `allow_greedy = true`!) |
| Multi-char lex error span expansion | `expand_lex_error_span(input, lexer.span())` (`/*`, `*/`, `/24`, `'...'`) | Underlining only a single byte on CIDR `/24` or `'single-quoted'` strings |
| Foreign `.fasm` dialect disambiguation | `detect_foreign_fasm(src)` (`;` x86 Flat Assembler vs `#` FPGA FASM) | Generic syntax errors when a user passes an x86 or FPGA `.fasm` file |
| Self-healing v3.0.0 keyword & `loop` diagnostics | `loop` $\rightarrow$ removed-in-2.0 hint; `raw.to_ascii_lowercase().replace(['_', '-'], "")` $\rightarrow$ `"Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace '<raw>' with '<kw>'."` | Opaque `"unexpected identifier"` errors without 1-click Quick Fix replacement hints |
| Reusable regex fragments | `#[logos(subpattern name = r"...")]` + `(?&name)` | Duplicating complex hex/IP/OID regexes across variants |
| Stateful lexing context | `#[logos(extras = S)]` via `lexer.extras` | `RefCell` or global/thread-local mutable state |
| Switching grammar dialects / modes | `lexer.morph::<SubToken>()` | Giant monolithic enum with boolean mode flags |
| Custom lex error with byte spans | `#[logos(error = E)]` + `lexer.spanned()` | Default unit error `()` discarding failure reasons |
| Pre-lexed stream for winnow | `Stream<'i, 'a> = &'i [(Token<'a>, Range<usize>, &'a str)]` or `TokenSlice<'t, SpannedToken<'a>>` | Converting tokens back to text or manual cursors |
| Automatic span tracking across tokens | `impl Location for SpannedToken` | Manual span arithmetic across token indices |
| Winnow keyword & set matching | `PartialEq<Token>` + `ContainsToken` (`literal`, `one_of`) | Pseudo-keyword hacks on `Token::Ident` (`pkttype`, `read`, `write`, `nop`, `error`, `shutdownack` are real `Token`s) |
| Translating parser error to source span | `tokens[err_idx]` with `err_idx < tokens.len()` EOF guard | Unbounded `tokens[err_idx]` (panics on EOF!) |
| Deriving rich compiler errors | `#[derive(Diagnostic)]` with `#[diagnostic(code(...), url(docsrs))]` | Hand-rolling error formatting strings |
| Delegating diagnostic to inner field | `#[diagnostic(transparent)]` or `#[diagnostic(forward(field))]` | Manual `Diagnostic` trait boilerplate |
| Attaching source code & file context | `NamedSource::new(filename, code).with_language("frameassembly")` | Using `.with_language("fasm")` or unnamed string slices |
| Span constructor from `Range<usize>` or `(start, len)` | `SourceSpan::from(start..end)` or `SourceSpan::from((start, end - start))` | `SourceSpan::from((start, end))` (treats `end` as byte **length**!) |
| Zero-length / EOF caret span | `LabeledSpan::at_offset(byte_offset, "unexpected EOF")` | Out-of-bounds byte offset past `source.len()` |
| Highlighting primary & secondary spans | `#[label(primary, "...")]` + `#[label("...")]` | Unmarked labels without visual caret hierarchy |
| Highlighting dynamic span collections | `#[label(collection, "...")] Vec<SourceSpan>` | Flattening multiple error locations to a single span |
| Batch multi-error diagnostics | `#[related] Vec<ChildDiagnostic>` | Aborting on first semantic error |
| Deterministic CI snapshot rendering | `GraphicalTheme::unicode_nocolor()` + `.with_width(80).with_links(false)` | `GraphicalReportHandler::default()` (TTY/width dependent) |
| Machine-readable / screen-reader output | `JSONReportHandler` / `NarratableReportHandler` | Regex-scraping ANSI terminal output |

---

## 2. Exact `logos-codegen 0.14.4` Priority Formula & FrameAssembly v3.0.0's 6-Tier Ladder

`logos-codegen` computes a compile-time specificity score (`Mir::priority`) for every token variant when no explicit `priority = N` is provided. If two patterns can match the same input and have the same priority, compilation fails with a DFA disambiguation error.

| Regex / Token AST Node (`Mir`) | Exact Priority Score Formula | Example & Computed Priority |
| :--- | :--- | :--- |
| `#[token("...")]` | $2 \times \text{bytes.len()}$ | `#[token("s")]` = **2**, `#[token("->")]` = **4**, `#[token("host")]` = **8** |
| `Mir::Literal(s)` | $2 \times \text{chars.count()}$ | `r"0x"` = **4** |
| `Mir::Class(_)` (`[a-z]`, `[0-9]`, `\d`, `.`) | **2** per required class | `r"[0-9]"` = **2**, `r"[a-zA-Z_]"` = **2** |
| `Mir::Loop(_)` (`*`, or repeating tail of `+`) | **0** | `r"[0-9]*"` = **0**, `r"[0-9]+"` (`Class` + `Loop`) = **2 + 0 = 2** |
| `Mir::Maybe(_)` (`?` optional) | **0** | `r"\.?"` = **0** |
| `Mir::Concat(items)` | $\sum \text{priority}(item)$ | `r"[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*"` = **2 + 0 + 0 = 2** |
| `Mir::Alternation(branches)` | $\min(\text{priority}(branch))$ | `r"([0-9]+\.[0-9]+)\|([a-z]+)"` = $\min(6, 2) =$ **2** |

### FrameAssembly v3.0.0's Mandatory 6-Tier Explicit Priority Ladder & Token Invariants (`src/lexer/mod.rs`)
1. **`priority = 6` — `MacAddress(&'a str)`**: IEEE colon (`([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`), hyphen (`([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}`), and Cisco dotted-quad (`[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}`).
2. **`priority = 5` — IPv4 `IpAddress(&'a str)`**: `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+` (outranks 4-arc `OidStr`).
3. **`priority = 4` — `Number(&'a str)`**: `-?[0-9]+|0[xX][0-9a-fA-F]+` (outranks single-arc `OidStr`).
4. **`priority = 3` — `OidStr(&'a str)`**: `\.?[0-9]+(\.[0-9]+)*`.
5. **`priority = 2` — IPv6 `IpAddress(&'a str)` & Strict-Lowercase Time Units (`ns`, `us`, `ms`, `s`, `m`)**: Ensures 1-char units `#[token("s", priority = 2)]` and `#[token("m", priority = 2)]` (without `ignore(ascii_case)`) outrank `Ident` (`2 > 1`) while `"sec"` or `"my_var"` lex as `Ident` via longest-match.
6. **`priority = 1` — `Ident(&'a str)`**: `#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*", priority = 1)]` so user-defined `host`, `flow`, and parameter names allow uppercase, `_`, and internal `-` (`fw-dmz-01`, `core_sw`) while stopping cleanly before `->`.
7. **Strict-Lowercase `[a-z0-9]+` Word Tokens & v3.0.0 Consolidation**:
   - Every built-in keyword, protocol, and modifier uses `#[token("<lowercase>")]` with zero `_`, zero `-`, and **no** `ignore(ascii_case)` (`host`, `ip`, `mac`, `flow`, `compile`, `wait`, `srcport`, `dstport`, `acknum`, `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `readholdingregisters`, etc.).
   - `Token::Loop` is removed; `#[token("sackperm")] SackPerm`, `#[token("agentip")] AgentIp`, `#[token("hellotime")] HelloTime` (unified across STP `u16` and HSRP `<= 255` `u8`; `HelloTimeHsrp` removed), and `#[token("whois")] Whois` (`WhoIs` removed) are deduplicated; `pkttype`, `read`, `write`, `nop`, `error`, and `shutdownack` are promoted to first-class tokens.

---

## 3. Architecture Decision Guide

### 3.1 Two-Phase Bridge Invariants (`logos 0.14.4` / `0.16.1` -> `winnow 1.0.5+`)
1. **CRLF-Safe & `logos 0.16.1`-Ready Trivia Skipping**: Always use `#[logos(skip r"[ \t\r\n\f]+")]` and `#[logos(skip r"//[^\r\n]*")]`. In `logos 0.15+` / `0.16.1`, unbounded greedy dot repetitions (`//.*`) are rejected at compile time unless `allow_greedy = true` is specified; `r"//[^\r\n]*"` is non-backtracking and compiles cleanly on both `0.14.4` and `0.16.1`.
2. **Multi-Char Lex Error Span Expansion (`expand_lex_error_span`)**: When `Token::lexer` returns `Err(())` on a single byte, expand the `(start, len)` span across `/*`, `*/`, `/24` CIDR suffixes, and `'single-quoted'` strings so `miette` underlines the full offending token.
3. **EOF Token Index Clamping**: `err_idx = tokens.len() - stream.len()` (or `ParseError::offset()` on `TokenSlice`) is a **token index** (`0..=tokens.len()`), never a byte offset. Always guard `err_idx >= tokens.len()` and map EOF to `(last_end, 0)`.

### 3.2 Diagnostic Architecture (`miette 7.6.0`, `src/parser/mod.rs` & `src/error.rs`)
1. **`SourceSpan` `(byte_offset, byte_length)` Guardrail**: Never pass `(span.start, span.end)` to `SourceSpan::from((usize, usize))`—tuple conversion interprets the second element as **`byte_length`**, not `end_offset`! Always pass `(span.start, span.end - span.start)` or `SourceSpan::from(span.start..span.end)`.
2. **Foreign `.fasm` Detection (`detect_foreign_fasm`)**: Inspect input lacking `compile` + (`flow` or `host`) for x86 Flat Assembler signatures (`;` comments, `format PE`/`ELF`, `section`, `use32`/`use64`, `org`) and SymbiFlow/F4PGA FPGA FASM signatures (`#` comments, `CLB`/`LUT`/`IOB`/`SLICE` tile features) to return actionable disambiguation guidance in `lex_error_help` and `parse_error_help`.
3. **Self-Healing v3.0.0 Keyword & Removed-`loop` Diagnostics**:
   - When parsing fails on `Token::Ident(raw)` and `raw.eq_ignore_ascii_case("loop")`, emit: `"The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile { ... }'."`
   - When `raw.to_ascii_lowercase().replace(['_', '-'], "")` matches a valid v3.0.0 built-in keyword `<kw>` (`raw != <kw>`), emit the exact self-healing `help` string: `"Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace '<raw>' with '<kw>'."` (powering 1-click Quick Fix `CodeActionProvider` edits in `frameassembly-vscode`).
4. **Deterministic Snapshot Testing**: In tests, construct `GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor()).with_width(80).with_links(false).with_context_lines(2)` so rendered box-drawing diagnostics are 100% identical across developer machines and CI environments.

---

## 4. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations with complete rustdoc documentation:
1. **Two-Phase Lexing & Self-Healing Diagnostic Pipeline**: Complete `logos` (strict-lowercase `[a-z0-9]+` tokens + 6-tier priority ladder + `expand_lex_error_span`) -> `winnow` -> `miette` (`detect_foreign_fasm` + v3.0.0 `suggest_v2_keyword_fix` + `(start, len)` `SourceSpan`) compilation pipeline.
2. **Advanced Logos State, Extras, Subpatterns & Lexer Morphing**: Subpattern interpolation `(?&name)`, stateful lexer extras, `FilterResult`, and dialect switching via `lexer.morph::<SubToken>()`.
3. **Rich Multi-Span Diagnostics, Collections, Forwarding & Deterministic CI Snapshot Testing**: `#[derive(Diagnostic)]` with `#[label(primary)]`, `#[label(collection)]`, `#[diagnostic(forward(...))]`, `LabeledSpan::at_offset`, `JSONReportHandler`, and deterministic `unicode_nocolor` snapshot testing.
4. **Byte-Stream & Binary Protocol Lexing with Spanned Diagnostics**: Zero-copy packet lexing over `&[u8]` using `#[logos(source = [u8])]` and binary byte-offset diagnostics.
5. **Pratt Operator Precedence Expression Parsing with Lexed Tokens & Error Diagnostics**: Lexed token stream fed into `winnow::combinator::expression` with `Prefix`, `Postfix`, `Infix::{Left, Right, Neither}`, error recovery with `cut_err`, and conversion to `miette::Diagnostic`.
