---
trigger: glob
globs: "src/lexer/**/*.rs, src/error.rs, src/parser/**/*.rs, Cargo.toml, tests/**/*.rs"
description: "Logos 0.14.4 / 0.16.1 zero-copy lexing, 6-tier priority ladder, Miette 7.6.0 (start, len) span invariants, foreign .fasm detection, and CI snapshot testing rules."
---

# Logos (`0.14.4` -> `0.16.1`) & Miette `7.6.0` Architecture & Best Practices

Enforce these zero-allocation lexing and technician-friendly diagnostic rules across `src/lexer/`, `src/error.rs`, and `src/parser/`:

## 1. Logos Version Hygiene & Forward-Compatible Trivia Skipping
- **Fix Yanked `0.14.3` & Support Clean `0.16.1` Upgrades**:
  - `Cargo.lock` currently resolves `logos = "0.14.4"` (because `0.14.3` in `Cargo.toml` was yanked upstream due to an MSRV bump). Pin at least `logos = "0.14.4"` in `Cargo.toml`.
  - **CRITICAL `logos 0.16.1` Upgrade Guardrail (`allow_greedy`)**: `logos 0.15+` / `0.16.1` rejects unbounded greedy dot repetitions (`.*` and `.+`) at compile time—including on `#[logos(skip ...)]` in `0.16.1`! Always write single-line comment skipping with a negated character class rather than `//.*`:
    ```rust
    #[derive(Logos, Debug, PartialEq, Clone)]
    #[logos(skip r"[ \t\r\n\f]+")]
    #[logos(skip r"//[^\r\n]*")]
    pub enum Token<'a> { /* ... */ }
    ```
    `r"//[^\r\n]*"` is CRLF-safe, $O(N)$ non-backtracking, and compiles cleanly on **both** `logos 0.14.4` and `logos 0.16.1` without needing `allow_greedy = true`!
- **Zero-Allocation `&'a str` Slices & ASCII Case Folding**:
  - Never allocate `String` or `Vec` inside lexer callbacks; borrow `&'a str` directly (`Token::StringLit(&'a str)`, `Token::Ident(&'a str)`) and defer unescaping (`unescape_string`) to the parser.
  - Use `ignore(ascii_case)` on all ~640 ASCII DSL keywords and time units (`#[token("HOST", ignore(ascii_case))]`) rather than full Unicode `ignore(case)`.

## 2. Exact Priority Formula & FrameAssembly's 6-Tier Disambiguation Ladder
- **`logos-codegen 0.14.4` Default Priority Formula (`Mir::priority`)**:
  - `#[token("...")]`: $2 \times \text{bytes.len()}$ (`"s"` = $2$, `"ns"` = $4$, `"TCP"` = $6$).
  - `Mir::Class(_)` (`[a-z]`, `[0-9]`, `.`): **`2` per required character class** (NOT `1`!).
  - `Mir::Loop(_)` (`*`, tail of `+`) and `Mir::Maybe(_)` (`?`): **`0`**.
- **Mandatory 6-Tier Explicit Priority Ladder (`src/lexer/mod.rs`)**:
  Preserve this strict priority ordering so overlapping numeric, OID, IP, MAC, and unit literals never collide:
  1. `priority = 6` — **`MacAddress(&'a str)`**: IEEE colon (`00:1a:2b:3c:4d:5e`), hyphen (`00-1A-2B-3C-4D-5E`), and Cisco dotted-quad (`001a.2b3c.4d5e`).
  2. `priority = 5` — **IPv4 `IpAddress(&'a str)`**: `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+` (outranks 4-arc `OidStr`).
  3. `priority = 4` — **`Number(&'a str)`**: `-?[0-9]+|0[xX][0-9a-fA-F]+` (outranks single-arc `OidStr`).
  4. `priority = 3` — **`OidStr(&'a str)`**: `\.?[0-9]+(\.[0-9]+)*`.
  5. `priority = 2` — **IPv6 `IpAddress(&'a str)`** and **1-char/2-char Time Units** (`ns`, `us`, `ms`, `s`, `m`) so `"s"` and `"m"` beat `Ident`.
  6. `priority = 1` — **`Ident(&'a str)`**: `[a-zA-Z_][a-zA-Z0-9_]*`.

## 3. Token-Index-to-Byte-Span Mapping & Multi-Char Lex Error Expansion
- **EOF Token Index Guard**: `err_idx = tokens.len() - stream.len()` is a **token index**, not a byte offset. Always guard `err_idx >= tokens.len()` (mapping EOF to `(last_end, 0)` as in `diagnose_parse_error`).
- **Multi-Char Lex Failure Span Expansion**: Keep `expand_lex_error_span` in `src/lexer/mod.rs` expanding single-byte lexer failures across `/*`, `*/`, `/24` CIDR suffixes, and `'single-quoted'` strings so `miette` underlines the full offending token.

## 4. Miette `7.6.0` Span Invariants, Foreign `.fasm` Detection & CI Snapshots
- **CRITICAL `(byte_offset, byte_length)` Tuple Invariant**:
  - `miette::SourceSpan::from((usize, usize))` interprets a 2-tuple as **`(start_byte_offset, byte_length)`**, **NEVER** `(start, end)`!
  - When converting `Range<usize>` (`r.start..r.end`) into `CompilerError`'s `span: (usize, usize)` field, **always** compute `(r.start, r.end - r.start)` (or pass `r.start..r.end` directly to `SourceSpan::from(range)`).
- **`NamedSource` Language Tag & Technician-First Hints (`src/error.rs`)**:
  - Construct `NamedSource::new(filename, code).with_language("frameassembly")` (never `"fasm"`).
  - Preserve `detect_foreign_fasm(src)` in `src/error.rs` so users passing x86 Flat Assembler or SymbiFlow/F4PGA FPGA `.fasm` files receive immediate disambiguation guidance.
  - Never leak Rust debug formatting (`Ident(...)`, `ContextError`, `AST`) into user-facing `Display` or `Diagnostic::help()` strings.
- **Deterministic CI Snapshot Rendering**:
  - Never use `GraphicalReportHandler::default()` in assertions (varies by TTY, `NO_COLOR`, and terminal width). Always render with `GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor()).with_width(80).with_links(false).with_context_lines(2)`.