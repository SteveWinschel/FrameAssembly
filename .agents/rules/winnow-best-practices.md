---
trigger: glob
globs: "src/parser/**/*.rs, tests/**/*.rs"
description: "Winnow 1.0.4+ and memchr 2.8.3 zero-copy TokenSlice parser combinator patterns, protocol-scoped cut_err dispatch, and parser QA rules."
---

# Winnow 1.0.4+ Parsing Architecture & Best Practices

Always enforce these modern, zero-copy, high-performance, and idiomatic `winnow` (`1.0.4+`, `memchr 2.8.3`) parsing rules and combinator patterns when designing, writing, or refactoring parsers in Rust:

## 1. Core Parser Signature & Imperative-Declarative Hybrid Model
- **Mutable Stream Reference (`&mut I`)**:
  - Write every parser function with the signature `fn parse_item<'i, 'a>(input: &mut Stream<'i, 'a>) -> ModalResult<Output>` (or `winnow::Result<Output, E>` when non-backtracking). `winnow` advances `input` in-place on `Ok` and rewinds via `Checkpoint` on `ErrMode::Backtrack` inside branching/repeating combinators.
- **`ModalResult` vs. `Result`**:
  - Use `winnow::ModalResult<O, E = ContextError>` (alias for `Result<O, ErrMode<E>>`, replacing legacy `PResult`) whenever a parser participates in backtracking (`alt`, `opt`, `repeat`, `separated`, `unordered_seq!`) or streaming (`Partial`).
- **Top-Level Entry Point (`Parser::parse`)**:
  - Always invoke top-level parsers with `parser.parse(input)` rather than `parse_next` or `parse_peek`. `Parser::parse` automatically enforces full input consumption (`eof`), resets the stream to the failure checkpoint on error, and wraps the error in `ParseError<I, E>` with `.offset()`, `.inner()`, and `.char_span()` ready for `miette`. Reserve `parse_peek` strictly for unit tests asserting on `(remaining, output)`.
- **Hybrid Imperative + Combinator Style**:
  - Freely mix declarative combinators with imperative `let x = sub_parser.parse_next(input)?;` statements inside `fn(input: &mut I) -> ModalResult<O>`. When manually rejecting input after advancing `input` imperatively, capture `let start = input.checkpoint();` before parsing and call `input.reset(&start);` before returning `Err(ErrMode::from_input(input))`.
- **Avoid Deep `impl Parser` Return Chains**:
  - Returning deeply nested combinator chains via `-> impl Parser<I, O, E>` inflates type sizes and compile times. Prefer plain `fn(input: &mut I) -> ModalResult<O>` functions, or borrow a mutable `impl Parser` across calls via `parser.by_ref()`.

## 2. Declarative Sequencing, Prefix Dispatch & Protocol-Scoped `cut_err`
- **`seq!` & `unordered_seq!` Over Tuple Chains**:
  - Prefer `seq! { StructName { field_a: parser_a, _: ignored_delim, field_b: parser_b, ..Default::default() } }` (or `seq!(p1, _: sep, p2)`) over nested `preceded`/`terminated`/`delimited`/tuple `.map(...)` chains. Earlier parsed fields (`field_a`) are in variable scope for subsequent field parsers (`field_b`).
  - Use `unordered_seq! { Config { host: parse_host, port: parse_port } }` (replacing deprecated `permutation`) when fields must each appear once in any order.
- **`dispatch!` Over `alt` for $O(1)$ Prefix Routing**:
  - Whenever branches can be distinguished by a leading token, byte, or fixed slice, use `dispatch! { peek(any); ... }` (or `dispatch! { any; ... }` when branches consume the prefix). `dispatch!` compiles to a native Rust `match` jump table ($O(1)$) instead of `alt`'s sequential $O(N)$ backtracking ladder.
  - `alt((...))` is implemented for tuples up to 21 elements and for mutable parser slices `alt(&mut [P])` when all branches share a uniform parser type (`fn(&mut I) -> ModalResult<O>`).
- **CRITICAL GUARDRAIL: Protocol-Scoped Dispatch & Shared Keyword `cut_err`**:
  - In multi-protocol DSLs like `frameassembly`, always consume the protocol token first (`TCP`, `DNS`, `COAP`, `HTTP`, `SNMP3`) and dispatch (`match proto { ... }`) to a protocol-scoped modifier loop (`src/parser/{l2,l3,l4,l7}/<protocol>.rs`).
  - **Shared Keyword Rule**: If two branches inside the same `alt` share a keyword prefix that takes different value types (e.g., `TOKEN <u32>` vs `TOKEN <str>`, or `VERSION <u8>` vs `VERSION <str>`), **NEVER** write `preceded(Token::TokenKw, cut_err(parse_u32))` as an `alt` branch alongside `preceded(Token::TokenKw, cut_err(parse_str))`—`cut_err` converts a type mismatch on the first branch into a fatal `ErrMode::Cut`, aborting the `alt` before trying the second branch! Instead, parse the shared keyword once and wrap the union of valid value types inside a single `cut_err`: `preceded(Token::TokenKw, cut_err(alt((parse_u32_val, parse_str_val))))`.
  - **Zero-Argument Flag Rule**: Never let a 0-argument flag keyword (`ACK`, `SYN`, `FIN`, `RST`, `DF`, `MF`) shadow a keyword-value modifier in another protocol (`ACK <u32>`); scope 0-arg flags strictly to their owning protocol parser.

## 3. Repetition, Folding & Zero-Allocation `Accumulate<T>` Sinks
- **`repeat` & `separated` Range Bounds & Zero-Length Guardrail**:
  - Use `repeat(0.., p)`, `repeat(1.., p)`, `repeat(n, p)`, or `repeat(m..=n, p)` and `separated(range, item, sep)` instead of legacy `many0`/`many1`/`count`/`separated_list0`.
  - **Debug Panic Guardrail**: `repeat`, `separated`, `escaped`, and `take_escaped` panic in debug mode (and error in release mode) if the inner parser succeeds while consuming `0` tokens/bytes! Ensure every inner loop parser consumes at least `1` token (`1..`, never `0..`).
- **Zero-Allocation `Accumulate<T>` Targets (`()` vs `Vec<()>`)**:
  - `repeat` and `separated` return any type implementing `Accumulate<T>`:
    - **`()` (Zero-Allocation Sink)**: When a loop mutates state in a captured `&mut Spec` closure (`repeat(0.., |input| { ...; Ok(()) })`), **ALWAYS** bind the result to `()` (`let (): () = repeat(0.., ...).parse_next(input)?;`), **NEVER** `let _: Vec<()> = repeat(0.., ...)` (note: `src/parser/mod.rs:262` currently uses `let _: Vec<()>` which needlessly tracks a `Vec<()>`).
    - **`usize` (Zero-Allocation Counter)**: `let count: usize = repeat(0.., p).parse_next(input)?;` counts matches with zero heap allocation.
    - **`(C, usize)`**: Collects items into collection `C` alongside the item count.
- **Stateful Folding & Top-Level Iteration**:
  - Use `repeat(range, p).fold(init_fn, |acc, item| ...)` (or `.verify_fold(...)`, `.try_fold(...)`) to reduce elements on-the-fly without allocating a `Vec`.
  - Use `parser.parse_iter(&mut input)` (`ParseIter`, or `iterator(&mut input, parser)`) for lazy top-level iteration before calling `.finish()`.

## 4. Built-In Pratt Expression Parsing (`combinator::expression`)
- **Use `expression()` for Operator Precedence**:
  - Use `winnow::combinator::expression(operand_parser).current_precedence_level(0).prefix(dispatch! { ... }).infix(dispatch! { ... }).postfix(dispatch! { ... })` with `Prefix(power, ...)`, `Postfix(power, ...)`, and `Infix::{Left, Right, Neither}(power, ...)`.

## 5. Error Modalities (`Backtrack` vs `Cut`) & Rich Diagnostics
- **Commit After Unambiguous Prefixes (`cut_err`)**:
  - Wrap the remainder of a grammar rule in `cut_err(...)` (`ErrMode::Backtrack` -> `ErrMode::Cut`) immediately after consuming a unique keyword or opening delimiter (`HOST`, `FLOW`, `COMPILE`, `{`, `(`).
- **Zero-Allocation `StrContext` Annotations**:
  - Attach static diagnostic context at rule boundaries using `.context(StrContext::Label("host block"))` and `.context(StrContext::Expected(StrContextValue::Description("IP address") | StrContextValue::StringLiteral("IP") | StrContextValue::CharLiteral('}')))`.
- **Guard `alt` Error Reporting & Debugging**:
  - Attach `.context(StrContext::Label(...))` to the `alt` / `dispatch!` block as a whole (or on a final `_ => fail.context(...)` arm).
  - Use `TreeError<I, StrContext>` or `cargo test --features winnow/debug` with `winnow::combinator::trace("name", parser)` when debugging complex backtracking.

## 6. Stream Selection, Two-Phase `TokenSlice` & `memchr` SIMD Acceleration
- **Enable `features = ["simd"]` in `Cargo.toml` (`memchr 2.8.3`)**:
  - Always configure `winnow = { version = "1.0.4", features = ["simd"] }` in `Cargo.toml`. Enabling `"simd"` activates `memchr::memchr` / `memchr2` / `memchr3` SIMD vectorization for 1–3 byte `ContainsToken` sets (`take_while`, `take_till`) and `memchr::memmem::Finder` for `FindSlice` (`take_until`, `literal`). (QA note: `Cargo.toml` currently specifies `winnow = "1.0.4"` without `features = ["simd"]` even though `memchr 2.8.3` is already in `Cargo.lock`!)
- **Two-Phase Lexing with `TokenSlice<'t, T>`**:
  - Wrap lexed `&'t [SpannedToken<'a>]` in `TokenSlice::new(&tokens)`.
  - Implement `winnow::stream::Location` (`previous_token_end -> self.span.end`, `current_token_start -> self.span.start`), `PartialEq<Token<'a>>`, and `ContainsToken<&'t SpannedToken<'a>>` on `SpannedToken<'a>` so `.span()`, `.with_span()`, `literal(...)`, and `one_of([...])` work natively on token streams.
- **Byte/String Streams, `LocatingSlice<I>`, `Stateful<I, S>` & `Recoverable<I, E>`**:
  - For single-phase text/binary parsing, choose `&'i str`, `&'i BStr`, or `&'i Bytes`, wrapped in `LocatingSlice::new(input)` for `.span()` tracking and `Stateful { input, state }` for recursion depth or symbol tables.
  - For multi-error recovery (`features = ["unstable-recover"]`), use `Recoverable<I, E>` with `.retry_after(...)` / `.resume_after(...)`.

## 7. Value Conversion, Chaining (`flat_map`, `and_then`) & Legacy Migration
- **Recognize First, Convert Second**:
  - Recognize raw slices with `.take()` / `.with_taken()`, then convert via `.parse_to::<T>()`, `.try_map(|x| ...)`, or `.verify_map(|x| ...)`.
  - Use `.and_then(sub_parser)` to run a second parser over the output slice of the first parser, and `.flat_map(|out| next_parser(out))` for dependent/TLV parsing.
- **Canonical FrameAssembly Syntax in Parser Examples**:
  - Never use `=` or `:` in FrameAssembly `HOST` or L2–L7 modifier examples (always space-separated `IP 10.0.0.1`, `TTL 64 DSCP 46 ECN 2 FLOWLABEL 0x12345`).
- **Avoid Legacy `nom` / `winnow 0.5–0.6` APIs**:
  - Use `ModalResult` (not `PResult`/`IResult`), `literal` (not `tag`), `Caseless` (not `tag_no_case`), `.take()`/`.with_taken()` (not `recognize`), `.span()`/`.with_span()` (not `located`), `repeat` (not `many0`/`many1`/`fold_repeat`), `separated` (not `separated_list0`), and `unordered_seq!` (not `permutation`).
