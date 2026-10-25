---
name: winnow-parser
description: Comprehensive guide, combinator selection matrix, and production code templates for building high-performance, zero-copy parsers in Rust with winnow 1.0+ (including logos + TokenSlice two-phase lexing, Pratt expression() parsing, LocatingSlice spans, Stateful recursion tracking, StrContext + miette diagnostics, and BStr byte-stream parsing).
---

# Winnow 1.0.4+ Parser Engineering Skill

Use this skill when designing, implementing, debugging, or optimizing parsers using `winnow` (`1.0.4+`) and `memchr` (`2.8.3`) in Rust.

## 1. Quick Combinator Selection Matrix

| Parsing Goal | Idiomatic `winnow 1.0.4+` API | Avoid (Legacy / Suboptimal / Anti-Pattern) |
| :--- | :--- | :--- |
| Top-level entry point (complete input) | `parser.parse(input)` | `parser.parse_peek(input)` or manual `eof` |
| Parser function signature | `fn foo<'i, 'a>(input: &mut Stream<'i, 'a>) -> ModalResult<O>` | `fn foo(input: I) -> IResult<I, O>` |
| Struct / tuple sequencing | `seq! { Foo { a: p1, _: ':', b: p2 } }` | Nested `preceded`/`terminated`/`.map()` |
| Order-independent struct fields | `unordered_seq! { Foo { a: p1, b: p2 } }` | `permutation((...))` (deprecated) |
| Branching on leading token/byte | `dispatch! { peek(any); Token::Tcp => ..., _ => fail }` | Deep `alt((...))` chains ($O(N)$ backtracking) |
| Choice over > 21 uniform branches | `dispatch!` or `alt(&mut [p1, p2, ...])` | Deeply nested `alt((alt((...)), ...))` |
| Shared keyword with multiple value types | `preceded(kw, cut_err(alt((val_a, val_b))))` | `alt((preceded(kw, cut_err(val_a)), preceded(kw, cut_err(val_b))))` |
| Operator precedence (Pratt) | `combinator::expression(atom).prefix(...).infix(...)` | Hand-rolled recursive precedence climbing |
| Zero-copy slice capture | `parser.take()` / `parser.with_taken()` | `recognize(parser)` / `with_recognized(parser)` |
| Source byte range (`Range<usize>`) | `parser.span()` / `parser.with_span()` | `located` / manual pointer arithmetic |
| Zero-allocation side-effect loop | `let (): () = repeat(0.., p).parse_next(input)?;` | `let _: Vec<()> = repeat(0.., p)...` (`src/parser/mod.rs:262`) |
| Zero-allocation repetition count | `let n: usize = repeat(0.., p).parse_next(input)?;` | `many0(p).map(\|v\| v.len())` |
| Stateful accumulation | `repeat(0.., p).fold(init, acc_fn)` | `fold_repeat` |
| Lazy top-level stream iteration | `parser.parse_iter(&mut input)` (`ParseIter`) | Collecting all items into an intermediate `Vec` |
| Dependent / chained sub-parsing | `p1.flat_map(\|v\| p2(v))` / `p1.and_then(sub_parser)` | Manual nested `parse_peek` calls |
| Commit to branch (syntax error) | `cut_err(parser)` (`ErrMode::Cut`) | Returning `Backtrack` after consuming unique keyword |
| Static diagnostic context | `.context(StrContext::Label("..."))` | Allocating custom error strings on backtrack |
| Case-insensitive literal | `Caseless("select")` | `tag_no_case("select")` |
| String / slice -> `FromStr` type | `parser.take().parse_to::<T>()` | `map_res` |
| Fallible `Result<O, E>` conversion | `parser.try_map(\|x\| ...)` | `map_res` |
| Fallible `Option<O>` conversion | `parser.verify_map(\|x\| ...)` | `map_opt` |
| SIMD byte/substring scanning | `winnow = { version = "1.0.4", features = ["simd"] }` | Omitting `"simd"` when `memchr 2.8.3` is already in `Cargo.lock` |

---

## 2. Architecture Decision Guide

1. **Two-Phase (`logos 0.14.4` + `TokenSlice`) vs. Single-Phase (`&str` / `&BStr` / `LocatingSlice`)**:
   - **Two-Phase Lexer + `TokenSlice<'t, SpannedToken<'a>>`**: Used by `frameassembly` (`Stream<'i, 'a> = TokenSlice<'i, SpannedToken<'a>>`). Implement `Location`, `PartialEq<Token<'a>>`, and `ContainsToken` on `SpannedToken<'a>` so `.span()`, `.with_span()`, `literal(...)`, and `one_of([...])` work with zero boilerplate.
   - **Single-Phase Byte/String Stream**: Prefer `&'i BStr` (or `LocatingSlice<&'i BStr>`) with `features = ["simd"]` enabled so 1–3 byte `ContainsToken` sets (`take_while`, `take_till`) dispatch to `memchr::memchr`/`memchr2`/`memchr3` and `FindSlice` (`take_until`) uses `memchr::memmem::Finder`.

2. **Protocol-Scoped Dispatch & The Shared-Keyword `cut_err` Rule**:
   - Always dispatch on the protocol token (`TCP`, `UDP`, `DNS`, `COAP`, `HTTP`, `SNMP3`) first, then loop over protocol-scoped modifiers using `let (): () = repeat(0.., ...).parse_next(input)?;`.
   - **Never** place `preceded(SharedKeyword, cut_err(TypeA))` and `preceded(SharedKeyword, cut_err(TypeB))` as sibling branches in an `alt`: once `SharedKeyword` matches the first branch, `cut_err(TypeA)` turns a type mismatch into a fatal `ErrMode::Cut` and prevents `alt` from trying `TypeB`! Parse `SharedKeyword` once and put `alt((TypeA, TypeB))` *inside* `cut_err`.

3. **Zero-Allocation `repeat` Accumulators & Loop Safety**:
   - When `repeat(0.., ...)` mutates a `&mut Spec` in place and returns `Ok(())`, always annotate the output type as unit `()` (`let (): () = repeat(0.., ...).parse_next(input)?;`), never `let _: Vec<()>`.
   - Never pass a parser that can succeed while consuming `0` tokens to `repeat`, `separated`, `escaped`, or `take_escaped`—`winnow` panics in debug builds on 0-length loop iterations.

4. **State Management (`Stateful<I, S>`) & Error Recovery (`Recoverable<I, E>`)**:
   - Thread recursion depth limits, symbol interners, or arena references via `Stateful { input, state }` instead of `RefCell` or thread-locals.
   - For multi-error IDE/LSP recovery (`features = ["unstable-recover"]`), wrap streams in `Recoverable<I, E>` and synchronize with `.retry_after(...)` or `.resume_after(...)`.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations:
1. **Two-Phase Lexing Bridge (`logos` + `TokenSlice` + `Location` + `ContainsToken`)**
2. **High-Performance Declarative DSL AST Parsing (`HOST`, `FLOW`, `COMPILE` with `seq!`, `cut_err`, `repeat`, `opt`)**
3. **Canonical Space-Separated L3 Modifier Extraction & Shared-Keyword `cut_err` Dispatch (`TTL`, `DSCP`, `ECN`, `DF`/`MF`, `FLOWLABEL`)**
4. **Built-In Pratt Precedence Climbing Expression Parser (`combinator::expression`)**
5. **Zero-Copy String Unescaping & Hex Byte Stream Decoding (`Cow<'i, str>`, `\xHH`, `\u{...}`)**
6. **Stateful Recursion Tracking & Symbol Interning (`Stateful<LocatingSlice<I>, State>`)**
7. **Binary TLV, Bitfields & Packet Dissection (`length_and_then`, `binary::bits`)**
8. **Rich Diagnostic Integration with `miette` (`CompilerParseError` from `winnow::error::ParseError`)**
