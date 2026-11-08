---
name: winnow-parser
description: Comprehensive guide, combinator selection matrix, and production code templates for building high-performance, zero-copy parsers in Rust with winnow 1.0.5+ and memchr 2.8.3 (including zero-copy 3-tuple token streams, TokenSlice bridges, 3-tier protocol-scoped dispatch, Pratt expression() parsing, LocatingSlice spans, Stateful recursion tracking, StrContext + miette diagnostics, and BStr byte-stream parsing).
---

# Winnow 1.0.5+ Parser Engineering Skill

Use this skill when designing, implementing, debugging, or optimizing parsers using `winnow` (`1.0.5+`) and `memchr` (`2.8.3`) in Rust.

## 1. Quick Combinator Selection Matrix

| Parsing Goal | Idiomatic `winnow 1.0.5+` API | Avoid (Legacy / Suboptimal / Anti-Pattern) |
| :--- | :--- | :--- |
| Top-level entry point (complete input) | `parser.parse(input)` | `parser.parse_peek(input)` or manual `eof` |
| Parser function signature | `fn foo<'i, 'a>(input: &mut Stream<'i, 'a>) -> ModalResult<O>` | `fn foo(input: I) -> IResult<I, O>` |
| Struct / tuple sequencing | `seq! { Foo { a: p1, _: ':', b: p2 } }` | Nested `preceded`/`terminated`/`.map()` |
| Order-independent struct fields | `unordered_seq! { Foo { a: p1, b: p2 } }` | `permutation((...))` (deprecated) |
| Branching on leading token/byte | `dispatch! { peek(any); Token::Tcp => ..., _ => fail }` | Deep `alt((...))` chains ($O(N)$ backtracking) |
| Choice over > 21 uniform branches | `dispatch!` or `alt(&mut [p1, p2, ...])` | Deeply nested `alt((alt((...)), ...))` |
| Shared keyword with multiple value types | `(tag(Token::Area), cut_err(alt((parse_u32, parse_any_str))))` | `alt((preceded(kw, cut_err(val_a)), preceded(kw, cut_err(val_b))))` |
| Operator precedence (Pratt) | `combinator::expression(atom).prefix(...).infix(...)` | Hand-rolled recursive precedence climbing |
| Zero-copy slice capture | `parser.take()` / `parser.with_taken()` | `recognize(parser)` / `with_recognized(parser)` |
| Source byte range (`Range<usize>`) | `parser.span()` / `parser.with_span()` | `located` / manual pointer arithmetic |
| Zero-allocation side-effect loop | `let (): () = repeat(0.., p).parse_next(input)?;` (as in `src/parser/mod.rs`) | `let _: Vec<()> = repeat(0.., p)...` |
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
| SIMD byte/substring scanning | `winnow = { version = "1.0.5", features = ["simd"] }` | Omitting `"simd"` when `memchr 2.8.3` is already in `Cargo.lock` |

---

## 2. Architecture Decision Guide

1. **Two-Phase Token Streams (`Stream<'i, 'a>` vs. `TokenSlice<'t, T>`) & Single-Phase Byte Streams**:
   - **FrameAssembly Zero-Copy 3-Tuple Slice Stream (`src/parser/mod.rs`)**: `FrameAssembly` defines `pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)];`, pairing each `logos 0.14.4` `Token<'a>` with its byte range and exact original `&'a str` slice (preserving wire casing for bareword identifiers while keeping keywords case-insensitive). Leaf combinators (`tag(expected: Token<'a>)`, `parse_spanned_ident`) match directly against `(t, span, raw_str)` tuples with zero wrapper overhead.
   - **Standalone `winnow::stream::TokenSlice<'t, SpannedToken<'a>>`**: When building standalone token-stream parsers outside `Stream<'i, 'a>`, wrap `&[SpannedToken<'a>]` in `TokenSlice` and implement `Location`, `PartialEq<Token<'a>>`, and `ContainsToken` on `SpannedToken<'a>` so `.span()`, `.with_span()`, `literal(...)`, and `one_of([...])` work natively.
   - **Single-Phase Byte/String Stream**: Prefer `&'i BStr` (or `LocatingSlice<&'i BStr>`) with `features = ["simd"]` enabled (`memchr 2.8.3`) so 1–3 byte `ContainsToken` sets (`take_while`, `take_till`) dispatch to `memchr::memchr`/`memchr2`/`memchr3` and `FindSlice` (`take_until`) uses `memchr::memmem::Finder`.

2. **Three-Tier Protocol-Scoped Dispatch & The Shared-Keyword `cut_err` Rule**:
   - **3-Tier Statement Modifier Loop (`src/parser/statement.rs` & `src/parser/fields.rs`)**:
     1. **Tier 1 (`parse_universal_field`)**: Parses `WAIT`, `PAYLOAD`, `HEXPAYLOAD`, and universal L2/L3/L4 header fields—**explicitly bypassing `Token::Ack` and `Token::Rst`** when `current_protocol` is `Coap`, `Dhcp`, `Tftp`, or `Sip` so protocol message types are never misparsed as TCP flags.
     2. **Tier 2 (`dispatch_protocol_field`)**: Once `current_protocol` is known, dispatches via `match proto` directly to `src/parser/{l2,l3,l4,l7}/<protocol>.rs` before trying other protocols.
     3. **Tier 3 (`parse_fallback_field`)**: Scans protocol declarations and modifiers when `current_protocol` has not yet appeared on the line (supporting modifiers placed before the protocol keyword, e.g., `a -> b VLAN 100 DSCP 46 ICMP ECHO_REQUEST`).
     - Always save `let saved = *input;` before each tier: on `Err(ErrMode::Backtrack(_))`, restore `*input = saved;`; on `Err(ErrMode::Cut(e))`, propagate immediately.
   - **CRITICAL Shared-Keyword `cut_err` Rule**:
     - **Never** place `preceded(SharedKeyword, cut_err(TypeA))` and `preceded(SharedKeyword, cut_err(TypeB))` as sibling branches in an `alt`: once `SharedKeyword` (`TOKEN`, `VERSION`, `STATUS`, `VALUE`, `DCID`, `SCID`, `AREA`, `PORT_ID`, `GROUP`) matches the first branch, `cut_err(TypeA)` turns a type mismatch into a fatal `ErrMode::Cut` and prevents `alt` from trying `TypeB`! Parse `SharedKeyword` once and put `alt((TypeA, TypeB))` *inside* `cut_err`.

3. **Zero-Allocation `repeat` Accumulators & Loop Safety**:
   - When `repeat(0.., ...)` mutates captured state in place (such as `ip` and `mac` inside `parse_host_def` in `src/parser/mod.rs`) and returns `Ok(())`, always annotate the output type as unit `()` (`let (): () = repeat(0.., ...).parse_next(input)?;`), never `let _: Vec<()>`.
   - Never pass a parser that can succeed while consuming `0` tokens to `repeat`, `separated`, `escaped`, or `take_escaped`—`winnow` panics in debug builds on 0-length loop iterations.

4. **State Management (`Stateful<I, S>`) & Error Recovery (`Recoverable<I, E>`)**:
   - Thread recursion depth limits, symbol interners, or arena references via `Stateful { input, state }` instead of `RefCell` or thread-locals.
   - For multi-error IDE/LSP recovery (`features = ["unstable-recover"]`), wrap streams in `Recoverable<I, E>` and synchronize with `.retry_after(...)` or `.resume_after(...)`.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations:
1. **Two-Phase Lexing Bridge (FrameAssembly 3-Tuple `Stream<'i, 'a>` + Standalone `TokenSlice` + `Location` + `ContainsToken`)**
2. **High-Performance Declarative DSL AST Parsing (`HOST`, `FLOW`, `COMPILE` with `seq!`, `cut_err`, `repeat`, `opt`)**
3. **3-Tier Protocol-Scoped Dispatch, Space-Separated L3 Modifiers & Shared-Keyword `cut_err` Factoring**
4. **Built-In Pratt Precedence Climbing Expression Parser (`combinator::expression`)**
5. **Zero-Copy String Unescaping & Hex Byte Stream Decoding (`Cow<'i, str>`, `\xHH`, `\u{...}`)**
6. **Stateful Recursion Tracking & Symbol Interning (`Stateful<LocatingSlice<I>, State>`)**
7. **Binary TLV, Bitfields & Packet Dissection (`length_and_then`, `binary::bits`)**
8. **Rich Diagnostic Integration with `miette` (`CompilerParseError` from `winnow::error::ParseError`)**
