---
trigger: glob
globs: "src/parser/**/*.rs, Cargo.toml, tests/**/*.rs"
description: "Winnow 1.0.5+ and memchr 2.8.3 zero-copy 3-tuple Stream combinators, protocol-first whois disambiguation, 3-tier protocol-scoped dispatch, shared-keyword cut_err rules, and zero-allocation sinks."
---

# Winnow 1.0.5+ Parsing Architecture & Best Practices

Enforce these zero-copy, high-performance `winnow` (`1.0.5+`) and `memchr` (`2.8.3`) parser engineering rules across `src/parser/`:

## 1. Stream Representation & Core Combinator Signatures
- **FrameAssembly Zero-Copy 3-Tuple Slice Stream (`src/parser/mod.rs`)**:
  - `FrameAssembly` defines `pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)];`, pairing each `logos` `Token<'a>` with its byte range and exact original `&'a str` slice (preserving wire casing for barewords and flexible user identifiers while matching strict-lowercase v3.0.0 built-in keywords).
  - Every parser function uses `&mut Stream<'i, 'a>` and returns `winnow::ModalResult<O>` (`PResult<O>`, alias for `Result<O, ErrMode<ContextError>>`):
    ```rust
    pub(crate) fn parse_item<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<Output<'a>>
    ```
  - *(Alternative for standalone sub-parsers)*: When building standalone parsers outside `Stream<'i, 'a>`, wrap `&[SpannedToken]` in `winnow::stream::TokenSlice` (implementing `Location`, `PartialEq`, `ContainsToken`) or wrap byte/string slices in `LocatingSlice` / `Stateful`.
- **Enable SIMD Acceleration (`memchr 2.8.3`)**:
  - Configure `winnow = { version = "1.0.5", features = ["simd"] }` in `Cargo.toml` (`memchr 2.8.3` is already in `Cargo.lock`, so enabling `"simd"` activates vectorized byte/slice scanning at zero extra dependency cost).
- **Avoid Deep `-> impl Parser` Return Chains**: Keep grammar productions as concrete `fn(&mut Stream<'i, 'a>) -> PResult<O>` functions to minimize monomorphization bloat and compile times; reserve `-> impl Parser` strictly for small leaf helpers like `tag(expected: Token<'a>)`.

## 2. Protocol-First Disambiguation, Three-Tier Dispatch & Shared-Keyword `cut_err` Rules
- **3-Tier Statement Modifier Loop (`src/parser/statement.rs` & `src/parser/fields.rs`)**:
  1. **Tier 1 (`parse_universal_field`)**: Parses `wait`, `payload`, `hexpayload`, and universal L2/L3/L4 header fields—**explicitly bypassing `Token::Ack` and `Token::Rst`** when `current_protocol` is `Coap`, `Dhcp`, `Tftp`, or `Sip` so protocol message types are never misparsed as TCP flags!
  2. **Tier 2 (`dispatch_protocol_field`)**: Once `current_protocol` is known, dispatches via `match proto` directly to `src/parser/{l2,l3,l4,l7}/<protocol>.rs` before trying other protocols.
  3. **Explicit Protocol-Keyword Check -> Tier 3 (`parse_fallback_field`)**: When `current_protocol.is_none()`, **first** check explicit protocol keywords (so `a -> b whois domain "example.com"` always sets `Protocol::Whois` instead of being intercepted alphabetically by BACnet's `Token::Whois` in `parse_bacnet_field`!), and then fall through to `parse_fallback_field` for modifiers placed before the protocol keyword (e.g., `a -> b vlan 100 dscp 46 icmp echorequest`).
  - On `Err(ErrMode::Backtrack(_))`, restore `*input = saved;`; on `Err(ErrMode::Cut(e))`, propagate immediately!
- **CRITICAL Shared-Keyword `cut_err` & Unified Modifier Rules**:
  - **NEVER** place `preceded(SharedKw, cut_err(parse_u32))` and `preceded(SharedKw, cut_err(parse_str_val))` as sibling branches in `alt((...))`! Once `SharedKw` (`token`, `version`, `status`, `value`, `dcid`, `scid`, `area`, `portid`, `group`) matches branch 1, `cut_err` converts a type mismatch into a fatal `ErrMode::Cut`, aborting `alt` before branch 2 runs!
  - **Correct Pattern**: Either consume the keyword once and wrap `alt` *inside* `cut_err`:
    ```rust
    (tag(Token::Area), cut_err(alt((
        parse_u32.map(|v| ...),
        parse_any_str.map(|v| ...),
    ))))
    ```
    or omit `cut_err` on the non-final overloaded branch so `Backtrack` falls through to the string branch cleanly.
  - **Unified `hellotime`**: Both STP (`u16`) and HSRP (`<= 255` `u8`, validated in `validation.rs`) share `Token::HelloTime` (`ParsedField::HelloTime`), avoiding duplicate lexer tokens.
- **Contextual Identifiers (`parse_spanned_ident`)**: Every built-in keyword in `Token<'a>` (including promoted v3.0.0 tokens `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`) is automatically usable as a `host`, `flow`, or parameter identifier via `parse_spanned_ident` as long as punctuation and literal variants remain excluded in `src/parser/ident.rs` (never add `PartialEq` string hacks on `Token::Ident` for pseudo-keywords).

## 3. Zero-Allocation `Accumulate<T>` Sinks & Loop Safety
- **Bind Side-Effect `repeat` Loops to `()` (Never `Vec<()>`)**:
  - `winnow::combinator::repeat` returns any `Accumulate<T>`. When mutating captured variables in place (such as `ip` and `mac` inside `parse_host_def` in `src/parser/mod.rs`), **always** bind the sink to unit `()`:
    ```rust
    let (): () = repeat(
        0..,
        alt((
            (tag(Token::Ip), cut_err(parse_ip)).map(|(_, i)| ip = Some(i)),
            (tag(Token::Mac), cut_err(parse_mac)).map(|(_, m)| mac = Some(m)),
        )),
    )
    .parse_next(input)?;
    ```
    Never write `let _: Vec<()> = repeat(0.., ...)`.
- **Zero-Token Infinite-Loop Guardrail**: `repeat` and `separated` panic in debug builds if the inner parser succeeds while consuming `0` tokens. Every `repeat` body must consume at least `1` token on `Ok` (never wrap the entire `repeat` body in `opt(...)`).

## 4. Modern `winnow 1.0.5+` Idioms (Zero Legacy `nom` APIs)
- Use `ModalResult` (never `IResult`), `seq!` / `unordered_seq!` (never `permutation`), `dispatch!` (for $O(1)$ prefix jump tables), `repeat` / `separated` (never `many0` / `separated_list0`), `literal` / `Caseless` (never `tag_no_case`), and `.take()` / `.with_taken()` (never `recognize`).
