---
trigger: always_on
description: "Rust 2024 Edition and rustc 1.85-1.99.1 idioms, zero-copy slice helpers, soundness rules, and centralized Cargo lints."
---

# Rust 2024 Edition & Modern Rust Best Practices (1.85–1.99.1)

Always enforce these idiomatic, performant, and sound `rustc 1.99.1` (`clippy 0.1.99`, Edition 2024) architectural standards across all crate implementations, test suites, protocol builders, and compiler frontends:

---

## 1. Edition 2024 Control Flow, Pattern Matching & Rescoping

- **Match Ergonomics & Reference Patterns (Rust 1.85 / Edition 2024)**:
  - Never write explicit `ref`, `ref mut`, or `mut` bindings inside a match or `if let` pattern when matching against reference expressions (`&T` or `&mut T`) where default binding modes apply.
  - Match directly against `&expr` (e.g., `if let Some(val) = &self.field`) and let Edition 2024 infer the borrow mode automatically.
  - Avoid mixing explicit `&` reference patterns with bare reference-binding identifiers in the same nested pattern.
- **Temporary Drop Order (`if_let_rescope` & `tail_expr_drop_order`, Edition 2024)**:
  - Temporaries created in the scrutinee of `if let <pat> = <expr> { ... } else { ... }` are dropped *before* entering the `else` branch (fixing `MutexGuard` / `RefCell` borrow-across-`else` deadlocks).
  - Temporaries in block/function tail expressions drop *before* local variables in that block. Never rely on a tail-expression temporary outliving a local variable.
- **`let ... else` Precondition Guards**:
  - Use `let Some(x) = opt else { return ...; };` or `let Ok(val) = res else { return ...; };` for early error exits, validation gates, and loop `continue` paths.
- **Chained `if let` & `while let` Conditions (`let_chains`, Rust 1.88.0)**:
  - Replace nested `if let` pyramids with flat boolean and pattern chains using `&&`:
    ```rust
    if let Some(a) = opt_a && let Ok(b) = parse(a) && b > 0 {
        process(b);
    }
    ```
- **`if let` Match Guards (Rust 1.95.0)**:
  - Use `if let` pattern guards directly on `match` arms to avoid duplicate fallback logic:
    ```rust
    match event {
        Event::Message(msg) if let Some(payload) = extract_payload(msg) => handle(payload),
        Event::Message(_) => log_ignored(),
        Event::Close => shutdown(),
    }
    ```
- **Compile-Time Conditional Dispatch (`cfg_select!`) & Pattern Assertions**:
  - Prefer `std::cfg_select! { ... }` (Rust 1.95.0) over chained `#[cfg(...)]` blocks for mutually exclusive target selection.
  - Use `std::assert_matches::assert_matches!` and `debug_assert_matches!` (Rust 1.96.0) in unit tests instead of verbose `assert!(matches!(...))`.

---

## 2. Lifetimes & Return-Position `impl Trait` (RPIT) with `+ use<...>`

- **Edition 2024 RPIT Capture-All Default**:
  - In Edition 2024, Return-Position `impl Trait` (RPIT) captures all in-scope generic type and lifetime parameters by default.
  - When a returned `impl Trait` does NOT borrow from an input reference parameter, restrict captured generics with precise capturing syntax `+ use<...>`:
    ```rust
    fn parse_tokens<'a, 'b>(
        input: &'a str,
        _context: &'b str,
    ) -> impl Iterator<Item = Token<'a>> + use<'a> {
        tokenize(input)
    }
    ```
  - For independent or `'static` iterators, specify an empty capture list: `-> impl Iterator<Item = u32> + use<>`.
- **Explicit Elided Lifetime Markers (`mismatched_lifetime_syntaxes`, Rust 1.89.0)**:
  - Always write explicit elided lifetime markers (`'_`) on returned types that borrow from elided input references (e.g., `fn iter(&self) -> Iter<'_, T>`, `fn as_slice(&self) -> Span<'_>`).

---

## 3. Concurrency, Atomics, `LazyLock` & Modern Closures

- **Absolute Prohibition on `static mut`**:
  - Never declare or reference `static mut` variables; `static_mut_refs` is a deny-by-default compiler error in Edition 2024.
  - Use `std::sync::LazyLock<T>` (with `LazyLock::get`, `get_mut`, `force_mut` from Rust 1.94.0) or `std::sync::OnceLock<T>` for global state.
- **Concrete Typed Atomics vs. Unstable `Atomic<T>`**:
  - **CRITICAL GUARDRAIL**: Generic `std::sync::atomic::Atomic<T>` remains **unstable** (`#![feature(generic_atomic)]`, E0658) in `rustc 1.99.1`. Always use concrete typed atomics (`AtomicU64`, `AtomicUsize`, `AtomicU32`, `AtomicBool`) and their stabilized `.update(Ordering, Ordering, |v| ...)` / `.try_update(...)` CAS helpers (Rust 1.95.0).
- **Native Async Closures (Rust 1.85.0)**:
  - Use `AsyncFn`, `AsyncFnMut`, and `AsyncFnOnce` trait bounds with native `async || {}` closures instead of two-parameter `Fn() -> Fut` bounds.

---

## 4. High-Performance Slice, Array & Zero-Copy Span Acceleration

- **Chunked Iteration via `as_chunks` (Rust 1.88.0)**:
  - Prefer `slice.as_chunks::<N>()` (`as_chunks_mut`, `as_rchunks`, stabilized as `const fn` in Rust 1.88.0) over manual index stepping (`chunks_exact(N)`):
    ```rust
    let (chunks, remainder) = slice.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    ```
- **Fixed-Size Array Slicing & Windows (`as_array`, `array_windows`)**:
  - Use `<[T]>::as_array::<N>()` and `as_mut_array::<N>()` (`const fn`, Rust 1.93.0) or inferred const generic `[u8; _]` (Rust 1.89.0) to borrow fixed-size arrays without runtime loop bounds checks.
  - Prefer `<[T]>::array_windows::<N>()` (`const fn`, Rust 1.94.0) over `.windows(N)` in wire/corpus scanners so window elements destructure directly as `&[T; N]`:
    ```rust
    let has_magic = bytes.array_windows::<4>().any(|w| w == b"\x0a\x0d\x0d\x0a");
    ```
- **Zero-Copy Parser Span Recovery (`substr_range` & `subslice_range`, Rust 1.98.0)**:
  - Use `source.substr_range(subslice)` (`Option<Range<usize>>`) and `slice.subslice_range(subslice)` (or `<[T]>::element_offset` from Rust 1.94.0) to recover $O(1)$ byte/token spans from borrowed subslices without `unsafe` pointer subtraction.
- **Disjoint Mutable Indexing & Owned Array Iteration**:
  - Use `<[T]>::get_disjoint_mut` and `HashMap::get_disjoint_mut` (Rust 1.86.0) for simultaneous non-overlapping mutable borrows.
  - `Box<[T]>::into_iter()` (Edition 2024 / Rust 1.85.0) and `Box<[T; N]>::into_iter()` (Rust 1.99.0) yield owned `T` values by value.
- **`std::net` Stability Guardrail**:
  - `Ipv4Addr::to_bits`/`from_bits` and `Ipv6Addr::to_bits`/`from_bits` are stable, whereas `Ipv4Addr::is_benchmarking()`, `is_shared()`, `is_ietf_protocol_assignment()`, and `Ipv6Addr::is_documentation()` remain **unstable** (`#![feature(ip)]`, E0658) in `rustc 1.99.1`. Implement RFC 2544 / RFC 6598 / RFC 3849 prefix checks via bitmasks on `.to_bits()`.

---

## 5. Unsafe Soundness, FFI & Pointer Hygiene

- **`unsafe_op_in_unsafe_fn` & `// SAFETY:` Comments**:
  - In Edition 2024, `unsafe fn` bodies are checked as safe code by default. Wrap each individual unsafe operation in a minimal `unsafe { ... }` block preceded by a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks`).
- **FFI Blocks & Unsafe Attributes (Edition 2024)**:
  - Declare external blocks as `unsafe extern "C" { ... }` and mark verified memory-safe functions `safe fn`.
  - Wrap unsafe attributes in `#[unsafe(...)]`: `#[unsafe(no_mangle)]`, `#[unsafe(export_name = "...")]`, `#[unsafe(link_section = "...")]`.
- **Raw Pointers & Process Environment**:
  - Construct raw pointers via `&raw const expr` / `&raw mut expr` (avoiding `raw_borrows_via_references`, Rust 1.99.0, and `dangling_pointers_from_temporaries`, Rust 1.91.0).
  - Never call `std::env::set_var` or `std::env::remove_var` (marked `unsafe fn` in Edition 2024 due to multi-threaded data races); pass environment maps via `std::process::Command::env`.

---

## 6. Rust 1.85.0–1.99.1 Stabilization Reference Matrix

| Version | Key Stabilized Language, Compiler & Stdlib Features |
| :--- | :--- |
| **1.85.0** | Edition 2024: match ergonomics (`ref`/`mut` restriction), RPIT capture-all + `+ use<...>`, `if_let_rescope`, `tail_expr_drop_order`, `AsyncFn*`, `unsafe_op_in_unsafe_fn`, `static_mut_refs` (deny), `unsafe extern "C"` + `safe fn`, `#[unsafe(no_mangle)]`, `unsafe` `env::set_var`, `Box<[T]>::into_iter()`, merged doctests |
| **1.86.0** | Trait upcasting (`&dyn Sub` -> `&dyn Super`), `<[T]>::get_disjoint_mut`, `HashMap::get_disjoint_mut`, safe `#[target_feature]` |
| **1.88.0** | `let_chains` (`if let ... && let ...`, `while let ... && ...`), `<[T]>::as_chunks::<N>()` (`const fn`), `as_chunks_mut`, `as_rchunks` |
| **1.89.0** | `mismatched_lifetime_syntaxes` lint (`'_` required on borrowing return types), inferred const generic arguments (`[u8; _]`) |
| **1.91.0** | `dangling_pointers_from_locals` & `dangling_pointers_from_temporaries` lints, `Path::file_prefix` |
| **1.93.0** | `<[T]>::as_array::<N>()` & `as_mut_array::<N>()` (`const fn`), `Vec::into_raw_parts`, `String::into_raw_parts` |
| **1.94.0** | `<[T]>::array_windows::<N>()` (`const fn`), `<[T]>::element_offset`, `LazyLock::{get, get_mut, force_mut}` |
| **1.95.0** | `if let` match guards (`Pat if let Some(x) = y => ...`), `Atomic*::update` & `try_update`, `std::cfg_select!` |
| **1.96.0** | `std::assert_matches::{assert_matches!, debug_assert_matches!}`, new `core::range::{Range, RangeFrom, RangeToInclusive}` |
| **1.97.0** | `dead_code_pub_in_binary` lint, integer bit manipulation (`isolate_highest_one`, `isolate_lowest_one`, `bit_width`) |
| **1.98.0** | `<[T]>::subslice_range` & `str::substr_range`, stack integer formatting (`core::fmt::NumBuffer`, `{integer}::format_into`) |
| **1.99.0** | `IntoIterator` for `Box<[T; N]>`, `Vec::into_parts`, `raw_borrows_via_references` lint (`1.99.1` toolchain patch) |

---

## 7. Centralized Cargo `[lints]`, Merged Doctests & Multi-Tier QA

- **Centralized `[lints]` Table in `Cargo.toml`**:
  - Define `[lints.rust]`, `[lints.rustdoc]`, and `[lints.clippy]` centrally in `Cargo.toml` rather than duplicating `#![warn(missing_docs)]` and `#![warn(clippy::missing_docs_in_private_items)]` across individual `src/` and `tests/` files:
    ```toml
    [lints.rust]
    missing_docs = "warn"
    unsafe_op_in_unsafe_fn = "warn"

    [lints.rustdoc]
    broken_intra_doc_links = "warn"
    bare_urls = "warn"

    [lints.clippy]
    missing_docs_in_private_items = "warn"
    undocumented_unsafe_blocks = "warn"
    cast_possible_truncation = "warn"
    cast_lossless = "warn"
    large_enum_variant = "warn"
    ```
- **Merged Single-Binary Doctests (`cargo test --doc`)**:
  - Edition 2024 compiles crate doctests into a single binary. Keep Rust doc examples runnable; annotate non-Rust fences explicitly (`text`, `console`) and ensure any `frameassembly`/`fasm` fence is a complete compilable program (`HOST` + `FLOW` + `COMPILE`).
- **4-Tier Testing & Corpus QA**:
  - Partition tests into **Tier 1** (Protocol headers/defaults), **Tier 2** (Boundary/0-byte/65535-byte extremes), **Tier 3** (Cross-layer QinQ/IPv6/TCP state), and **Tier 4** (End-to-end conversational flows), backed by `tests/corpus_verification_tests.rs` and RAII `AtomicU64` temporary file guards.

---

## 8. Summary Checklist & Anti-Pattern Matrix

| # | Anti-Pattern | Correct Edition 2024 (`1.99.1`) Practice | Invariant / Failure Mode Prevented |
|---|---|---|---|
| 1 | Writing `if let Some(ref x) = expr` | Write `if let Some(x) = &expr` | Violates Edition 2024 match ergonomics rules |
| 2 | Using generic `Atomic<T>` in stable code | Use `AtomicU64`/`AtomicBool` + `.update()` | `generic_atomic` is unstable (E0658) in `1.99.1` |
| 3 | Slicing `&buf[i..i+2]` or `.windows(4)` | Use `buf.as_chunks::<2>()` / `array_windows::<4>()` | Eliminates runtime bounds checks; gives `&[T; N]` |
| 4 | Duplicating `#![warn(missing_docs)]` in 7 files | Centralize in `Cargo.toml` `[lints]` table | Ensures uniform lint coverage across all targets |
| 5 | Omitting `'_` on borrowing return types | Write `fn span(&self) -> Span<'_>` | Triggers `mismatched_lifetime_syntaxes` (1.89+) |
| 6 | RPIT capturing unneeded input lifetimes | Restrict via `+ use<'a>` or `+ use<>` | Prevents over-capturing caller borrows in Edition 2024 |
| 7 | Calling `Ipv4Addr::is_benchmarking()` | Mask `ip.to_bits()` directly | `feature(ip)` methods are unstable (E0658) |
| 8 | Calling `std::env::set_var` in tests | Pass env via `Command::env` | `set_var` is `unsafe fn` due to thread data races |
| 9 | Partial snippet in ```` ```frameassembly ```` fence | Use ```` ```text ```` or full `HOST`/`FLOW`/`COMPILE` | Partial `.fasm` blocks fail `corpus_verification_tests` |
| 10| Emitting `0x0000` UDP checksum over IPv6 | Map `if c == 0 { 0xFFFF } else { c }` | Violates RFC 8200 §8.1; dropped by IPv6 stacks |
| 11| Writing SCTP CRC32c in big-endian | Write `cksum.to_le_bytes()` in bytes `8..12` | Violates RFC 9260 §3.3.10 little-endian rule |
| 12| Omitting `IfTsResol(9)` in PCAPNG IDB | Include `InterfaceDescriptionOption::IfTsResol(9)` | Prevents 1000x nanosecond timestamp skew |
