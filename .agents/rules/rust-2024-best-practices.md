---
trigger: glob
globs: "Cargo.toml, src/**/*.rs, tests/**/*.rs, frameassembly-wasm/**/*.rs"
description: "Rust 2024 Edition and rustc 1.85-1.99.1 idioms, zero-copy slice/formatting helpers, advisory file locks, soundness rules, and cross-platform CI guardrails."
---

# Rust 2024 Edition & Modern Rust Best Practices (`rustc 1.85–1.99.1`)

Enforce these idiomatic, zero-copy, and sound `rustc 1.99.1` (`clippy 0.1.99`, Edition 2024, crate MSRV `1.85` with `incompatible_msrv = "allow"`) standards across the compiler, protocol builders, reverse decompiler, WASM bindings, and test suites:

## 1. Edition 2024 Control Flow, Pattern Matching & Rescoping
- **Match Ergonomics**: Never write explicit `ref`, `ref mut`, or `mut` inside `match` or `if let` patterns when matching against `&T` or `&mut T` where default binding modes apply (`if let Some(val) = &self.field`). Never mix explicit `&` patterns with bare reference-binding identifiers in the same pattern.
- **Edition 2024 Temporary Drop Order**: Remember `if_let_rescope` (scrutinee temporaries in `if let <pat> = <expr>` drop *before* entering `else`) and `tail_expr_drop_order` (tail-expression temporaries drop *before* local bindings).
- **Guard Clauses, Let Chains & Match Guards**:
  - Use `let Some(x) = opt else { return ...; };` for flat precondition guards.
  - Flatten nested conditionals with `let_chains` (stabilized in Rust 1.88.0):
    ```rust
    if let Some((_, pass)) = &stmt.auth && pass.is_empty() {
        return Err("SNMPv3 authentication password cannot be empty".to_string());
    }
    ```
  - Use `if let` match guards (`Pat if let Some(x) = y => ...`, Rust 1.95.0), `std::cfg_select!` (Rust 1.95.0), `std::hint::cold_path` (Rust 1.95.0), and `std::assert_matches::assert_matches!` (Rust 1.96.0).

## 2. Lifetimes, Trait Upcasting & Return-Position `impl Trait` (`+ use<...>`)
- **Precise RPIT Capturing**: Edition 2024 RPIT captures all in-scope type and lifetime parameters by default. When a returned `impl Trait` does not borrow from an input lifetime, restrict captures explicitly (`-> impl Iterator<Item = Token<'a>> + use<'a>` or `+ use<>`).
- **Explicit Elided Lifetimes (`mismatched_lifetime_syntaxes`, Rust 1.89.0)**: Always write `'_` on returned types borrowing from `&self` or elided inputs (`fn as_slice(&self) -> Span<'_>`).
- **Trait Upcasting (Rust 1.86.0)**: Coerce `&dyn SubTrait` or `Box<dyn SubTrait>` directly to `&dyn SuperTrait` / `Box<dyn SuperTrait>` (including `dyn Any`) without helper `as_any()` methods.

## 3. Concurrency, Advisory File Locks, Atomics & Process Environment
- **Zero `static mut`**: `static_mut_refs` is a hard error in Edition 2024. Use `std::sync::LazyLock<T>` or `OnceLock<T>`.
- **Concrete Typed Atomics**: Generic `Atomic<T>` remains unstable (`E0658`) in `rustc 1.99.1`. Always use `AtomicU64`, `AtomicUsize`, `AtomicU32`, or `AtomicBool` (with `.update(...)` / `.try_update(...)` from Rust 1.95.0).
- **Native Advisory File Locking (Rust 1.89.0)**: Use standard library `std::fs::File::lock()`, `lock_shared()`, `try_lock()`, `try_lock_shared()`, and `unlock()` for cross-process file synchronization instead of external `fs2` / `fd-lock` crates.
- **Safe Process Environment**: Never call `std::env::set_var` or `remove_var` (`unsafe fn` in Edition 2024 due to multi-threaded races); pass environment variables via `std::process::Command::env`.

## 4. Zero-Copy Slice, Array, Formatting & Network Primitives (`1.86–1.98`)
- **Disjoint Mutable Indexing (Rust 1.86.0)**: Use `<[T]>::get_disjoint_mut([i..j, k..l])` and `HashMap::get_disjoint_mut` to mutate non-overlapping packet header/payload regions or map entries simultaneously without `split_at_mut` index arithmetic.
- **Aligned Chunking (`as_chunks`, Rust 1.88.0)**: Use `slice.as_chunks::<2>()` (as in `src/packet.rs::internet_checksum`) and `as_chunks::<N>()` / `as_rchunks::<N>()` instead of manual index stepping (`&slice[i..i + 2]`).
- **Fixed-Size Windows & Arrays (Rust 1.93.0–1.94.0)**: Prefer `<[T]>::as_array::<N>()` (Rust 1.93.0) and `<[T]>::array_windows::<N>()` (Rust 1.94.0) over `.windows(N)` so window patterns match fixed `[u8; N]` arrays without bounds checks.
- **Collection, Range & Conversion Ergonomics (`1.89–1.98`)**:
  - `NonZero<char>` & `Result::flatten` (Rust 1.89.0).
  - `u{n}::checked_sub_signed` / `saturating_sub_signed` (Rust 1.90.0), `{integer}::strict_add` / `strict_sub` / `strict_mul` & `Path::file_prefix` (Rust 1.91.0).
  - `Vec::push_mut` (returns `&mut T` to the pushed element) and `TryFrom<Integer> for bool` (Rust 1.95.0).
  - `core::range::{Range, RangeFrom, RangeInclusive}` (`Copy` iterator-aware range types, Rust 1.96.0).
  - `str::substr_range` & `<[T]>::subslice_range` (Rust 1.98.0) to recover $O(1)$ byte/token ranges without pointer subtraction, and `{integer}::format_into` with `core::num::NumBuffer<Self>` (Rust 1.98.0) for zero-allocation `itoa`-speed integer formatting.
- **`std::net` Stability Guardrail**: Use stable `Ipv4Addr::to_bits`/`from_bits` and `Ipv6Addr::to_bits`/`from_bits` bitmasks rather than unstable `#![feature(ip)]` helpers.

## 5. Soundness, Raw Pointer Layout, Toolchain & Cross-Platform CI (`1.88–1.99.1`)
- **Unsafe & FFI Hygiene (`1.88–1.99.1`)**:
  - Keep the core crate 100% safe Rust. If FFI/unsafe is ever required, enable `unsafe_op_in_unsafe_fn = "warn"` and `dangling_pointers_from_locals` (Rust 1.91.0), wrap minimal operations in `unsafe { ... }` with `// SAFETY:` comments, and use `unsafe extern "C"`, `#[unsafe(no_mangle)]`, `#[unsafe(naked)]` with `naked_asm!` (Rust 1.88.0), `&raw const` / `&raw mut`, and `NonNull::from_ref` / `from_mut` (Rust 1.89.0).
  - In Rust `1.99.0` / `1.99.1`: use stabilized `extern "C"` variadics (`core::ffi::{VaList, VaArgSafe}`), raw pointer layout queries (`Layout::for_value_raw`, `mem::size_of_val_raw`, `mem::align_of_val_raw`), and `Box::into_raw` / `Box::into_non_null` (never round-trip `Box::leak(b) as *mut T` into `Box::from_raw`, which Rust 1.99.1 flags when dropping).
- **Centralized `[lints]`, Linker & Build Diagnostics (`1.90–1.97`)**:
  - Declare all `rust`, `rustdoc`, and `clippy` lints once in `Cargo.toml` `[lints]` (note: `Result` and `ControlFlow` share `#[must_use]` equivalence in Rust 1.97.0, and Cargo supports `build.warnings` in `1.97.0` and `cargo publish --workspace` in `1.90.0`).
  - Linux `x86_64` defaults to `rust-lld` (Rust 1.90.0), emits unwind tables by default even with `panic = "abort"` (Rust 1.92.0), and uses `v0` symbol mangling by default (Rust 1.97.0).
- **Cross-Platform & WASM CI Discipline**:
  - Guard Unix-only tools (`bash`, `unzip`, `tshark`) in tests and normalize `\r\n` line endings so `x86_64-pc-windows-msvc` CI passes cleanly.
  - On `wasm32-unknown-unknown` builds (where Rust 1.96.0 enforces link-time undefined symbol checks), set `CARGO_PROFILE_RELEASE_STRIP=none` and `wasm-opt = false` so `wasm-bindgen` retains `.target_features` metadata without CI `wasm-opt` flag failures.