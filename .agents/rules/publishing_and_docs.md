---
trigger: glob
globs: "Cargo.toml, README.md, **/README.md, docs/**/*.md, llms*.txt, src/**/*.rs, contrib/**"
description: "Zero NUL bytes, Rustdoc and docs.rs lint gates, Cargo build.warnings (Rust 1.97+), accurate module docstrings, and Cargo.toml packaging rules."
---

# Documentation Formatting, Rustdoc Lints & Crates.io Packaging Rule

## 1. Zero Binary / NUL Bytes & Markdown Table Hygiene
- **Zero Literal NUL Bytes (`0x00`)**: NEVER write literal `0x00` bytes into `README.md`, `docs/*.md`, `llms.txt`, `llms-full.txt`, or any text/grammar file. Crates.io stores READMEs in PostgreSQL `TEXT` columns, which reject `0x00` with HTTP `500 Internal Server Error`. Always escape binary protocol magic (`AMQP\x00\x00\x09\x01`, `0xff 0xfd 0x01`).
- **Single-Line Table Cells & Explicit Code Fences**: Never place raw line breaks or `<br>` tags inside Markdown table cells (escape literals as `\r\n`). Tag every fenced code block with an explicit language identifier (`frameassembly`, `rust`, `toml`, `console`, `ebnf`, `text`).
- **100% Compilable `.fasm` Fences**: Every ` ```frameassembly ` or ` ```fasm ` block across `README.md`, `docs/*.md`, `src/**/*.rs`, `AGENTS.md`, `CLAUDE.md`, and `.agents/skills/**/*.md` must be a complete, compilable `.fasm` program (`HOST` + `FLOW` + `COMPILE`). Use ` ```text ` for partial snippets or invalid syntax examples.

## 2. Rustdoc, `docs.rs` & Module Accuracy Gates
- **Centralized Cargo `[lints]` & `build.warnings` (Rust 1.97+)**: Maintain clean zero-warning builds under `[lints.rust]` (`missing_docs`, `unsafe_op_in_unsafe_fn`), `[lints.rustdoc]` (`broken_intra_doc_links`, `private_intra_doc_links`, `bare_urls`, `invalid_html_tags`, `invalid_rust_codeblocks`, `unescaped_backticks`), `[lints.clippy]` (`missing_docs_in_private_items`, `undocumented_unsafe_blocks`), and Cargo `build.warnings = "deny"` (`CARGO_BUILD_WARNINGS=deny`).
- **Inner `//!` Module Docs & `< 50 KB` AI-Critical File Cap**:
  - Every `src/**/*.rs` and `tests/*.rs` file must remain strictly `< 50,000` bytes (`< 50 KB`) and start with an inner `//!` docstring of `>= 50` words. Human-facing Markdown guides (`README.md`, `docs/*.md`) have no `< 50 KB` cap, though each must have `>= 50` words.
  - Never combine outer `///` doc comments on `pub mod <name>;` with inner `//!` headers in the child module (prevents duplicated summary lines on `docs.rs`).
  - **Zero Phantom Protocols & Consistent Decompiler Terminology in Module Docs**: Module docstrings (especially `src/builders/mod.rs`, `src/builders/l7/mod.rs`, and `src/reverse/`) must list **only** implemented protocols (8 L2, 20 L3, 3 L4, 50 L7 = 81 total)—never mention unimplemented protocols (`PPPoE`, `MACsec`, `Profinet RT`, `EIGRP`, `IS-IS`, `LDP`, `RSVP`, `L2TP`, `GTP-U`) or stale protocol counts (`45` instead of `50` L7 protocols), and always describe `src/reverse/` as **PCAP-to-`.fasm` decompilation** / **decompiler** (`pcap-decompilation`).
- **Visibility & AST `*Spec` Annotations**:
  - Keep internal parser submodules (`src/parser/{l2,l3,l4,l7,snmp}`) as `pub(crate) mod` so `docs.rs` does not emit empty module pages, and annotate public layer re-exports (`pub use <proto>::*;`) with `#[doc(inline)]`.
  - Annotate all 81 AST `*Spec` structs in `src/ast/{l2,l3,l4,l7}/` with `/// Syntax mapping: \`...\`` and `#[doc(alias = "...")]`, and ensure every `pub` field on every `*Spec` struct is wired into `src/builders/`, `src/packet.rs`, or `src/backend/` (verified by Gate 6).

## 3. Crate Packaging Manifest (`Cargo.toml`)
- **Lean Tarball**: Exclude `frameassembly-vscode/`, `frameassembly-wasm/`, `contrib/`, `*.vsix`, `*.pcap*`, `temp/`, `dist/`, `llms*.txt`, `docs/`, `examples/`, `*.ebnf`, `*.gbnf`, `*.lark`, `AGENTS.md`, `CLAUDE.md`, `CITATION.cff`, `codemeta.json`, `context7.json`, `demo.fasm`, `install.sh`, `tests/`, `.github/`, and `.agents/` in `package.exclude`.
- **Registry Metadata & Dependency Pinning**:
  - Maintain a typo-free `120–160` char `description` (fix `"custon"` -> `"custom"`), `documentation = "https://docs.rs/frameassembly"`, `homepage = "https://frameassembly.ai.studio/"`, `repository = "https://github.com/SteveWinschel/FrameAssembly"`, `rust-version = "1.85"`, `[package.metadata.docs.rs]`, and valid `crates.io` category slugs (`"command-line-utilities"`, never `"command-line-interface"`).
  - Never leave yanked version specs in `Cargo.toml` (specify `logos = "0.14.4"` rather than yanked `0.14.3`, enable `winnow = { version = "1.0.5", features = ["simd"] }`, and use `wasm-bindgen = "0.2.130"` + `serde-wasm-bindgen = "0.6.5"` in `frameassembly-wasm`).
