---
trigger: always_on
description: "Zero NUL bytes, Rustdoc and docs.rs lint gates, inner module doc hygiene, and Cargo.toml packaging rules."
---

# Documentation Formatting, Rustdoc Lints & Crates.io Packaging Rule

## 1. Zero Binary / NUL Bytes & Markdown Table Hygiene
- **No NUL Bytes (`0x00`)**: NEVER write literal NUL bytes (`0x00`) into `README.md`, `llms-full.txt`, or any `.md` / `.txt` file. Crates.io stores README text in PostgreSQL `TEXT` columns, which reject NUL bytes with HTTP `500 Internal Server Error`. Always escape binary protocol signatures (`'AMQP\x00\x00\x09\x01'`, `0xff 0xfd 0x01`).
- **Single-Line Table Cells & Explicit Code Fences**: Never allow unescaped `\r` or `\n` inside Markdown table cells (use escaped literals like `\r\n`). Always tag code blocks and ASCII trees with explicit language identifiers (`frameassembly`, `rust`, `text`, `console`).

## 2. Rustdoc & `docs.rs` Lint Gates
- **Mandatory Rustdoc & Clippy Lints**: Enforce clean builds under `missing_docs`, `clippy::missing_docs_in_private_items`, `rustdoc::broken_intra_doc_links`, `rustdoc::private_intra_doc_links`, `rustdoc::bare_urls`, `rustdoc::invalid_html_tags`, `rustdoc::invalid_rust_codeblocks`, and `rustdoc::unescaped_backticks`.
- **Inner `//!` Module Doc Hygiene**: Every `src/**/*.rs` file must remain strictly `< 50 KB` (`50,000` bytes) and begin with an inner `//!` module docstring containing `>= 50` words. Never combine outer `///` doc comments on `pub mod <name>;` with inner `//!` module docs in the child file (which causes sentence stuttering on `docs.rs`).
- **Visibility & Re-Export Hygiene**: Keep internal parser implementation submodules (`src/parser/{l2,l3,l4,l7,snmp}`) as `pub(crate) mod` so `docs.rs` never generates empty module pages. Annotate layer re-exports (`pub use <proto>::*;`) with `#[doc(inline)]`.
- **AST `*Spec` Annotations**: Annotate all 81 AST `*Spec` structs in `src/ast/{l2,l3,l4,l7}/` with `/// Syntax mapping:` (including a compilable ````frameassembly` example) and `#[doc(alias = "...")]`.

## 3. Crate Packaging Manifest (`Cargo.toml`)
- **Lean Tarball**: Keep `examples/`, `docs/`, `tests/`, `llms*.txt`, `*.ebnf`, `*.gbnf`, `*.lark`, `frameassembly-vscode/`, `*.vsix`, `*.pcap*`, `AGENTS.md`, `CLAUDE.md`, `.github/`, and `.agents/` in `package.exclude`.
- **Complete Registry Metadata**: Maintain a `120–160` char `description`, `documentation = "https://docs.rs/frameassembly"`, `homepage = "https://github.com/SteveWinschel/FrameAssembly"`, `rust-version = "1.85"`, `[package.metadata.docs.rs]`, and valid `crates.io` category slugs (`"command-line-utilities"`, never `"command-line-interface"`).
