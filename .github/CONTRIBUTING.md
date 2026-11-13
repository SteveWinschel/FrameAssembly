# Contributing to FrameAssembly

Thanks for helping improve **FrameAssembly** (`frameassembly` v3.0.0, browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/))! Whether you are fixing a protocol field, improving `.pcap` / `.pcapng` reverse decompilation, or adding new Layer 2–7 protocols, this guide walks through how the codebase is organized and verified.

## Ways to Contribute

- **Report issues or missing protocol fields**: Use the [GitHub Issue Templates](https://github.com/SteveWinschel/FrameAssembly/issues/new/choose) for reverse/decompile bugs, new protocol requests, or CLI / VS Code / AI generation feedback.
- **Submit fixes or new protocols**: Fork the repository, build and test locally, and open a pull request against `main`.
- **Share traffic recipes**: Ask questions or share `.frasm` packet workflows in [GitHub Discussions](https://github.com/SteveWinschel/FrameAssembly/discussions).

> **Important:** Always sanitize real-world packet captures (strip internal IP addresses, MACs, credentials, SNMPv3 passphrases, and hostnames) before attaching captures or hex dumps to issues or pull requests.

## Repository Layout & Symmetry

FrameAssembly enforces strict `<layer>/<protocol>` symmetry across its compiler, reverse decompiler, corpus, and docs:

- `src/lexer/mod.rs` — Zero-copy `logos` tokenizer. All built-in keywords, protocol names, modifiers, and time units (`ns`, `us`, `ms`, `s`, `m`) are strictly lowercase alphanumeric (`[a-z0-9]+`) with zero `_` and zero `-`.
- `src/ast/{l2,l3,l4,l7}/<protocol>.rs` — Strongly typed AST definitions (`*Spec` structs) with `/// Syntax mapping:` docstrings.
- `src/parser/{l2,l3,l4,l7}/<protocol>.rs` — `winnow` token-slice combinators, protocol-scoped field dispatch, and semantic validation (`src/parser/validation.rs`).
- `src/builders/{l2,l3,l4,l7}/<protocol>.rs` — Inner-outward wire encoders and checksum engines.
- `src/reverse/{l2,l3,l4,l7}/<protocol>.rs` — PCAP/PCAPNG-to-`.frasm` dissectors and forward-compiler oracle checks.
- `examples/{l2,l3,l4,l7,topologies}/` — Verified `.frasm` scenarios (`2,611` corpus files).
- `docs/` — User and protocol reference guides ([`docs/README.md`](../docs/README.md), [`docs/12_frasm_specification.md`](../docs/12_frasm_specification.md)).
- `frameassembly-wasm/` & `frameassembly-vscode/` — WebAssembly compiler/decompiler bindings and VS Code Packet Studio extension.

## Lockstep & Coding Standards

1. **Keyword & Grammar Lockstep**: Whenever you add or update built-in tokens or protocol fields in `src/lexer/mod.rs` and `src/parser/`, keep `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, `frameassembly-vscode/protocol_schema.json`, and `frameassembly-wasm` synchronized.
2. **Rust 2024 & Documentation Hygiene**:
   - Every `src/**/*.rs` file must begin with an inner `//!` module docstring (`>= 50` words) and stay under `50,000` bytes.
   - Document all public and private functions, structs, enums, and fields; never combine outer `///` comments on `pub mod` with inner `//!` docs.
   - Never introduce literal NUL bytes (`0x00`) into `.md`, `.txt`, or grammar files.
3. **Compilable Examples & Docs**: Every ````frameassembly` fenced block in docs and every `.frasm` file under `examples/` must compile cleanly under FrameAssembly 3.0 syntax.
4. **Versioning**: Do not bump `version` fields in `Cargo.toml` or package manifests inside feature/bugfix PRs unless part of a coordinated release.

## Local Verification Checklist

Before opening a pull request, verify your changes locally:

```bash
# Format and lint
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings

# Run full unit, integration, docs, and corpus verification tests
cargo test

# Validate shell scripts if modified
bash -n install.sh
bash -n contrib/packaging/apt/build-deb.sh
bash -n contrib/packaging/update-checksums.sh
```

By contributing to FrameAssembly, you agree that your contributions will be licensed under the repository's [MIT License](../LICENSE).
