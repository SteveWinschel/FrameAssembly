---
trigger: glob
globs: "frameassembly-wasm/**, frameassembly-vscode/**, Cargo.toml, .github/workflows/**"
description: "WebAssembly (wasm-bindgen 0.2.130, serde-wasm-bindgen 0.6.5, wasm-pack 0.15.1) in-memory compilation, UTF-16 IDE span mapping, VS Code extension (@vscode/vsce 4.1.0, TextMate source.frameassembly), and OIDC Trusted Publishing rules."
---

# WebAssembly (`frameassembly-wasm`) & VS Code Extension (`frameassembly-vscode`) Best Practices

Enforce these cross-target compilation, UTF-16 span mapping, TextMate grammar, packaging, and CI publishing rules across `frameassembly-wasm/`, `frameassembly-vscode/`, and `.github/workflows/`:

## 1. WebAssembly Architecture (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`)
- **In-Memory PCAPNG Serialization (`wasm32-unknown-unknown`)**:
  - Browser and Web Worker runtimes on `wasm32-unknown-unknown` have no filesystem (`std::fs::File::create` fails unconditionally).
  - Never call `backend::generate_pcap(&program, path)` from WASM exports! Always run `parser::parse_program(src)` -> `backend::compile_program(&program)` and serialize `SHB -> IDB (ETHERNET, snaplen 65535, IfTsResol(9)) -> EPBs` into an in-memory `PcapNgWriter::new(Vec::new())` (or direct PCAPNG byte buffer) returning `Uint8Array` (`Result<Vec<u8>, JsError>`), alongside `validate_fasm` (`IdeDiagnostic[]`) and `inspect_fasm` (`PacketPreview[]`).
- **UTF-8 Byte Offset to Zero-Based UTF-16 `(line, col)` Coordinate Mapping**:
  - Rust `miette` and `logos` spans use UTF-8 byte offsets, whereas Monaco, CodeMirror, and VS Code Web editors require zero-based UTF-16 `(line, col)` coordinates. Always clamp offsets with `source.is_char_boundary(i)` and compute column width via `.encode_utf16().count()`.
- **Zero Uncaught Panics & Typed TS Exports Across the JS Boundary**:
  - On `wasm32-unknown-unknown`, Rust panics abort the WASM instance (`unreachable` trap) and poison module state. Return `Result<JsValue, JsError>` or `Result<Vec<u8>, JsError>` on all `#[wasm_bindgen]` entrypoints, use `miette = { version = "7.6.0", default-features = false }`, emit TypeScript interfaces via `#[wasm_bindgen(typescript_custom_section)]` + `#[wasm_bindgen(unchecked_return_type = "...")]`, and forbid `.unwrap()` / `.expect()` on user `.fasm` input.
- **Mandatory WASM Build & CI Profile Flags**:
  - Set `crate-type = ["cdylib", "rlib"]` in `frameassembly-wasm/Cargo.toml`.
  - **CRITICAL CI Guardrail**: Always build WASM with `CARGO_PROFILE_RELEASE_STRIP=none` and `[package.metadata.wasm-pack.profile.release] wasm-opt = false`! Stripping symbols removes the `.target_features` custom section required by `wasm-bindgen 0.2.130`, breaks Rust 1.96+ WASM link-time symbol signature checks, and bundled `wasm-opt` binaries fail on bulk-memory / multivalue instructions emitted by `rustc 1.99.1`.
- **NPM Package Hygiene**: Ensure `frameassembly-wasm` ships generated `.d.ts` TypeScript declarations, `.wasm` binary, JS glue, `README.md`, and `LICENSE`, with version locked to root `Cargo.toml` and `pkg/package.json` `repository.url` normalized to `git+https://github.com/SteveWinschel/FrameAssembly.git` for `npm publish --provenance`.

## 2. VS Code Extension (`SteveWinschel.frameassembly-vscode`, `@vscode/vsce 4.1.0`)
- **Canonical Language ID, Scope, MIME & Disambiguation**:
  - Language ID: `"frameassembly"`, display name `"FrameAssembly"`, extension `".fasm"`, MIME `"text/vnd.frameassembly"`, TextMate scope **`"source.frameassembly"`** (NEVER `"source.fasm"`, which collides with x86 Flat Assembler extensions), and Markdown fenced-code injection `markdown.frameassembly.codeblock` into `text.html.markdown`.
  - Set `firstLine` regex to `^(?:HOST|FLOW|COMPILE|host|flow|compile|//)` (never include `#` or `;`, which belong to FPGA and x86 FASM formats).
  - Configure `language-configuration.json` with `"lineComment": "//"` (never `#` or `;`), auto-closing pairs `{}` / `()` / `""`, and folding markers on `HOST`/`FLOW`/`COMPILE`/`LOOP` blocks.
- **TextMate Grammar Lockstep (`syntaxes/frameassembly.tmLanguage.json`)**:
  - Keep all 81 protocol keywords, ~640 modifiers, case-insensitive `(?i:...)` word-boundary `\b...\b` patterns, time durations (`\b[0-9]+(?i:ns|us|ms|s|m)\b`), multi-format MACs (colon, hyphen, Cisco dotted-quad), IPv4/IPv6 literals, OIDs, and escape sequences (`\\r`, `\\n`, `\\t`, `\\x[0-9a-fA-F]{2}`, `\\u[0-9a-fA-F]{4}`) 100% synchronized with `src/lexer/mod.rs`.
  - Keep `frameassembly-vscode/README.md` written for network/security engineers (zero `"DSL"` / `"AST"` compiler jargon).
- **VSIX Packaging Rules (`@vscode/vsce 4.1.0`)**:
  - Package with `npx @vscode/vsce package` (never deprecated unscoped `vsce`).
  - Use a PNG `icon` (`128x128` or `256x256`)—`@vscode/vsce` rejects user-provided SVG icons/badges for Marketplace security.
  - Maintain a strict `.vscodeignore` excluding `.git`, `.vscode/**`, `.vscode-test/**`, `vsc-extension-quickstart.md`, `*.pcap*`, and test fixtures so the `.vsix` stays tiny and fast to install via `install.sh`.

## 3. CI Release Resilience & Trusted Publishing (Post-PAT Era)
- **Trusted Publishing / Federated Identity (OIDC)**:
  - Global Personal Access Tokens (PATs) in Azure DevOps are retired on **December 1, 2026**. Prefer Microsoft Entra ID / GitHub Actions OIDC Federated Credentials (`npx @vscode/vsce publish --oidc`) and npm OIDC Trusted Publishing (`npm publish --provenance --access public`) over long-lived static secrets.
- **GitHub Actions Secret-Guard & Non-Blocking Optional Registries**:
  - Never reference `secrets.*` directly in a step-level `if:` expression; bind secrets to job/step `env:` (`if: ${{ env.NPM_TOKEN != '' }}`) and isolate optional registry publish steps so GitHub Releases and binary/VSIX assets always publish cleanly.
