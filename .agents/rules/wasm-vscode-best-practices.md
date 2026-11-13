---
trigger: glob
globs: "frameassembly-wasm/**, frameassembly-vscode/**, Cargo.toml, .github/workflows/**"
description: "WebAssembly (wasm-bindgen 0.2.130, serde-wasm-bindgen 0.6.5, wasm-pack 0.15.1) in-memory compilation, UTF-16 IDE span mapping, VS Code Packet Studio (@vscode/vsce 4.1.0, in-process WASM, Quick Fixes, Packet Ladder, TextMate source.frameassembly), supported release channels, and OIDC Trusted Publishing rules."
---

# WebAssembly (`frameassembly-wasm`) & VS Code Packet Studio (`frameassembly-vscode`) Best Practices

Enforce these cross-target compilation, UTF-16 span mapping, in-process WASM Packet Studio, TextMate grammar, packaging, and CI publishing rules across `frameassembly-wasm/`, `frameassembly-vscode/`, and `.github/workflows/`:

## 1. WebAssembly Architecture (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`)
- **In-Memory PCAPNG Serialization & Decompilation (`wasm32-unknown-unknown`)**:
  - Browser, Web Worker, and VS Code runtimes on `wasm32-unknown-unknown` require pure in-memory execution (`std::fs::File::create` fails unconditionally on `wasm32-unknown-unknown`).
  - Never call `backend::generate_pcap(&program, path)` from WASM exports! Always run `parser::parse_program(src)` -> `backend::compile_program(&program)` and serialize `SHB -> IDB (ETHERNET, snaplen 65535, IfTsResol(9)) -> EPBs` into an in-memory `PcapNgWriter::new(Vec::new())` returning `Uint8Array` (`Result<Vec<u8>, JsError>`), alongside `validate_fasm` (`IdeDiagnostic[]`), `inspect_fasm` (`PacketPreview[]` + summary metadata), and `reverse_pcap_to_fasm` (`Result<String, JsError>`).
- **UTF-8 Byte Offset to Zero-Based UTF-16 `(line, col)` Coordinate Mapping**:
  - Rust `miette` and `logos` spans use UTF-8 byte offsets, whereas Monaco, CodeMirror, and VS Code editors require zero-based UTF-16 `(line, col)` coordinates. Always clamp offsets with `source.is_char_boundary(i)`, resolve backend errors onto meaningful statement/`compile` spans instead of degenerate `(0, 0)` spans where source positions exist, and compute column width via `.encode_utf16().count()`.
- **Zero Uncaught Panics & Typed TS Exports Across the JS Boundary**:
  - On `wasm32-unknown-unknown`, Rust panics abort the WASM instance (`unreachable` trap) and poison module state. Return `Result<JsValue, JsError>` or `Result<Vec<u8>, JsError>` on all `#[wasm_bindgen]` entrypoints, use `miette = { version = "7.6.0", default-features = false }`, emit TypeScript interfaces via `#[wasm_bindgen(typescript_custom_section)]` + `#[wasm_bindgen(unchecked_return_type = "...")]`, and forbid `.unwrap()` / `.expect()` on user `.frasm` or `.pcap` input.
- **Mandatory WASM Build & CI Profile Flags**:
  - Set `crate-type = ["cdylib", "rlib"]` in `frameassembly-wasm/Cargo.toml`.
  - **CRITICAL CI Guardrail**: Always build WASM with `CARGO_PROFILE_RELEASE_STRIP=none` and `[package.metadata.wasm-pack.profile.release] wasm-opt = false`! Stripping symbols removes the `.target_features` custom section required by `wasm-bindgen 0.2.130`, breaks Rust 1.96+ WASM link-time symbol signature checks, and bundled `wasm-opt` binaries fail on bulk-memory / multivalue instructions emitted by `rustc 1.99.1`.
- **NPM Package Hygiene**: Ensure `frameassembly-wasm` (`3.0.0`) ships generated `.d.ts` TypeScript declarations, `.wasm` binary, JS glue, `README.md`, and `LICENSE`, with version locked to root `Cargo.toml` and `pkg/package.json` `repository.url` normalized to `git+https://github.com/SteveWinschel/FrameAssembly.git` for `npm publish --provenance`.

## 2. VS Code Packet Studio (`SteveWinschel.frameassembly-vscode`, `@vscode/vsce 4.1.0`)
- **In-Process WASM Packet Studio (`frameassembly-vscode-3.0.0.vsix`)**:
  - Bundle `frameassembly-wasm` (`wasm-pack build --release --target web`, initialized via `Uint8Array` `.wasm` bytes so both Desktop Node.js Extension Host and Browser `vscode.dev` work without requiring a native CLI binary) inside `frameassembly-vscode`, enforcing `needs: [prepare, wasm]` in `.github/workflows/release.yml`.
  - Provide live UTF-16 `DiagnosticCollection` + 1-click Quick Fix `CodeActionProvider` (rewriting typos from self-healing `replace '<raw>' with '<kw>'` compiler hints), protocol-scoped `CompletionItemProvider`, editor title-bar `Compile to .pcap` + live Packet Ladder `WebviewPanel`, and Explorer `.pcap`/`.pcapng` context-menu `Reverse to .frasm`.
- **Canonical Language ID, Scope, MIME & Disambiguation**:
  - Language ID: `"frameassembly"`, display name `"FrameAssembly"`, extension `".frasm"`, MIME `"text/vnd.frameassembly"`, TextMate scope **`"source.frameassembly"`** (NEVER `"source.fasm"`, which collides with x86 Flat Assembler extensions), and Markdown fenced-code injection `markdown.frameassembly.codeblock` into `text.html.markdown`.
  - Set `firstLine` regex to `^(?:host|flow|compile|HOST|FLOW|COMPILE|//)` (never include `#` or `;`, which belong to FPGA and x86 FASM formats).
  - Configure `language-configuration.json` with `"lineComment": "//"` (never `#` or `;`), auto-closing pairs `{}` / `()` / `""`, and folding markers on `host`/`flow`/`compile` blocks (never `loop`).
- **TextMate Grammar Lockstep (`syntaxes/frameassembly.tmLanguage.json`)**:
  - Keep all 81 protocol keywords, ~645 strict-lowercase `[a-z0-9]+` modifiers (zero `_`, zero `-`, zero `loop`), word-boundary `\b...\b` patterns, time durations (`\b[0-9]+(?:ns|us|ms|s|m)\b`), multi-format MACs (colon, hyphen, Cisco dotted-quad), IPv4/IPv6 literals, OIDs, and escape sequences (`\\r`, `\\n`, `\\t`, `\\x[0-9a-fA-F]{2}`, `\\u[0-9a-fA-F]{4}`) 100% synchronized with `src/lexer/mod.rs`.
  - Keep `frameassembly-vscode/README.md` written for network/security engineers (zero `"DSL"` / `"AST"` compiler jargon).
- **VSIX Packaging Rules (`@vscode/vsce 4.1.0`)**:
  - Package with `npx @vscode/vsce package` (never deprecated unscoped `vsce`), producing `frameassembly-vscode-3.0.0.vsix`.
  - Use a PNG `icon` (`128x128` or `256x256`)—`@vscode/vsce` rejects user-provided SVG icons/badges for Marketplace security.
  - Maintain a strict `.vscodeignore` excluding `.git`, `.vscode/**`, `.vscode-test/**`, `src/**/*.ts`, `vsc-extension-quickstart.md`, `*.pcap*`, and test fixtures while bundling compiled extension JS + `wasm/` runtime assets cleanly.

## 3. Supported Release Channels & Trusted Publishing (Post-PAT Era)
- **Supported Release Channels Only**:
  - Maintain only active channels: GitHub Releases + `.deb`, Crates.io, NPM (`frameassembly-wasm`), VS Code Marketplace, and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`). Never reference or configure any other third-party package or extension registries.
- **Trusted Publishing / Federated Identity (OIDC)**:
  - Global Personal Access Tokens (PATs) in Azure DevOps are retired on **December 1, 2026**. Prefer Microsoft Entra ID / GitHub Actions OIDC Federated Credentials (`npx @vscode/vsce publish --oidc`) and npm OIDC Trusted Publishing (`npm publish --provenance --access public`) over long-lived static secrets.
- **GitHub Actions Secret-Guard & Non-Blocking Optional Registries**:
  - Never reference `secrets.*` directly in a step-level `if:` expression; bind secrets to job/step `env:` (`if: ${{ env.NPM_TOKEN != '' }}`) and isolate optional registry publish steps so GitHub Releases and binary/VSIX assets always publish cleanly.
