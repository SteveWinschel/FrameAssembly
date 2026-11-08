---
name: wasm-vscode
description: Comprehensive architecture guide, API selection matrix, and production code templates for building in-memory WebAssembly (.wasm) compilers and packet inspectors with wasm-bindgen 0.2.130, serde-wasm-bindgen 0.6.5, and wasm-pack 0.15.1, UTF-16 IDE diagnostic coordinate mapping, VS Code extensions (@vscode/vsce 4.1.0, TextMate source.frameassembly), and post-PAT OIDC Trusted Publishing.
---

# WebAssembly (`frameassembly-wasm`) & VS Code Extension (`frameassembly-vscode`) Engineering Skill

Use this skill when building, debugging, packaging, or publishing FrameAssembly's WebAssembly compiler/inspector (`frameassembly-wasm`), browser IDE diagnostic bridges (Monaco, CodeMirror, VS Code Web), TextMate syntax grammars (`frameassembly-vscode`), or GitHub Actions OIDC release pipelines.

---

## 1. WebAssembly & VS Code Selection Matrix

| Engineering Goal | Idiomatic Modern Pattern | Avoid (Anti-Pattern / Defect) |
| :--- | :--- | :--- |
| **Crate Configuration** | `crate-type = ["cdylib", "rlib"]`, `wasm-bindgen = "0.2.130"`, `serde-wasm-bindgen = "0.6.5"`, `miette = { version = "7.6.0", default-features = false }` | Enabling `miette` `fancy` terminal features on `wasm32-unknown-unknown` or omitting `"rlib"` for unit tests |
| **PCAPNG Serialization in Browser** | In-memory `PcapNgWriter::new(Vec::new())` (or direct `SHB -> IDB -> EPB` `Vec<u8>` writer) returning `Result<Vec<u8>, JsError>` (`Uint8Array`) | Calling `backend::generate_pcap(&program, path)` which invokes `std::fs::File::create` and fails on `wasm32` |
| **JS Boundary Error Handling** | Return `Result<JsValue, JsError>` or `Result<Vec<u8>, JsError>` on every `#[wasm_bindgen]` entrypoint; zero `.unwrap()` on user `.fasm` input | Panicking across the WASM boundary (`unreachable` trap poisoning the WebAssembly instance) |
| **TypeScript Return Typing** | `#[wasm_bindgen(typescript_custom_section)]` + `#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]` | Returning untyped `any` to TypeScript consumers or manually editing generated `pkg/*.d.ts` files |
| **Editor Span Coordinates** | `byte_offset_to_utf16_line_col(source, offset)` using `is_char_boundary` clamping + `.encode_utf16().count()` | Passing raw UTF-8 byte offsets from `logos`/`miette` directly to Monaco / CodeMirror / VS Code UTF-16 APIs |
| **Rust 1.96–1.99.1 WASM CI Flags** | `CARGO_PROFILE_RELEASE_STRIP=none` and `[package.metadata.wasm-pack.profile.release] wasm-opt = false` | `strip = "symbols"` in CI (strips `.target_features` needed by `wasm-bindgen 0.2.130` and Rust 1.96+ WASM symbol checks) |
| **VS Code Language & Scope** | Language `"frameassembly"`, MIME `"text/vnd.frameassembly"`, scope `"source.frameassembly"`, Markdown injection `"markdown.frameassembly.codeblock"` | Using scope `"source.fasm"` (collides with x86 Flat Assembler) or omitting Markdown fenced codeblock grammar injection |
| **`.fasm` First-Line Detection** | `"firstLine": "^(?:HOST|FLOW|COMPILE|host|flow|compile|//)"` and `"lineComment": "//"` | Including `#` or `;` in `firstLine` or `lineComment` (misclassifies FPGA FASM and x86 Flat Assembler files) |
| **VSIX Packaging & Publishing** | `npx @vscode/vsce package` (`@vscode/vsce 4.1.0`), PNG `icon.png`, `.vscodeignore`, OIDC (`vsce publish --oidc`, `npm publish --provenance`) | Deprecated unscoped `vsce`, SVG icons, long-lived Azure DevOps PATs (retired Dec 1, 2026), or `secrets.*` in step `if:` |

---

## 2. WebAssembly Compiler & Inspector Architecture (`frameassembly-wasm`)

### 2.1 Crate Structure & In-Memory PCAPNG Serialization
- **Target Constraints (`wasm32-unknown-unknown`)**: Browser main threads and Web Workers lack `std::fs`. `compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError>` parses via `parse_program(source)`, compiles wire frames via `compile_program(&program)`, and serializes `SHB (0x0A0D0D0A) -> IDB (ETHERNET, snaplen 65535, IfTsResol(9)) -> EPBs` into an in-memory `Vec<u8>` (via `PcapNgWriter::new(Vec::new())` or direct little-endian block encoding), which `wasm-bindgen` zero-copy views as a JavaScript `Uint8Array`.
- **Three Canonical Entrypoints**:
  1. `validate_fasm(source: &str) -> Result<JsValue, JsError>` (`IdeDiagnostic[]`): Runs `parse_program` (which includes `validate_semantics`) and `compile_program`, returning an empty array on valid `.fasm` code or structured UTF-16 diagnostics with `message` and `help`.
  2. `inspect_fasm(source: &str) -> Result<JsValue, JsError>` (`PacketPreview[]`): Returns 1-based `index`, relative `timestamp_ms`, `length`, and space-delimited lowercase `hex` for browser packet ladder tables.
  3. `compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError>` (`Uint8Array`): Emits downloadable `.pcapng` bytes.

### 2.2 UTF-8 Byte Offset to Zero-Based UTF-16 `(line, col)` Mapping
- Rust strings (`&str`) and `miette::SourceSpan` use UTF-8 byte offsets, whereas JavaScript strings, Monaco Editor, CodeMirror 6, and VS Code `Range` objects index columns by **UTF-16 code units** (`0`-based).
- Always clamp `byte_offset.min(source.len())`, walk backward to the nearest UTF-8 character boundary via `(0..=clamped).rev().find(|&i| source.is_char_boundary(i))`, count `\n` bytes for the zero-based `line`, and compute the column after the last `\n` using `slice.encode_utf16().count() as u32`.

### 2.3 Critical WASM CI Build Flags (`rustc 1.99.1` & Rust 1.96+ Linker Checks)
- **Never Strip WASM Symbols Before `wasm-bindgen`**: Setting `CARGO_PROFILE_RELEASE_STRIP=symbols` at the workflow level removes the `.target_features` custom section from the intermediate `.wasm` binary, causing `wasm-bindgen 0.2.130` to fail or emit incompatible glue, and violating Rust 1.96+ WASM link-time symbol signature checks. Always override `CARGO_PROFILE_RELEASE_STRIP: none` in the `wasm` CI job.
- **Disable Bundled `wasm-opt`**: Set `[package.metadata.wasm-pack.profile.release] wasm-opt = false` in `frameassembly-wasm/Cargo.toml` so `wasm-pack 0.15.1` does not invoke outdated Binaryen `wasm-opt` binaries that reject bulk-memory / multivalue opcodes emitted by `rustc 1.99.1`.

---

## 3. VS Code Extension Engineering (`frameassembly-vscode`)

### 3.1 Language Registration, Disambiguation & Markdown Injection
- Register `"id": "frameassembly"`, `"extensions": [".fasm"]`, `"mimetypes": ["text/vnd.frameassembly"]`, and `"firstLine": "^(?:HOST|FLOW|COMPILE|host|flow|compile|//)"` (strictly excluding `#` and `;`).
- Bind `"scopeName": "source.frameassembly"` to `./syntaxes/frameassembly.tmLanguage.json` across all 81 protocols and ~640 modifiers in lockstep with `src/lexer/mod.rs`.
- Inject `"scopeName": "markdown.frameassembly.codeblock"` into `"text.html.markdown"` so fenced ````frameassembly` and ````fasm` blocks highlight inside Markdown previews and documentation:

```frameassembly
HOST client { IP 192.0.2.10 MAC 00:11:22:33:44:55 }
HOST server { IP 192.0.2.20 MAC 00:aa:bb:cc:dd:ee }
FLOW dns_check(c, s) {
    c -> s DNS QNAME "example.com" QTYPE "A"
    c <- s DNS RESPONSE QNAME "example.com" RDATA 93.184.216.34 WAIT 2ms
}
COMPILE {
    dns_check(client, server)
}
```

### 3.2 Packaging (`@vscode/vsce 4.1.0`) & Post-Dec-1-2026 OIDC Trusted Publishing
- Package with `npx --yes @vscode/vsce package --no-git-tag-version --no-update-package-json`, include a PNG `icon.png` (never SVG), and maintain `.vscodeignore` (`vsc-extension-quickstart.md`, `.vscode/**`, `.vscode-test/**`, `.gitignore`).
- **Post-PAT Era (Dec 1, 2026)**: Azure DevOps retires global Personal Access Tokens on December 1, 2026. Configure GitHub Actions with `permissions: { contents: read, id-token: write }`, normalize `pkg/package.json` `repository.url` (`git+https://...`) after `wasm-pack build` so `npm publish --provenance --access public` attestation verification passes, and publish via OIDC Federated Credentials (`npx --yes @vscode/vsce@latest publish --oidc`), guarding optional PAT steps via job/step `env:` variables (`if: ${{ env.VSCE_PAT == '' || steps.vsce_pat_publish.outcome == 'failure' }}`).

---

## 4. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations:
1. **`frameassembly-wasm/Cargo.toml` Manifest (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-opt = false`)**
2. **`frameassembly-wasm/src/lib.rs` Complete Implementation (`validate_fasm`, `inspect_fasm`, `compile_fasm_to_pcapng`, `byte_offset_to_utf16_line_col`)**
3. **`frameassembly-vscode/package.json`, `language-configuration.json` & `.vscodeignore`**
4. **TextMate Grammar (`source.frameassembly`) & Markdown Codeblock Injection (`markdown.frameassembly.codeblock`)**
5. **GitHub Actions WASM + VSIX OIDC Trusted Publishing Workflow (`.github/workflows/release.yml`)**
