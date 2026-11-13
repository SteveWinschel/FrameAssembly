---
name: wasm-vscode
description: Comprehensive architecture guide, API selection matrix, and production code templates for building in-memory WebAssembly (.wasm) compilers, packet inspectors, and PCAP-to-.frasm decompilers with wasm-bindgen 0.2.130, serde-wasm-bindgen 0.6.5, and wasm-pack 0.15.1, UTF-16 IDE diagnostic coordinate mapping, interactive VS Code extensions (@vscode/vsce 4.1.0, TextMate source.frameassembly, WASM Packet Studio), and post-PAT OIDC Trusted Publishing.
---

# WebAssembly (`frameassembly-wasm`) & VS Code Packet Studio (`frameassembly-vscode`) Engineering Skill

Use this skill when building, debugging, packaging, or publishing FrameAssembly's WebAssembly compiler/inspector/decompiler (`frameassembly-wasm`), browser IDE diagnostic bridges (Monaco, CodeMirror, VS Code Desktop & Web), interactive VS Code Packet Studio extension and TextMate syntax grammars (`frameassembly-vscode` v3.0.0), or GitHub Actions OIDC release pipelines.

---

## 1. WebAssembly & VS Code Selection Matrix (v3.0.0)

| Engineering Goal | Idiomatic Modern v3.0.0 Pattern | Avoid (Anti-Pattern / Defect) |
| :--- | :--- | :--- |
| **Crate Configuration** | `crate-type = ["cdylib", "rlib"]`, `wasm-bindgen = "0.2.130"`, `serde-wasm-bindgen = "0.6.5"`, `miette = { version = "7.6.0", default-features = false }` | Enabling `miette` `fancy` terminal features on `wasm32-unknown-unknown` or omitting `"rlib"` for unit tests |
| **PCAPNG Serialization & Reverse in WASM** | In-memory `SHB -> IDB (IfTsResol(9)) -> EPBs` `Vec<u8>` writer (`Uint8Array`) + `reverse_pcap_bytes(pcap_bytes)` | Calling `backend::generate_pcap(&program, path)` or `reverse_pcap_file(path)` (`std::fs` fails on `wasm32`) |
| **JS Boundary Error Handling** | Return `Result<JsValue, JsError>`, `Result<Vec<u8>, JsError>`, or structured `ReversePcapError`; zero `.unwrap()` on user input | Panicking across the WASM boundary (`unreachable` trap poisoning the WebAssembly instance) |
| **TypeScript Return Typing** | `#[wasm_bindgen(typescript_custom_section)]` + `#[wasm_bindgen(unchecked_return_type = "...")]` (`IdeDiagnostic[]`, `PacketPreview[]`, `ReversePcapResult`) | Returning untyped `any` to TypeScript consumers or manually editing generated `pkg/*.d.ts` files |
| **Editor Span & Backend Error Coordinates** | `byte_offset_to_utf16_line_col(source, offset)` + `find_backend_error_span(source, &err)` targeting the offending statement or `compile` block | Passing UTF-8 byte offsets to UTF-16 editor APIs or hardcoding `(0, 0) -> (0, 1)` on backend compilation errors |
| **Rust 1.96–1.99.1 WASM CI Flags** | `CARGO_PROFILE_RELEASE_STRIP=none` and `[package.metadata.wasm-pack.profile.release] wasm-opt = false` | `strip = "symbols"` in CI (strips `.target_features` needed by `wasm-bindgen 0.2.130` and Rust 1.96+ WASM symbol checks) |
| **Desktop + Web VS Code WASM Loading** | `wasm-pack build --release --target web`, bundled in `frameassembly-vscode/wasm/`, initialized via `Uint8Array` from `vscode.workspace.fs.readFile` (`"main"` + `"browser": "./extension.js"`) | Using Node-only `fs.readFileSync` or spawning an external CLI child process (breaks `vscode.dev` and zero-install UX) |
| **VS Code Language, Scope & `firstLine`** | Language `"frameassembly"`, MIME `"text/vnd.frameassembly"`, scope `"source.frameassembly"`, `"firstLine": "^(?:host\|flow\|compile\|//)"` | Using `"source.fasm"`, uppercase/loop v1.x keywords, or `#` / `;` in `firstLine` (collides with x86/FPGA FASM) |
| **1-Click Self-Healing Quick Fixes** | `CodeActionProvider` (`CodeActionKind.QuickFix`) parsing `replace '<raw>' with '<kw>'` from `IdeDiagnostic.help` | Showing lowercase keyword errors without actionable 1-click quick-fix edits |
| **Supported Release Channels Only** | GitHub Releases + `.deb`, Crates.io, NPM (`frameassembly-wasm`), VS Code Marketplace (`@vscode/vsce 4.1.0`), and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`) | Publishing to or referencing unmaintained third-party package or extension registries outside these 5 channels |

---

## 2. WebAssembly Compiler, Inspector & Decompiler Architecture (`frameassembly-wasm` v3.0.0)

### 2.1 Four Canonical WASM Entrypoints
- **`validate_fasm` / `validateFasm(source: &str) -> Result<JsValue, JsError>` (`IdeDiagnostic[]`)**:
  - Runs `parse_program(source)` (including `validate_semantics`) and `compile_program(&program)`.
  - Preserves `CompilerError` `help` strings in `IdeDiagnostic.help` (including v3.0.0 self-healing hints: `"Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace '<raw>' with '<kw>'."`).
  - Resolves backend compilation errors via `find_backend_error_span(source, &err)` to highlight the offending identifier/protocol or the `compile` keyword span rather than `(0, 0)`.
- **`inspect_fasm(source: &str) -> Result<JsValue, JsError>` (`PacketPreview[]`)**:
  - Returns 1-based `index`, relative `timestamp_ms`, `length`, space-delimited lowercase `hex`, plus `source_dest: String`, `protocol: String`, and `summary: String` (dissecting Ethernet II, 802.1Q VLAN, 802.1ad QinQ, MPLS, ARP, IPv4/IPv6, TCP/UDP/SCTP, and well-known L7 protocols) for browser and VS Code Packet Ladder previews.
- **`compile_fasm_to_pcapng` / `compileFasm(source: &str) -> Result<Vec<u8>, JsError>` (`Uint8Array`)**:
  - Serializes `SHB (0x0A0D0D0A) -> IDB (ETHERNET, snaplen 65535, IfTsResol(9)) -> EPBs` strictly in memory without `std::fs`.
- **`reverse_pcap` / `reversePcap(pcap_bytes: &[u8]) -> Result<JsValue, JsValue>` (`ReversePcapResult`)**:
  - Decompiles binary `.pcap` / `.pcapng` `Uint8Array` captures in memory via `frameassembly::reverse::reverse_pcap_bytes`, returning `{ success: true, fasm, packetCount, hostCount }` with strict-lowercase v3.0.0 keywords, `host1`/`host2` identifiers, and zero `loop` blocks.

### 2.2 UTF-8 Byte Offset to Zero-Based UTF-16 `(line, col)` Mapping
- Rust strings (`&str`) and `miette::SourceSpan` use UTF-8 byte offsets, whereas JavaScript strings, Monaco Editor, CodeMirror 6, and VS Code `Range` objects index columns by **UTF-16 code units** (`0`-based).
- Clamp `byte_offset.min(source.len())`, walk backward to a UTF-8 char boundary via `(0..=clamped).rev().find(|&i| source.is_char_boundary(i))`, count `\n` bytes for `line`, and compute `col` after the last `\n` via `slice.encode_utf16().count() as u32`.

### 2.3 Critical WASM CI Build Flags (`rustc 1.99.1` & Rust 1.96+ Linker Checks)
- **Never Strip WASM Symbols Before `wasm-bindgen`**: Override `CARGO_PROFILE_RELEASE_STRIP: none` in the `wasm` CI job so `.target_features` is preserved for `wasm-bindgen 0.2.130` and Rust 1.96+ WASM symbol checks.
- **Disable Bundled `wasm-opt`**: Keep `[package.metadata.wasm-pack.profile.release] wasm-opt = false` in `frameassembly-wasm/Cargo.toml` so `wasm-pack 0.15.1` does not invoke outdated Binaryen `wasm-opt` binaries on `rustc 1.99.1` bulk-memory / multivalue opcodes.

---

## 3. Interactive VS Code Packet Studio (`frameassembly-vscode` v3.0.0)

### 3.1 Universal WASM Extension Host Architecture (Desktop + `vscode.dev`)
- Set both `"main": "./extension.js"` and `"browser": "./extension.js"` with `"activationEvents": ["onLanguage:frameassembly", "onCommand:frameassembly.reversePcap"]` and zero external npm runtime dependencies.
- Load `./wasm/frameassembly_wasm_bg.wasm` bytes via `vscode.workspace.fs.readFile(vscode.Uri.joinPath(context.extensionUri, 'wasm', 'frameassembly_wasm_bg.wasm'))` and initialize the `wasm-pack --target web` module with `initSync({ module: wasmBytes })` (or async `init(wasmBytes)`).
- Deliver four integrated IDE capabilities:
  1. **Live UTF-16 Diagnostics & 1-Click Quick Fixes**: Debounced (`120ms`) `validateFasm` feeding `DiagnosticCollection('frameassembly')`, paired with a `CodeActionProvider` parsing `replace '<raw>' with '<kw>'` from `diag.help` to offer 1-click strict-lowercase keyword fixes.
  2. **Protocol-Scoped Autocomplete**: `CompletionItemProvider` suggesting top-level `host`/`flow`/`compile` blocks, declared host/flow identifiers, all 81 lowercase protocols after `->` / `<-`, and protocol-specific modifiers.
  3. **Compile to `.pcapng` & Live Packet Ladder Preview**: Editor title-bar commands `frameassembly.compileToPcap` (writes `.pcapng` via `vscode.workspace.fs.writeFile`) and `frameassembly.showPacketLadder` (renders a live `WebviewPanel` ladder + hex inspector from `inspect_fasm`).
  4. **Explorer `.pcap` / `.pcapng` Reverse to `.frasm`**: Explorer context-menu command `frameassembly.reversePcap` reading binary captures via `vscode.workspace.fs.readFile`, calling `reversePcap`, and opening the decompiled `.frasm` code.

### 3.2 Strict-Lowercase TextMate Grammar & Compilable Markdown Injection
- Register `"id": "frameassembly"`, `"extensions": [".frasm"]`, `"mimetypes": ["text/vnd.frameassembly"]`, `"firstLine": "^(?:host|flow|compile|//)"`, and `"scopeName": "source.frameassembly"` across all 81 strict-lowercase protocols and ~640 modifiers (`loop` removed, zero `_` or `-` in keywords).
- Inject `"scopeName": "markdown.frameassembly.codeblock"` into `"text.html.markdown"` so fenced ````frameassembly` and ````frasm` blocks highlight cleanly:

```frameassembly
host client { ip 192.0.2.10 mac 00:11:22:33:44:55 }
host server { ip 192.0.2.20 mac 00:aa:bb:cc:dd:ee }
flow dns_check(c, s) {
    c -> s dns qname "example.com" qtype "a"
    c <- s dns response qname "example.com" rdata 93.184.216.34 wait 2ms
}
compile {
    dns_check(client, server)
}
```

### 3.3 CI Bundling (`needs: [prepare, wasm]`), OIDC Publishing & Supported Channels
- In `.github/workflows/release.yml`, `vscode-extension` declares `needs: [prepare, wasm]`, downloads `release-wasm`, copies `frameassembly_wasm.{js,d.ts}` and `frameassembly_wasm_bg.wasm` into `frameassembly-vscode/wasm/`, packages `frameassembly-vscode-3.0.0.vsix` via `@vscode/vsce 4.1.0`, and publishes via OIDC (`vsce publish --oidc`, `npm publish --provenance --access public`).
- **Supported Release Channels ONLY**: GitHub Releases + `.deb`, Crates.io, NPM (`frameassembly-wasm`), VS Code Marketplace, and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`) — do not reference or add publish steps for any other third-party registries.

---

## 4. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable v3.0.0 production implementations:
1. **`frameassembly-wasm/Cargo.toml` & `package.json` Manifests (`version = "3.0.0"`, `wasm-opt = false`, 20 NPM SEO Keywords)**
2. **`frameassembly-wasm/src/lib.rs` Complete v3.0.0 Implementation (`validate_fasm` + `find_backend_error_span`, Enriched `inspect_fasm`, `compile_fasm_to_pcapng`, `reverse_pcap`)**
3. **`frameassembly-vscode/package.json` (30 Marketplace Keywords, Commands & Menus), `extension.js` WASM + Quick Fix Pattern & `language-configuration.json`**
4. **Strict-Lowercase v3.0.0 TextMate Grammar (`source.frameassembly`) & Markdown Codeblock Injection (`markdown.frameassembly.codeblock`)**
5. **GitHub Actions `wasm` -> `vscode-extension` (`needs: [prepare, wasm]`) OIDC Trusted Publishing Workflow (`.github/workflows/release.yml`)**
