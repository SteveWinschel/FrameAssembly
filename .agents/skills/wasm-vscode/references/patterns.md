# WebAssembly (`frameassembly-wasm`) & VS Code Extension (`frameassembly-vscode`) Reference Patterns

This reference document provides complete, production-verified templates for `frameassembly-wasm/Cargo.toml`, `frameassembly-wasm/src/lib.rs`, `frameassembly-vscode/package.json`, `language-configuration.json`, TextMate grammar definitions (`source.frameassembly` and `markdown.frameassembly.codeblock`), and GitHub Actions OIDC Trusted Publishing workflows.

---

## 1. `frameassembly-wasm/Cargo.toml` Production Manifest

Configures `crate-type = ["cdylib", "rlib"]`, `miette = { version = "7.6.0", default-features = false }` (avoiding terminal/filesystem dependencies on `wasm32-unknown-unknown`), `wasm-bindgen = "0.2.130"`, `serde-wasm-bindgen = "0.6.5"`, and `[package.metadata.wasm-pack.profile.release] wasm-opt = false` so `wasm-pack 0.15.1` preserves bulk-memory and multivalue instructions emitted by `rustc 1.99.1`.

```toml
[package]
name = "frameassembly-wasm"
version = "1.5.0"
edition = "2024"
authors = ["Steve Winschel"]
description = "WebAssembly compiler, packet inspector, and IDE diagnostics for the FrameAssembly (.fasm) network packet synthesis DSL"
license = "MIT"
repository = "https://github.com/SteveWinschel/FrameAssembly"
homepage = "https://github.com/SteveWinschel/FrameAssembly"
keywords = ["frameassembly", "pcap", "pcapng", "wireshark", "wasm"]

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
frameassembly = { path = "..", version = "1.5.0" }
miette = { version = "7.6.0", default-features = false }
pcap-file = "2.0.0"
serde = { version = "1.0", features = ["derive"] }
serde-wasm-bindgen = "0.6.5"
wasm-bindgen = "0.2.130"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"

[package.metadata.wasm-pack.profile.release]
wasm-opt = false
```

---

## 2. `frameassembly-wasm/src/lib.rs` Complete Implementation

Exposes `validate_fasm`, `inspect_fasm`, and `compile_fasm_to_pcapng` with typed TypeScript declarations (`#[wasm_bindgen(typescript_custom_section)]` + `unchecked_return_type`), zero uncaught panics (`Result<JsValue, JsError>` / `Result<Vec<u8>, JsError>`), UTF-8 byte offset to zero-based UTF-16 `(line, col)` conversion (`byte_offset_to_utf16_line_col`), and in-memory PCAPNG serialization (`PcapNgWriter::new(Vec::new())` / direct block writer without `std::fs`).

```rust
//! WebAssembly bindings, frame inspector, and UTF-16 IDE diagnostics for the FrameAssembly
//! (`.fasm`) network packet synthesis compiler.
//!
//! This crate exposes `validate_fasm`, `inspect_fasm`, and `compile_fasm_to_pcapng` to browser
//! environments and web-based code editors (Monaco, CodeMirror, VS Code Web) via `wasm-bindgen`.
//! It compiles declarative `.fasm` specifications across all 81 native Layer 2 through Layer 7
//! protocols into deterministic nanosecond-resolution PCAPNG byte arrays (`Uint8Array`) and maps
//! compiler spans into zero-based UTF-16 line and column coordinates.

use std::fmt::Write;

use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;
use miette::Diagnostic;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Custom TypeScript interface definitions appended to the generated `.d.ts` bindings.
#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export interface IdeDiagnostic {
    start_line: number;
    start_col: number;
    end_line: number;
    end_col: number;
    message: string;
    help?: string;
}

export interface PacketPreview {
    index: number;
    timestamp_ms: number;
    length: number;
    hex: string;
}
"#;

/// Zero-based UTF-16 source range diagnostic and remediation hint for browser code editors.
#[derive(Serialize)]
pub struct IdeDiagnostic {
    /// Zero-based starting line index.
    pub start_line: u32,
    /// Zero-based starting UTF-16 column offset.
    pub start_col: u32,
    /// Zero-based ending line index.
    pub end_line: u32,
    /// Zero-based ending UTF-16 column offset.
    pub end_col: u32,
    /// Primary diagnostic error message.
    pub message: String,
    /// Optional plain-English remediation hint.
    pub help: Option<String>,
}

/// Summary metadata and hexadecimal wire dump for a single synthesized Ethernet frame.
#[derive(Serialize)]
pub struct PacketPreview {
    /// One-based frame sequence index in the capture.
    pub index: usize,
    /// Relative frame timestamp in milliseconds from the first frame.
    pub timestamp_ms: f64,
    /// Total Ethernet frame length in bytes.
    pub length: usize,
    /// Space-delimited lowercase hexadecimal representation of the frame bytes.
    pub hex: String,
}

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair
/// suitable for Monaco Editor, CodeMirror 6, and VS Code Web diagnostics.
pub fn byte_offset_to_utf16_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let clamped = byte_offset.min(source.len());
    let safe_end = (0..=clamped)
        .rev()
        .find(|&i| source.is_char_boundary(i))
        .unwrap_or(0);

    let prefix = &source[..safe_end];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() as u32;
    let col = match prefix.rfind('\n') {
        Some(nl) => prefix[nl + 1..].encode_utf16().count() as u32,
        None => prefix.encode_utf16().count() as u32,
    };
    (line, col)
}

/// Validates `.fasm` source and returns UTF-16 line/column diagnostics for Monaco/CodeMirror.
#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm(source: &str) -> Result<JsValue, JsError> {
    let mut diagnostics = Vec::new();

    match parse_program(source) {
        Ok(program) => {
            if let Err(err) = compile_program(&program) {
                diagnostics.push(IdeDiagnostic {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 1,
                    message: err,
                    help: None,
                });
            }
        }
        Err(err) => push_diagnostic(source, &err, &mut diagnostics),
    }

    Ok(serde_wasm_bindgen::to_value(&diagnostics)?)
}

/// Returns decoded frame metadata and hex strings for a browser packet inspector.
#[wasm_bindgen(unchecked_return_type = "PacketPreview[]")]
pub fn inspect_fasm(source: &str) -> Result<JsValue, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e.to_string()))?;
    let base_ns = packets.first().map_or(0, |(_, ts)| *ts);

    let previews: Vec<PacketPreview> = packets
        .iter()
        .enumerate()
        .map(|(idx, (bytes, ts_ns))| {
            let mut hex = String::with_capacity(bytes.len().saturating_mul(3));
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    hex.push(' ');
                }
                let _ = write!(hex, "{b:02x}");
            }
            PacketPreview {
                index: idx + 1,
                timestamp_ms: ts_ns.saturating_sub(base_ns) as f64 / 1_000_000.0,
                length: bytes.len(),
                hex,
            }
        })
        .collect();

    Ok(serde_wasm_bindgen::to_value(&previews)?)
}

/// Compiles `.fasm` source into a standards-compliant PCAPNG byte array (JS `Uint8Array`).
///
/// Never calls `std::fs::File::create`; serializes `SHB -> IDB -> EPBs` strictly in memory.
#[wasm_bindgen]
pub fn compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(packets_to_pcapng(&packets))
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory PCAPNG byte vector
/// using `pcap_file::pcapng::PcapNgWriter::new(Vec::new())` with nanosecond resolution (`IfTsResol(9)`).
pub fn packets_to_pcapng_via_writer(packets: &[(Vec<u8>, u64)]) -> Result<Vec<u8>, JsError> {
    use std::borrow::Cow;
    use std::time::Duration;
    use pcap_file::DataLink;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use pcap_file::pcapng::blocks::interface_description::{
        InterfaceDescriptionBlock, InterfaceDescriptionOption,
    };
    use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};

    let mut writer = PcapNgWriter::new(Vec::new())
        .map_err(|e| JsError::new(&format!("Failed to initialize in-memory PcapNgWriter: {e}")))?;

    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65535,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    };
    writer
        .write_block(&interface.into_block())
        .map_err(|e| JsError::new(&format!("Failed to write PCAPNG IDB: {e}")))?;

    for (frame, ts_ns) in packets {
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(*ts_ns),
            original_len: frame.len() as u32,
            data: Cow::Borrowed(frame),
            options: vec![],
        };
        writer
            .write_block(&epb.into_block())
            .map_err(|e| JsError::new(&format!("Failed to write PCAPNG EPB: {e}")))?;
    }

    Ok(writer.into_inner())
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory PCAPNG byte vector
/// with nanosecond timestamp resolution (`if_tsresol = 9`) without extra I/O buffering.
fn packets_to_pcapng(packets: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60 + packets.len() * 96);

    // Section Header Block (28 bytes, magic 0x0A0D0D0A, byte-order magic 0x1A2B3C4D)
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block (32 bytes, LINKTYPE_ETHERNET = 1, snaplen = 65535, if_tsresol = 9)
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&65_535u32.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&[9, 0, 0, 0]);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());

    // Enhanced Packet Blocks (type = 6, 32-bit padded payload)
    for (frame, ts_ns) in packets {
        let orig_len = frame.len() as u32;
        let padded_len = (frame.len() + 3) & !3;
        let block_len = (32 + padded_len) as u32;

        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&block_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&((ts_ns >> 32) as u32).to_le_bytes());
        buf.extend_from_slice(&(*ts_ns as u32).to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf.extend_from_slice(frame);
        buf.resize(buf.len() + (padded_len - frame.len()), 0);
        buf.extend_from_slice(&block_len.to_le_bytes());
    }

    buf
}

/// Extracts span coordinates and remediation hints from a `miette::Diagnostic` and appends an `IdeDiagnostic`.
fn push_diagnostic(source: &str, err: &dyn Diagnostic, out: &mut Vec<IdeDiagnostic>) {
    let message = err.to_string();
    let help = err.help().map(|h| h.to_string());

    if let Some(mut labels) = err.labels()
        && let Some(span) = labels.next()
    {
        let (start_line, start_col) = byte_offset_to_utf16_line_col(source, span.offset());
        let (end_line, end_col) =
            byte_offset_to_utf16_line_col(source, span.offset() + span.len().max(1));
        out.push(IdeDiagnostic {
            start_line,
            start_col,
            end_line,
            end_col,
            message,
            help,
        });
    } else {
        out.push(IdeDiagnostic {
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 1,
            message,
            help,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf16_line_col_handles_multibyte_utf8_and_surrogate_pairs() {
        // '🔥' is 4 UTF-8 bytes (0..4) and 2 UTF-16 code units
        let src = "HOST a { IP 10.0.0.1 }\n// 🔥\nCOMPILE {}";
        assert_eq!(byte_offset_to_utf16_line_col(src, 0), (0, 0));
        let line2_start = src.find("//").unwrap();
        // Offset right after "// 🔥" (3 ASCII bytes + 4 UTF-8 emoji bytes = +7 bytes)
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 7), (1, 5));
        // Mid-codepoint byte offset clamps safely to preceding char boundary
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 5), (1, 3));
    }
}
```

---

## 3. VS Code Extension Configuration (`frameassembly-vscode`)

### A. `frameassembly-vscode/package.json`
Configures language ID `"frameassembly"`, MIME `"text/vnd.frameassembly"`, `firstLine` regex `^(?:HOST|FLOW|COMPILE|host|flow|compile|//)` (without `#` or `;`), primary TextMate grammar `"source.frameassembly"`, Markdown fenced codeblock injection `"markdown.frameassembly.codeblock"`, and PNG icon `"icon.png"`.

```json
{
  "name": "frameassembly-vscode",
  "displayName": "FrameAssembly (.fasm Packet Crafting DSL)",
  "description": "Syntax highlighting and language support for FrameAssembly (.fasm), the declarative DSL for deterministic .pcap/.pcapng network packet generation across 81 L2-L7 protocols.",
  "version": "1.5.0",
  "publisher": "SteveWinschel",
  "icon": "icon.png",
  "galleryBanner": {
    "color": "#0F172A",
    "theme": "dark"
  },
  "license": "MIT",
  "homepage": "https://github.com/SteveWinschel/FrameAssembly",
  "bugs": {
    "url": "https://github.com/SteveWinschel/FrameAssembly/issues"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/SteveWinschel/FrameAssembly.git"
  },
  "engines": {
    "vscode": "^1.75.0"
  },
  "categories": [
    "Programming Languages",
    "Snippets"
  ],
  "keywords": [
    "frameassembly",
    "fasm",
    "pcap",
    "pcapng",
    "wireshark",
    "packet-crafting",
    "networking",
    "security",
    "snmp",
    "dsl"
  ],
  "contributes": {
    "languages": [
      {
        "id": "frameassembly",
        "aliases": [
          "FrameAssembly",
          "frameassembly"
        ],
        "extensions": [
          ".fasm"
        ],
        "mimetypes": [
          "text/vnd.frameassembly"
        ],
        "firstLine": "^(?:HOST|FLOW|COMPILE|host|flow|compile|//)",
        "configuration": "./language-configuration.json"
      }
    ],
    "grammars": [
      {
        "language": "frameassembly",
        "scopeName": "source.frameassembly",
        "path": "./syntaxes/frameassembly.tmLanguage.json"
      },
      {
        "scopeName": "markdown.frameassembly.codeblock",
        "path": "./syntaxes/frameassembly.markdown.tmLanguage.json",
        "injectTo": [
          "text.html.markdown"
        ],
        "embeddedLanguages": {
          "meta.embedded.block.frameassembly": "frameassembly"
        }
      }
    ],
    "snippets": [
      {
        "language": "frameassembly",
        "path": "./snippets/frameassembly.code-snippets"
      }
    ]
  }
}
```

### B. `frameassembly-vscode/language-configuration.json` & `.vscodeignore`
```json
{
    "comments": {
        "lineComment": "//"
    },
    "brackets": [
        ["{", "}"],
        ["(", ")"]
    ],
    "autoClosingPairs": [
        { "open": "{", "close": "}" },
        { "open": "(", "close": ")" },
        { "open": "\"", "close": "\"", "notIn": ["string", "comment"] }
    ],
    "surroundingPairs": [
        ["{", "}"],
        ["(", ")"],
        ["\"", "\""]
    ],
    "folding": {
        "markers": {
            "start": "^\\s*(?i:HOST|FLOW|COMPILE|LOOP)\\b.*\\{\\s*$",
            "end": "^\\s*\\}"
        }
    }
}
```

```text
.vscode/**
.vscode-test/**
.gitignore
vsc-extension-quickstart.md
*.pcap
*.pcapng
*.vsix
```

---

## 4. TextMate Grammar & Markdown Injection Patterns

### A. Primary Grammar Structure (`syntaxes/frameassembly.tmLanguage.json`)
Must include every uppercase and lowercase keyword variant from `src/lexer/mod.rs` (verified by Gate 4 in `tests/corpus_verification_tests.rs`):

```json
{
  "$schema": "https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json",
  "name": "FrameAssembly",
  "scopeName": "source.frameassembly",
  "patterns": [
    { "include": "#comments" },
    { "include": "#strings" },
    { "include": "#keywords" },
    { "include": "#protocols" },
    { "include": "#constants" },
    { "include": "#properties" },
    { "include": "#operators" },
    { "include": "#numbers" }
  ],
  "repository": {
    "comments": {
      "match": "//.*$",
      "name": "comment.line.double-slash.frameassembly"
    },
    "strings": {
      "begin": "\"",
      "end": "\"",
      "name": "string.quoted.double.frameassembly",
      "patterns": [
        {
          "match": "\\\\(?:[rnt\"\\\\]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})",
          "name": "constant.character.escape.frameassembly"
        }
      ]
    },
    "keywords": {
      "match": "(?i)\\b(HOST|FLOW|COMPILE|LOOP|host|flow|compile|loop)\\b",
      "name": "keyword.control.frameassembly"
    },
    "operators": {
      "match": "(->|<-)",
      "name": "keyword.operator.direction.frameassembly"
    },
    "numbers": {
      "patterns": [
        {
          "match": "\\b[0-9]+(?i:ns|us|ms|s|m)\\b",
          "name": "constant.numeric.duration.frameassembly"
        },
        {
          "match": "\\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\\b|\\b(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\\b|\\b(?:[0-9a-fA-F]{4}\\.){2}[0-9a-fA-F]{4}\\b",
          "name": "constant.numeric.mac.frameassembly"
        }
      ]
    }
  }
}
```

### B. Markdown Codeblock Injection (`syntaxes/frameassembly.markdown.tmLanguage.json`)
Highlights fenced ````frameassembly`, ````fasm`, and ````text/vnd.frameassembly` blocks inside Markdown files:

```json
{
  "$schema": "https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json",
  "name": "FrameAssembly Markdown Codeblock",
  "scopeName": "markdown.frameassembly.codeblock",
  "injectTo": [
    "text.html.markdown"
  ],
  "patterns": [
    {
      "include": "#frameassembly-code-block"
    }
  ],
  "repository": {
    "frameassembly-code-block": {
      "begin": "(^|\\G)(\\s*)(`{3,}|~{3,})\\s*(?i:(frameassembly|fasm|text/vnd\\.frameassembly)((\\s+|:|,|\\{|\\?)[^`~]*)?$)",
      "name": "markup.fenced_code.block.markdown",
      "end": "(^|\\G)(\\2|\\s{0,3})(\\3)\\s*$",
      "beginCaptures": {
        "3": { "name": "punctuation.definition.markdown" },
        "4": { "name": "fenced_code.block.language.markdown" },
        "5": { "name": "fenced_code.block.language.attributes.markdown" }
      },
      "endCaptures": {
        "3": { "name": "punctuation.definition.markdown" }
      },
      "patterns": [
        {
          "begin": "(^|\\G)(\\s*)(.*)",
          "while": "(^|\\G)(?!\\s*([`~]{3,})\\s*$)",
          "contentName": "meta.embedded.block.frameassembly",
          "patterns": [
            { "include": "source.frameassembly" }
          ]
        }
      ]
    }
  }
}
```

---

## 5. GitHub Actions WASM & VS Code OIDC Trusted Publishing Workflow

Demonstrates `CARGO_PROFILE_RELEASE_STRIP: none`, `wasm-pack build --release --target web`, `npx @vscode/vsce package`, `env:` secret-guarding, and post-Dec-1-2026 OIDC Trusted Publishing (`npm publish --provenance --access public` and `npx @vscode/vsce@latest publish --oidc`).

```yaml
  wasm:
    name: Build & Package WebAssembly (NPM)
    needs: [prepare]
    runs-on: ubuntu-24.04
    continue-on-error: true
    permissions:
      contents: read
      id-token: write
    env:
      # CRITICAL: preserve .target_features section for wasm-bindgen 0.2.130 & Rust 1.96+ WASM symbol checks
      CARGO_PROFILE_RELEASE_STRIP: none
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - name: Checkout tagged commit
        uses: actions/checkout@v4
        with:
          ref: ${{ needs.prepare.outputs.tag }}

      - name: Install Rust stable with wasm32-unknown-unknown
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown

      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22
          registry-url: 'https://registry.npmjs.org'

      - name: Build WebAssembly package & normalize pkg/package.json repository URL
        working-directory: frameassembly-wasm
        run: |
          wasm-pack build --release --target web
          node -e '
            const fs = require("fs");
            const pkg = JSON.parse(fs.readFileSync("pkg/package.json", "utf8"));
            pkg.repository = {
              type: "git",
              url: "git+https://github.com/SteveWinschel/FrameAssembly.git"
            };
            fs.writeFileSync("pkg/package.json", JSON.stringify(pkg, null, 2) + "\n");
          '

      - name: Publish to NPM Registry via Token (Optional)
        id: npm_token_publish
        if: ${{ env.NPM_TOKEN != '' }}
        continue-on-error: true
        working-directory: frameassembly-wasm/pkg
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          echo "//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}" > ~/.npmrc
          npm publish --provenance --access public

      - name: Publish to NPM Registry via OIDC Trusted Publisher
        if: ${{ env.NPM_TOKEN == '' || steps.npm_token_publish.outcome == 'failure' }}
        continue-on-error: true
        working-directory: frameassembly-wasm/pkg
        run: |
          npm install -g npm@latest
          rm -f ~/.npmrc "$NPM_CONFIG_USERCONFIG"
          unset NPM_TOKEN NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG
          npm publish --provenance --access public

  vscode-extension:
    name: Package & Publish VS Code Extension (.vsix)
    needs: [prepare]
    runs-on: ubuntu-24.04
    continue-on-error: true
    permissions:
      contents: read
      id-token: write
    env:
      VSCE_PAT: ${{ secrets.VSCE_PAT }}
    steps:
      - name: Checkout tagged commit
        uses: actions/checkout@v4
        with:
          ref: ${{ needs.prepare.outputs.tag }}

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Package VSIX with @vscode/vsce 4.1.0
        working-directory: frameassembly-vscode
        run: |
          VERSION="${{ needs.prepare.outputs.version }}"
          npx --yes @vscode/vsce package --no-git-tag-version --no-update-package-json -o "frameassembly-vscode-${VERSION}.vsix"

      - name: Publish to Visual Studio Marketplace via PAT (Optional)
        id: vsce_pat_publish
        if: ${{ env.VSCE_PAT != '' }}
        continue-on-error: true
        working-directory: frameassembly-vscode
        env:
          VSCE_PAT: ${{ secrets.VSCE_PAT }}
        run: |
          VERSION="${{ needs.prepare.outputs.version }}"
          npx --yes @vscode/vsce@latest publish -p "${{ secrets.VSCE_PAT }}" --packagePath "frameassembly-vscode-${VERSION}.vsix"

      - name: Publish to Visual Studio Marketplace via OIDC Trusted Publisher
        if: ${{ env.VSCE_PAT == '' || steps.vsce_pat_publish.outcome == 'failure' }}
        continue-on-error: true
        working-directory: frameassembly-vscode
        run: |
          VERSION="${{ needs.prepare.outputs.version }}"
          unset VSCE_PAT
          npx --yes @vscode/vsce@latest publish --oidc --packagePath "frameassembly-vscode-${VERSION}.vsix"
```
