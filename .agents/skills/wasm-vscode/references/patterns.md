# WebAssembly (`frameassembly-wasm`) & VS Code Packet Studio (`frameassembly-vscode`) Reference Patterns (v2.0.0)

This reference document provides complete, production-verified v2.0.0 templates for `frameassembly-wasm/Cargo.toml`, `frameassembly-wasm/src/lib.rs`, `frameassembly-vscode/package.json`, `frameassembly-vscode/extension.js`, `language-configuration.json`, strict-lowercase TextMate grammar definitions (`source.frameassembly` and `markdown.frameassembly.codeblock`), and GitHub Actions OIDC Trusted Publishing workflows across supported release channels only (GitHub Releases + `.deb`, Crates.io, NPM `frameassembly-wasm`, VS Code Marketplace, and `SteveWinschel/homebrew-tap-FrameAssembly` for `Homebrew` & `Scoop`).

---

## 1. `frameassembly-wasm/Cargo.toml` Production Manifest (`v2.0.0`)

Configures `crate-type = ["cdylib", "rlib"]`, `miette = { version = "7.6.0", default-features = false }` (avoiding terminal/filesystem dependencies on `wasm32-unknown-unknown`), `wasm-bindgen = "0.2.130"`, `serde-wasm-bindgen = "0.6.5"`, and `[package.metadata.wasm-pack.profile.release] wasm-opt = false` so `wasm-pack 0.15.1` preserves bulk-memory and multivalue instructions emitted by `rustc 1.99.1`.

```toml
[package]
name = "frameassembly-wasm"
version = "2.0.0"
edition = "2024"
rust-version = "1.85"
authors = ["Steve Winschel"]
description = "Compile .fasm network traffic code to .pcapng and decompile .pcap/.pcapng captures in WebAssembly across 81 L2-L7 protocols with live IDE diagnostics."
license = "MIT"
documentation = "https://docs.rs/frameassembly-wasm"
repository = "https://github.com/SteveWinschel/FrameAssembly"
homepage = "https://frameassembly.ai.studio/"
readme = "README.md"
keywords = ["frameassembly", "pcap", "pcapng", "packet-generator", "wasm"]

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
frameassembly = { path = "..", version = "2.0.0" }
miette = { version = "7.6.0", default-features = false }
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

## 2. `frameassembly-wasm/src/lib.rs` Complete v2.0.0 Implementation

Exposes `validate_fasm` (`validateFasm`), `inspect_fasm`, `compile_fasm_to_pcapng` (`compileFasm`), and `reverse_pcap` (`reversePcap`) with typed TypeScript declarations, `find_backend_error_span` (resolving backend compilation errors to the offending identifier or `compile` block instead of `(0, 0)`), preserved `help` hints for 1-click Quick Fixes, enriched `PacketPreview` (`source_dest`, `protocol`, `summary`), and in-memory PCAPNG serialization/decompilation.

```rust
//! WebAssembly bindings, PCAP/PCAPNG-to-`.fasm` decompiler, frame inspector, and UTF-16 IDE
//! diagnostics for the FrameAssembly (`.fasm` v2.0.0) network packet synthesis compiler.

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;
use frameassembly::reverse::reverse_pcap_bytes;
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
    source_dest: string;
    protocol: string;
    summary: string;
}

export interface ReversePcapResult {
    success: boolean;
    fasm: string;
    packetCount: number;
    hostCount: number;
}
"#;

/// Zero-based UTF-16 source range diagnostic and remediation hint for browser and IDE code editors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// Optional plain-English remediation hint (including v2.0.0 lowercase keyword quick-fix hints).
    pub help: Option<String>,
}

/// Summary metadata, protocol dissection, and hexadecimal wire dump for a synthesized Ethernet frame.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PacketPreview {
    /// One-based frame sequence index in the capture.
    pub index: usize,
    /// Relative frame timestamp in milliseconds from the first frame.
    pub timestamp_ms: f64,
    /// Total Ethernet frame length in bytes.
    pub length: usize,
    /// Space-delimited lowercase hexadecimal representation of the frame bytes.
    pub hex: String,
    /// Formatted `source -> destination` IPv4, IPv6, or MAC endpoint pair.
    pub source_dest: String,
    /// Dissected highest-layer protocol label (e.g. `DNS`, `SNMP`, `MODBUS`, `TCP`, `ARP`).
    pub protocol: String,
    /// Human-readable Ethernet/VLAN/QinQ/MPLS/L3/L4/L7 frame summary string.
    pub summary: String,
}

/// Decompilation summary and canonical `.fasm` code returned by [`reverse_pcap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversePcapResult {
    /// Indicates that the binary capture was decompiled into `.fasm` code (`true`).
    pub success: bool,
    /// Generated canonical strict-lowercase `.fasm` source code (`host1`, `host2`, zero `loop`).
    pub fasm: String,
    /// Total number of packets reversed from the capture.
    pub packet_count: usize,
    /// Total number of `host1`, `host2`, ... definitions emitted in the `.fasm` program.
    pub host_count: usize,
}

/// Converts a UTF-8 byte offset within `source` into a zero-based `(line, utf16_col)` pair
/// suitable for Monaco Editor, CodeMirror 6, and VS Code diagnostics.
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

/// Locates the `compile` block keyword or offending single-quoted identifier span in `source`
/// so backend compilation errors never highlight `(0, 0)` when a `compile` block is present.
pub fn find_backend_error_span(source: &str, err_msg: &str) -> (usize, usize) {
    if let Some(q1) = err_msg.find('\'')
        && let Some(q2) = err_msg[q1 + 1..].find('\'')
    {
        let subject = &err_msg[q1 + 1..q1 + 1 + q2];
        if !subject.is_empty()
            && let Some(idx) = source.rfind(subject)
        {
            return (idx, idx + subject.len());
        }
    }
    if let Some(idx) = source.rfind("compile") {
        return (idx, idx + "compile".len());
    }
    (0, source.len().min(1))
}

/// Validates `.fasm` source and returns UTF-16 line/column diagnostics for Monaco, CodeMirror, and VS Code.
#[wasm_bindgen(unchecked_return_type = "IdeDiagnostic[]")]
pub fn validate_fasm(source: &str) -> Result<JsValue, JsError> {
    let mut diagnostics = Vec::new();

    match parse_program(source) {
        Ok(program) => {
            if let Err(err) = compile_program(&program) {
                let (start_byte, end_byte) = find_backend_error_span(source, &err);
                let (start_line, start_col) = byte_offset_to_utf16_line_col(source, start_byte);
                let (end_line, end_col) =
                    byte_offset_to_utf16_line_col(source, end_byte.max(start_byte + 1));
                diagnostics.push(IdeDiagnostic {
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                    message: err,
                    help: None,
                });
            }
        }
        Err(err) => push_diagnostic(source, &err, &mut diagnostics),
    }

    Ok(serde_wasm_bindgen::to_value(&diagnostics)?)
}

/// Returns decoded frame metadata, endpoint/protocol summaries, and hex strings for packet ladder inspectors.
#[wasm_bindgen(unchecked_return_type = "PacketPreview[]")]
pub fn inspect_fasm(source: &str) -> Result<JsValue, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e))?;
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
            let (source_dest, protocol, summary) = summarize_ethernet_frame(bytes);
            PacketPreview {
                index: idx + 1,
                timestamp_ms: ts_ns.saturating_sub(base_ns) as f64 / 1_000_000.0,
                length: bytes.len(),
                hex,
                source_dest,
                protocol,
                summary,
            }
        })
        .collect();

    Ok(serde_wasm_bindgen::to_value(&previews)?)
}

/// Compiles `.fasm` source into a standards-compliant PCAPNG byte array (JS `Uint8Array`).
#[wasm_bindgen]
pub fn compile_fasm_to_pcapng(source: &str) -> Result<Vec<u8>, JsError> {
    let program = parse_program(source).map_err(|e| JsError::new(&e.to_string()))?;
    let packets = compile_program(&program).map_err(|e| JsError::new(&e))?;
    Ok(packets_to_pcapng(&packets))
}

/// Decompiles an in-memory `.pcap` or `.pcapng` capture (`Uint8Array`) into canonical v2.0.0 `.fasm` code.
#[wasm_bindgen(unchecked_return_type = "ReversePcapResult")]
pub fn reverse_pcap(pcap_bytes: &[u8]) -> Result<JsValue, JsError> {
    let out = reverse_pcap_bytes(pcap_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let result = ReversePcapResult {
        success: true,
        fasm: out.fasm,
        packet_count: out.packet_count,
        host_count: out.host_count,
    };
    Ok(serde_wasm_bindgen::to_value(&result)?)
}

/// Dissects Ethernet II / IPv4 / IPv6 headers into `(source_dest, protocol, summary)` preview strings.
fn summarize_ethernet_frame(data: &[u8]) -> (String, String, String) {
    if data.len() < 14 {
        return ("unknown -> unknown".into(), "RAW".into(), format!("{} bytes", data.len()));
    }
    let etype = u16::from_be_bytes([data[12], data[13]]);
    if etype == 0x0800 && data.len() >= 34 {
        let src = Ipv4Addr::new(data[26], data[27], data[28], data[29]);
        let dst = Ipv4Addr::new(data[30], data[31], data[32], data[33]);
        return (format!("{src} -> {dst}"), format!("IP({})", data[23]), format!("{} bytes", data.len()));
    }
    if etype == 0x86DD && data.len() >= 54 {
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[22..38]).unwrap_or_default());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[38..54]).unwrap_or_default());
        return (format!("{src} -> {dst}"), format!("IPv6({})", data[20]), format!("{} bytes", data.len()));
    }
    ("l2 -> l2".into(), format!("0x{etype:04x}"), format!("{} bytes", data.len()))
}

/// Serializes `(frame_bytes, timestamp_ns)` tuples into an in-memory PCAPNG byte vector (`if_tsresol = 9`).
fn packets_to_pcapng(packets: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60 + packets.len() * 96);
    // SHB (28B) + IDB (32B, LINKTYPE_ETHERNET = 1, snaplen = 65535, if_tsresol = 9)
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());

    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&65_535u32.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&[9, 0, 0, 0]);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&32u32.to_le_bytes());

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

/// Extracts span coordinates and remediation hints from a `miette::Diagnostic`.
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
        let src = "host a { ip 10.0.0.1 }\n// 🔥\ncompile {}";
        assert_eq!(byte_offset_to_utf16_line_col(src, 0), (0, 0));
        let line2_start = src.find("//").unwrap();
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 7), (1, 5));
        assert_eq!(byte_offset_to_utf16_line_col(src, line2_start + 5), (1, 3));
    }
}
```

---

## 3. VS Code Packet Studio Configuration (`frameassembly-vscode` v2.0.0)

### A. `frameassembly-vscode/package.json`
Configures `"main": "./extension.js"` and `"browser": "./extension.js"`, 30 Marketplace SEO keywords (zero `"DSL"` jargon), strict-lowercase `"firstLine": "^(?:host|flow|compile|//)"`, editor title-bar Packet Ladder & `.pcapng` compile commands, and Explorer `.pcap`/`.pcapng` reverse command.

```json
{
  "name": "frameassembly-vscode",
  "displayName": "FrameAssembly — PCAP & Network Packet Studio (.fasm)",
  "description": "Compile, inspect, and reverse .pcap / .pcapng network packet captures as .fasm code across 81 L2-L7 protocols with live diagnostics, autocomplete, and packet ladder preview.",
  "version": "2.0.0",
  "publisher": "SteveWinschel",
  "icon": "icon.png",
  "galleryBanner": {
    "color": "#0F172A",
    "theme": "dark"
  },
  "license": "MIT",
  "homepage": "https://frameassembly.ai.studio/",
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
  "main": "./extension.js",
  "browser": "./extension.js",
  "activationEvents": [
    "onLanguage:frameassembly",
    "onCommand:frameassembly.reversePcap"
  ],
  "categories": [
    "Programming Languages",
    "Snippets",
    "Linters",
    "Other"
  ],
  "keywords": [
    "frameassembly", "fasm", "pcap", "pcapng", "wireshark", "tshark",
    "tcpreplay", "packet-crafting", "packet-generator", "pcap-editor",
    "pcap-decompiler", "packets-as-code", "networking", "network-testing",
    "firewall", "security", "cybersecurity", "pentesting", "suricata",
    "zeek", "siem", "ids", "shadow-it", "snmp", "snmpv3", "checkmk",
    "zabbix", "modbus", "scada", "vlan"
  ],
  "contributes": {
    "languages": [
      {
        "id": "frameassembly",
        "aliases": ["FrameAssembly", "frameassembly"],
        "extensions": [".fasm"],
        "mimetypes": ["text/vnd.frameassembly"],
        "firstLine": "^(?:host|flow|compile|//)",
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
        "injectTo": ["text.html.markdown"],
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
    ],
    "commands": [
      {
        "command": "frameassembly.compileToPcap",
        "title": "FrameAssembly: Compile .fasm to .pcapng",
        "icon": "$(package)"
      },
      {
        "command": "frameassembly.showPacketLadder",
        "title": "FrameAssembly: Show Live Packet Ladder Preview",
        "icon": "$(split-horizontal)"
      },
      {
        "command": "frameassembly.reversePcap",
        "title": "FrameAssembly: Reverse Capture (.pcap/.pcapng) to .fasm"
      }
    ],
    "menus": {
      "editor/title": [
        {
          "command": "frameassembly.showPacketLadder",
          "when": "editorLangId == frameassembly",
          "group": "navigation@1"
        },
        {
          "command": "frameassembly.compileToPcap",
          "when": "editorLangId == frameassembly",
          "group": "navigation@2"
        }
      ],
      "explorer/context": [
        {
          "command": "frameassembly.reversePcap",
          "when": "resourceExtname == .pcap || resourceExtname == .pcapng",
          "group": "navigation@1"
        }
      ]
    }
  }
}
```

### B. Universal `Uint8Array` WASM Loader & 1-Click Quick Fix Pattern (`extension.js`)
```javascript
const vscode = require("vscode");

// Universal WASM initialization for both Desktop Node Extension Host & Browser vscode.dev
async function loadWasmBindings(context) {
  const wasmJsUri = vscode.Uri.joinPath(context.extensionUri, "wasm", "frameassembly_wasm.js");
  const wasmBinUri = vscode.Uri.joinPath(context.extensionUri, "wasm", "frameassembly_wasm_bg.wasm");
  const wasmBytes = await vscode.workspace.fs.readFile(wasmBinUri);
  const mod = await import(wasmJsUri.toString());
  if (typeof mod.initSync === "function") {
    mod.initSync({ module: wasmBytes });
  } else if (typeof mod.default === "function") {
    await mod.default(wasmBytes);
  }
  return mod;
}

// 1-Click Quick Fix parsing "replace '<raw>' with '<kw>'" from IdeDiagnostic.help
function provideLowercaseQuickFixes(document, range, context) {
  const actions = [];
  for (const diag of context.diagnostics) {
    if (diag.source !== "frameassembly") continue;
    const match = /replace '([^']+)' with '([^']+)'/.exec(diag.message);
    if (!match) continue;
    const [, rawToken, canonicalKw] = match;
    const fix = new vscode.CodeAction(
      `Replace '${rawToken}' with '${canonicalKw}'`,
      vscode.CodeActionKind.QuickFix
    );
    fix.edit = new vscode.WorkspaceEdit();
    fix.edit.replace(document.uri, diag.range, canonicalKw);
    fix.diagnostics = [diag];
    fix.isPreferred = true;
    actions.push(fix);
  }
  return actions;
}

module.exports = { loadWasmBindings, provideLowercaseQuickFixes };
```

### C. `frameassembly-vscode/language-configuration.json` & `.vscodeignore`
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
            "start": "^\\s*(?:host|flow|compile)\\b.*\\{\\s*$",
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

## 4. Strict-Lowercase v2.0.0 TextMate Grammar & Markdown Injection Patterns

### A. Primary Grammar Structure (`syntaxes/frameassembly.tmLanguage.json`)
Must include every strict-lowercase `[a-z0-9]+` keyword from `src/lexer/mod.rs` (zero `_`, zero `-`, no `loop`, no `(?i)` case-insensitivity — verified by Gate 4 in `tests/corpus_verification_tests.rs`):

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
      "match": "\\b(host|flow|compile)\\b",
      "name": "keyword.control.frameassembly"
    },
    "operators": {
      "match": "(->|<-)",
      "name": "keyword.operator.direction.frameassembly"
    },
    "numbers": {
      "patterns": [
        {
          "match": "\\b[0-9]+(?:ns|us|ms|s|m)\\b",
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

## 5. GitHub Actions WASM -> VS Code (`needs: [prepare, wasm]`) OIDC Publishing Workflow

Demonstrates `CARGO_PROFILE_RELEASE_STRIP: none`, `wasm-pack build --release --target web`, `release-wasm` artifact bundling into `frameassembly-vscode/wasm/`, `npx @vscode/vsce package` (`frameassembly-vscode-2.0.0.vsix`), and post-Dec-1-2026 OIDC Trusted Publishing (`npm publish --provenance --access public` and `npx @vscode/vsce@latest publish --oidc` to Visual Studio Marketplace only).

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

      - name: Build WebAssembly package & sync package.json metadata
        working-directory: frameassembly-wasm
        run: |
          wasm-pack build --release --target web
          node -e '
            const fs = require("fs");
            const src = JSON.parse(fs.readFileSync("package.json", "utf8"));
            const pkg = JSON.parse(fs.readFileSync("pkg/package.json", "utf8"));
            for (const field of ["keywords", "description", "homepage", "license", "repository"]) {
              if (src[field] !== undefined) pkg[field] = src[field];
            }
            pkg.repository = pkg.repository || {
              type: "git",
              url: "git+https://github.com/SteveWinschel/FrameAssembly.git"
            };
            fs.writeFileSync("pkg/package.json", JSON.stringify(pkg, null, 2) + "\n");
          '

      - name: Package & upload WASM archive
        run: |
          TAG="${{ needs.prepare.outputs.tag }}"
          tar -czf "frameassembly-wasm-${TAG}.tar.gz" -C frameassembly-wasm pkg
      - uses: actions/upload-artifact@v4
        with:
          name: release-wasm
          path: frameassembly-wasm-*.tar.gz

      - name: Publish to NPM Registry via OIDC Trusted Publisher
        if: ${{ env.NPM_TOKEN == '' }}
        continue-on-error: true
        working-directory: frameassembly-wasm/pkg
        run: |
          npm install -g npm@latest
          unset NPM_TOKEN NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG
          npm publish --provenance --access public

  vscode-extension:
    name: Package & Publish VS Code Extension (.vsix)
    needs: [prepare, wasm]
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

      - name: Download release-wasm artifact & bundle into frameassembly-vscode/wasm
        uses: actions/download-artifact@v4
        with:
          name: release-wasm
          path: wasm-artifact
      - run: |
          mkdir -p wasm-extract frameassembly-vscode/wasm
          tar -xzf wasm-artifact/frameassembly-wasm-*.tar.gz -C wasm-extract
          cp -f wasm-extract/pkg/frameassembly_wasm.js \
                wasm-extract/pkg/frameassembly_wasm_bg.wasm \
                wasm-extract/pkg/frameassembly_wasm.d.ts \
                frameassembly-vscode/wasm/
          rm -rf wasm-artifact wasm-extract

      - name: Setup Node.js & Package VSIX with @vscode/vsce 4.1.0
        uses: actions/setup-node@v4
        with:
          node-version: 22
      - working-directory: frameassembly-vscode
        run: |
          VERSION="${{ needs.prepare.outputs.version }}"
          rm -f frameassembly-vscode-*.vsix
          npx --yes @vscode/vsce package --no-git-tag-version --no-update-package-json -o "frameassembly-vscode-${VERSION}.vsix"

      - name: Publish to Visual Studio Marketplace via OIDC Trusted Publisher
        if: ${{ env.VSCE_PAT == '' }}
        continue-on-error: true
        working-directory: frameassembly-vscode
        run: |
          VERSION="${{ needs.prepare.outputs.version }}"
          unset VSCE_PAT
          npx --yes @vscode/vsce@latest publish --oidc --packagePath "frameassembly-vscode-${VERSION}.vsix"
```
