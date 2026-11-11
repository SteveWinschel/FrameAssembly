# Change Log

All notable changes to the "frameassembly-vscode" extension will be documented in this file.

Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

## [2.0.0] - 2026-11-10
- Upgraded into the **FrameAssembly — PCAP & Network Packet Studio (`.fasm` v2.0.0)** powered by the embedded `frameassembly-wasm` 2.0.0 engine across Desktop and Web (`vscode.dev`) Extension Hosts.
- Added **Live Diagnostics & 1-Click Quick Fixes**: `120ms`-debounced UTF-16 compiler diagnostics with `CodeActionProvider` quick fixes that convert legacy uppercase or underscored keywords into FrameAssembly 2.0 strict lowercase.
- Added **Protocol-Scoped Autocomplete (`CompletionItemProvider`)** backed by `protocol_schema.json` across `host`/`flow`/`compile` blocks, endpoint identifiers, all 81 L2–L7 protocols, and active-protocol modifiers.
- Added **Live Packet Ladder Webview (`frameassembly.showPacketLadder`)** and **Compile `.fasm` to `.pcapng` (`frameassembly.compileToPcap`)** editor title bar actions.
- Added **Explorer Right-Click Reverse Capture (`frameassembly.reversePcap`)** to decompile `.pcap` and `.pcapng` files directly into `.fasm` code in VS Code.
- Updated TextMate grammars (`syntaxes/frameassembly.tmLanguage.json` and `syntaxes/frameassembly.markdown.tmLanguage.json`), `language-configuration.json`, `firstLine` signature, and all 18 built-in snippets to FrameAssembly 2.0 strict lowercase (removing `loop` and keyword underscores/hyphens).

## [1.5.1] - 2026-11-08
- Linked official website and interactive browser playground (`https://frameassembly.ai.studio/`) across extension metadata and documentation, and synchronized with FrameAssembly v1.5.1 release.

## [1.5.0] - 2026-11-07
- Synchronized with FrameAssembly v1.5.0 release (PCAP/PCAPNG-to-`.fasm` decompilation, MAC-only Layer 2 `host` blocks, and inline frame statements inside `compile { ... }`).
- Added `compile-inline` (inline `compile { ... }` frame capture without a `flow` block) and `host-l2` (MAC-only Layer 2 endpoint) snippets to `snippets/frameassembly.code-snippets` (18 tab-completable snippets total).

## [1.4.6] - 2026-11-05
- Synchronized with FrameAssembly v1.4.6 release.

## [1.4.5] - 2026-11-04
- Synchronized with FrameAssembly v1.4.5 release.

## [1.4.4] - 2026-11-03
- Synchronized with FrameAssembly v1.4.4 release.

## [1.4.3] - 2026-11-02
- Added Markdown fenced code block syntax injection (`syntaxes/frameassembly.markdown.tmLanguage.json`) for ```` ```frameassembly ```` and ```` ```fasm ```` blocks.
- Expanded TextMate keyword, protocol, constant, and property rules across all supported editors.
- Updated built-in `.fasm` code snippets to lowercase syntax.
- Multi-platform packaging and distribution release automation across APT, Homebrew, and Scoop.
- Official WebAssembly compiler package (`frameassembly-wasm`) on NPM for browser and Node.js runtimes.
- Synchronized with FrameAssembly v1.4.3 release.

## [1.3.1] - 2026-11-01
- Multi-platform packaging and distribution release synchronization across APT, Homebrew, and Scoop.
- Official `.fasm` (`text/vnd.frameassembly`) MIME and magic registration harmonization.
- Synchronized with FrameAssembly v1.3.1 release.

## [1.3.0] - 2026-10-31
- Added 16 tab-completable `.fasm` code snippets (`snippets/frameassembly.code-snippets`) for rapid network scenario authoring.
- Extended MAC address TextMate syntax highlighting to support colon-separated (`00:1a:2b:3c:4d:5e`), hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco IOS dotted-quad (`001a.2b3c.4d5e`) formats.
- Removed unsupported `/* ... */` block comments, `[...]` bracket auto-closing pairs, and `'...'` single-quote auto-closing pairs from `language-configuration.json` to prevent invalid syntax insertion.
- Synchronized with FrameAssembly v1.3.0 release.

## [1.2.2] - 2026-10-29
- Synchronized extension version with FrameAssembly v1.2.2 (documentation overhaul for network engineers; no grammar changes).

## [1.2.1] - 2026-10-28
- Lowered minimum VS Code engine requirement (`engines.vscode`) from `^1.107.0` to `^1.75.0` for broad compatibility across VS Code, Cursor, Windsurf, VSCodium, and Antigravity IDE.
- Enriched extension manifest metadata (`displayName`, `license`, `homepage`, `bugs`, `keywords`) and synchronized with FrameAssembly v1.2.1 release.

## [1.2.0] - 2026-10-27
- Enabled case-insensitive syntax highlighting across keywords, protocols, constants, modifiers, and duration units (`ns`, `us`, `ms`, `s`, `m`).
- Synchronized with FrameAssembly v1.2.0 release.

## [1.1.1] - 2026-10-25
- Added zero-clone `.vsix` bootstrap installation via `install.sh` and synchronized with FrameAssembly v1.1.1.

## [1.1.0] - 2026-10-25
- Synchronized all lexer keywords across `src/lexer/mod.rs`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly.tmLanguage.json`.
- Synchronized with FrameAssembly v1.1.0 release.

## [1.0.1] - 2026-10-24
- Synchronized with FrameAssembly v1.0.1 release.

## [1.0.0] - 2026-10-23

### Added
- Complete syntax highlighting coverage for all 81 native protocols across Layer 2, Layer 3, Layer 4, and Layer 7.
- Comprehensive sub-keyword and frame modifier highlighting across L2–L7.
- Highlighting support for all duration units: nanoseconds (`ns`), microseconds (`us`), milliseconds (`ms`), seconds (`s`), and minutes (`m`).
- Full IPv6 address syntax highlighting (compressed, full, and IPv4-mapped forms) alongside IPv4 addresses and IEEE 802 MAC addresses.
- SNMP OID dotted-notation highlighting and hexadecimal integer literal (`0x...`) support.
- Synchronized with FrameAssembly v1.0.0 packet-crafting compiler.

## [0.12.1] - 2026-10-20
- Initial beta release with basic TCP, UDP, and SNMP highlighting.
