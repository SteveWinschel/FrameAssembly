# Change Log

All notable changes to the `frameassembly-vscode` extension are documented in this file.

## [3.1.0] - 2026-11-15
- Streamlined the extension into a fast, read-only **Syntax Highlighting + Live WebAssembly Linter** (with 1-click Quick Fix support for lowercase keywords and common modifier typos), removing editor commands, Webview panels, startup popups, snippets, and custom autocomplete bloat.
- Declared explicit `capabilities.untrustedWorkspaces` and `capabilities.virtualWorkspaces` support so syntax highlighting and live linting remain active inside VS Code Restricted Mode and browser editors (`vscode.dev`, `github.dev`).
- Synchronized the embedded WebAssembly validator and `source.frameassembly` TextMate grammar (`report`, `nextheader`, `auth`, and all 81 protocols) with FrameAssembly 3.1.0.

## [3.0.0] - 2026-11-13
- Renamed FrameAssembly source files from `.fasm` to **`.frasm`** across the language registration and Markdown fenced-block highlighting (`frameassembly` and `frasm` blocks), preserving the `source.frameassembly` scope and `text/vnd.frameassembly` MIME type so `.fasm` x86 Flat Assembler and FPGA FASM files never collide.

## [2.0.0] - 2026-11-10
- Added embedded `frameassembly-wasm` live UTF-16 diagnostics and 1-click Quick Fixes across Desktop and Web (`vscode.dev`) Extension Hosts.
- Updated TextMate grammars (`syntaxes/frameassembly.tmLanguage.json` and `syntaxes/frameassembly.markdown.tmLanguage.json`) and `language-configuration.json` to lowercase keyword syntax.

## [1.5.0] - 2026-11-07
- Synchronized with FrameAssembly v1.5.0 release (MAC-only Layer 2 `host` blocks and inline frame statements inside `compile { ... }`).

## [1.4.3] - 2026-11-02
- Added Markdown fenced code block syntax injection (`syntaxes/frameassembly.markdown.tmLanguage.json`).

## [1.3.0] - 2026-10-31
- Extended MAC address TextMate syntax highlighting to support colon-separated (`00:1a:2b:3c:4d:5e`), hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco IOS dotted-quad (`001a.2b3c.4d5e`) formats.
- Removed unsupported `/* ... */` block comments, `[...]` bracket auto-closing pairs, and `'...'` single-quote auto-closing pairs from `language-configuration.json`.

## [1.2.1] - 2026-10-28
- Lowered minimum VS Code engine requirement (`engines.vscode`) to `^1.75.0` for compatibility across VS Code, Cursor, Windsurf, VSCodium, and Antigravity IDE.

## [1.0.0] - 2026-10-23
- Initial 1.0 release with syntax highlighting across all 81 native Layer 2 through Layer 7 protocols, IPv4/IPv6/MAC/OID/hex literals, and duration units (`ns`, `us`, `ms`, `s`, `m`).
