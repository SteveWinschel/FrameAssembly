# Change Log

All notable changes to the "frameassembly-vscode" extension will be documented in this file.

Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

## [1.2.2] - Unreleased
- Synchronized extension version with FrameAssembly v1.2.2 (documentation overhaul for network engineers; no grammar changes).

## [1.2.1] - 2026-10-28
- Lowered minimum VS Code engine requirement (`engines.vscode`) from `^1.107.0` to `^1.75.0` for broad compatibility across VS Code, Cursor, Windsurf, VSCodium, and Antigravity IDE.
- Enriched extension manifest metadata (`displayName`, `license`, `homepage`, `bugs`, `keywords`) and synchronized with FrameAssembly v1.2.1 release.

## [1.2.0] - 2026-10-27
- Enabled full case-insensitive syntax highlighting (`(?i)`) across all keywords, protocols, constants, modifiers, and duration units (`ns`, `us`, `ms`, `s`, `m`).
- Synchronized with FrameAssembly v1.2.0 release.

## [1.1.1] - 2026-10-25
- Added zero-clone `.vsix` bootstrap installation via `install.sh` and synchronized with FrameAssembly v1.1.1.

## [1.1.0] - 2026-10-25
- Synchronized all 640 lexer keywords across the 5-way grammar lockstep (`src/lexer/mod.rs`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly.tmLanguage.json`).
- Synchronized with FrameAssembly v1.1.0 release.

## [1.0.1] - 2026-10-24
- Synchronized with FrameAssembly v1.0.1 release.

## [1.0.0] - 2026-10-23

### Added
- Complete syntax highlighting coverage for all 81 native protocols across Layer 2, Layer 3, Layer 4, and Layer 7.
- Comprehensive sub-keyword and frame modifier highlighting (over 180 protocol-specific modifiers and fields across L2–L7).
- Highlighting support for all duration units: nanoseconds (`ns`), microseconds (`us`), milliseconds (`ms`), seconds (`s`), and minutes (`m`).
- Full IPv6 address syntax highlighting (compressed, full, and IPv4-mapped forms) alongside IPv4 addresses and IEEE 802 MAC addresses.
- SNMP OID dotted-notation highlighting and hexadecimal integer literal (`0x...`) support.
- Synchronized with FrameAssembly v1.0.0 declarative packet-crafting compiler DSL.

## [0.12.1] - 2026-10-20
- Initial beta release with basic TCP, UDP, and SNMP highlighting.