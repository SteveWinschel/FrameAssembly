# CLAUDE.md — FrameAssembly Project Instructions for Claude Code & AI Agents

**FrameAssembly** (`frameassembly` v1.5.1, official website & interactive browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.fasm` network packet specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.fasm` code—across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

---

## 1. Essential Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (prebuilt release binary fast-path or curl + C linker + rustup >= 1.85 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and corpus verification tests
cargo test

# Run the corpus verification suite (validates all 2,611 examples/**/*.fasm headers, AST parsing & PCAP output)
cargo test --test corpus_verification_tests

# Compile a single .fasm specification to a .pcap file (defaults to <input_stem>.pcap)
cargo run -- demo.fasm -o output.pcap

# Show the terminal packet ladder for a .fasm file without writing a .pcap file
cargo run -- show demo.fasm

# Decompile a .pcap / .pcapng capture into canonical .fasm code (defaults to <input_stem>.fasm)
cargo run -- reverse output.pcap -o reversed.fasm
```

---

## 2. Canonical `.fasm` Language Rules (Zero Hallucinations)

1. **Three-Block Program Structure & Case-Insensitivity**:
   - All keywords, protocols, modifiers, time suffixes (`ns`, `us`, `ms`, `s`, `m`), and user-defined identifiers (`HOST`, `FLOW`, parameters) are case-insensitive (`host` / `HOST`, `tcp` / `TCP`).
   - `HOST <id> { IP <ipv4_or_ipv6> [MAC <mac>] }` (`MAC` is optional and accepts colon `00:1a:2b:3c:4d:5e`, hyphen `00-1A-2B-3C-4D-5E`, or Cisco dotted-quad `001a.2b3c.4d5e`; never use `IPV4`, `IPV6`, `=`, colons, commas, or `MASK`).
   - `FLOW <id>(<param1>, <param2>, ...) { <src> -> <dst> <PROTOCOL> [modifiers...] [WAIT <int><ns|us|ms|s|m>] }` (never declare parameterless `FLOW <id> { ... }` or use `FROM`, `TO`, `REVERSE`, `SEND`, standalone `WAIT` lines, or `+5ms` / `[+delay]` prefixes).
   - `COMPILE { <flow_id>(<host1>, <host2>, ...) [LOOP <count> { ... }] }` (every compilable `.fasm` program or Markdown ````frameassembly` code block must include `HOST`, `FLOW`, and `COMPILE { ... }`).
2. **Exact Modifier Keywords**:
   - Always use `SRCPORT`, `DSTPORT`, `SEQ`, `ACKNUM`, `WIN` or `WINDOW`, and bare TCP flags `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR` (never `SPORT`, `DPORT`, `ACK_NUM`, `ACK <n>`, or `FLAGS [...]`).
   - Always use `TTL` for both IPv4 Time-To-Live and IPv6 Hop Limit (never `HOP_LIMIT`), `QINQ <outer> INNER_VLAN <inner>` (never `QINQ <a> <b>`), `HOST_HDR` for HTTP Host headers (never `HTTP ... HOST`), and `REQID` (never `REQ_ID`).
3. **Dual-Stack Endpoint Homogeneity**:
   - A `FLOW` is polymorphic across IPv4 and IPv6, but both endpoints in any single statement (`a -> b` or `a <- b`) must belong to the same IP family (both IPv4 or both IPv6).
4. **Pre-Training Corpus Headers (`examples/**/*.fasm`, `2,611` Files)**:
   - Line 1: `// PROMPT: <natural language description>`
   - Line 2: `// TOKENS: <comma-separated uppercase lexer tokens>`
   - Preceding every `HOST`, `FLOW`, and `COMPILE` block: `// INSTRUCTION: <explanation>`
   - Metrics: `words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50,000` bytes (`< 50 KB` applies to AI-critical `src/**/*.rs`, `tests/*.rs`, and `examples/**/*.fasm` files; human-facing `README.md` and `docs/*.md` have no `< 50 KB` cap and must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` lines, except `docs/for_nerds.md`).

---

## 3. Repository Architecture & Documentation Map

- **Compiler Pipeline (`src/`)**:
  - [`src/lexer/mod.rs`](src/lexer/mod.rs) — Zero-copy `logos 0.14` tokenizer (`Token<'a>`).
  - [`src/ast/`](src/ast/mod.rs) — Layer-organized AST specifications (`l2/`, `l3/`, `l4/`, `l7/`).
  - [`src/parser/`](src/parser/mod.rs) — `winnow 1.0` combinator parser (`parse_program`) and 2-arg semantic validator (`validate_semantics(&program, &source)`).
  - [`src/builders/`](src/builders/mod.rs) — Wire-level protocol encoders (`l2/`, `l3/`, `l4/`, `l7/`, including RFC 3414/3826/7860 `l7/snmp/`).
  - [`src/backend/mod.rs`](src/backend/mod.rs), [`src/packet.rs`](src/packet.rs), [`src/pcap.rs`](src/pcap.rs) — Stateful 4-tuple TCP sequence progression, Ethernet/IPv4/IPv6 encapsulation, and nanosecond PCAPNG writer.
  - [`src/reverse/`](src/reverse/mod.rs) — Five-stage PCAP/PCAPNG-to-`.fasm` decompiler (`reverse_pcap_reader`, `reverse_pcap_bytes`, `reverse_pcap_file`) organized into `l2/`, `l3/` (including `src/reverse/l3/{ip,ipv6,icmpv6}.rs` alongside the 20 L3 protocol dissectors), `l4/`, and `l7/<protocol>.rs` (including `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors) plus `container.rs`, `topology.rs`, `oracle.rs`, and `shadow_emit.rs`.
- **Canonical Documentation (`docs/*.md` — 13 guides)**:
  - [`docs/getting_started.md`](docs/getting_started.md), [`docs/use_cases.md`](docs/use_cases.md), [`docs/l2_protocols.md`](docs/l2_protocols.md), [`docs/l3_protocols.md`](docs/l3_protocols.md), [`docs/l4_transports.md`](docs/l4_transports.md), [`docs/l7_snmp.md`](docs/l7_snmp.md), [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md), [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md), [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md), [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md), [`docs/topologies_and_dual_stack.md`](docs/topologies_and_dual_stack.md), [`docs/fasm-specification.md`](docs/fasm-specification.md), [`docs/for_nerds.md`](docs/for_nerds.md).
- **Constrained Decoding Grammars, `.fasm` Registration Artifacts & AI Context Bundles**:
  - [`grammar.ebnf`](grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](frameassembly.gbnf) (`llama.cpp` & `XGrammar` GBNF), [`frameassembly.lark`](frameassembly.lark) (`llguidance` & `Outlines` Lark).
  - [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md), [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml), [`contrib/linguist/languages.yml`](contrib/linguist/languages.yml), [`contrib/linguist/heuristics.yml`](contrib/linguist/heuristics.yml), [`.gitattributes`](.gitattributes).
  - [`AGENTS.md`](AGENTS.md), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), [`context7.json`](context7.json), [`CITATION.cff`](CITATION.cff), [`codemeta.json`](codemeta.json).
- **Brand, 3-Surface Audience Architecture, `.fasm` Disambiguation & Companion Positioning Rules**:
  - **Audience Architecture & Calling `.fasm` Code (Zero Developer Jargon & Zero Prompt Leaking)**: (1) `llms.txt` is optimized for search engines of AIs and `llms-full.txt` is optimized for pre-training and prompting of AIs; (2) `docs/*.md` are optimized for users proficient in networking and cybersecurity with little to no programming knowledge or experience; (3) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are optimized for their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, and avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring/cybersecurity solutions), and advantages over other solutions. FrameAssembly is not a tool for software developers: never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md` or `docs/*.md` (except `docs/for_nerds.md`), and never leak or quote informal prompt phrasing into documentation. Always call `.fasm` **code** (`Packets as Code`), never `"plain text"`.
  - Always write `FrameAssembly` as one unspaced CamelCase word (`frameassembly` for crate/CLI/URLs/identifiers); never split `Frame` and `Assembly` into two words or claim zero external crate dependencies (use `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`).
  - Disambiguate FrameAssembly `.fasm` (`text/vnd.frameassembly`) network packet definitions from x86 Flat Assembler and SymbiFlow/F4PGA FPGA FASM files; position FrameAssembly as the upstream companion compiler to `tcpreplay`, `Wireshark`, `tshark`, `Suricata`, and `Zeek` (compare only against `Scapy`, `text2pcap`, and `Ostinato`), and keep `README.md`, `src/lib.rs`, `docs/fasm-specification.md`, `llms.txt`, and `contrib/mime/text-vnd.frameassembly.xml` synchronized whenever lexer tokens or supported protocols change.

---

## 4. Workspace Rules (`.agents/rules/*.md`) & Domain Skills (`.agents/skills/*/SKILL.md`)

### 4.1 All 15 Workspace Rules (`4` `always_on` + `11` `glob`-Scoped)
- **Always-On Rules (`trigger: always_on`)**:
  1. [`.agents/rules/frameassembly-dsl.md`](.agents/rules/frameassembly-dsl.md) — Core `.fasm` language syntax, 6-stage forward compiler + reverse PCAP decompiler invariants, 81-protocol rules, and anti-hallucination guardrails.
  2. [`.agents/rules/versioning_and_git.md`](.agents/rules/versioning_and_git.md) — Enforces 4-way ecosystem version synchronization on explicit request and prohibits unrequested version bumps or `git commit`/`push`/`tag`.
  3. [`.agents/rules/temporary_files.md`](.agents/rules/temporary_files.md) — Workspace `temp/` directory and thread-safe RAII cleanup guards for scratch packet captures.
  4. [`.agents/rules/token-and-context-efficiency.md`](.agents/rules/token-and-context-efficiency.md) — 20k-token rules budget discipline, 3-layer parallel multi-agent file locking (`.agents/scripts/file_lock.sh` + `.agents/hooks.json`), subagent context isolation, and `/compact` checkpoint persistence.
- **Glob-Scoped Domain Rules (`trigger: glob`)**:
  5. [`.agents/rules/rust-2024-best-practices.md`](.agents/rules/rust-2024-best-practices.md) — Rust 2024 Edition and `rustc 1.85–1.99.1` standards, `< 50 KB` module ceiling, and error handling (`Cargo.toml`, `src/**/*.rs`, `tests/**/*.rs`, `frameassembly-wasm/**/*.rs`).
  6. [`.agents/rules/publishing_and_docs.md`](.agents/rules/publishing_and_docs.md) — Zero NUL bytes, Rustdoc/`docs.rs` lint gates, Cargo `build.warnings` (Rust 1.97+), `//!` module docstrings, and Crates.io packaging.
  7. [`.agents/rules/ai-seo-best-practices.md`](.agents/rules/ai-seo-best-practices.md) — Pre-training dataset filters, 4-stage RLVR compiler & PCAP-to-`.fasm` decompilation rewards, 6-way grammar/IDE/WASM lockstep, and SEO.
  8. [`.agents/rules/clap-best-practices.md`](.agents/rules/clap-best-practices.md) — `clap 4.6.7+`, `anstyle 1.0.14`, and `anstream 1.0.0` Derive CLI design and `show`/`reverse` subcommands (`src/main.rs`).
  9. [`.agents/rules/logos-miette-best-practices.md`](.agents/rules/logos-miette-best-practices.md) — `logos 0.14.4` / `0.16.1` lexing, 6-tier priority ladder, and `miette 7.6.0` diagnostics (`src/lexer/`, `src/error.rs`).
  10. [`.agents/rules/networking-pcap-best-practices.md`](.agents/rules/networking-pcap-best-practices.md) — L2–L7 RFC wire framing, checksums, 4-tuple state constants, and `pcap-file 2.0.0` PCAPNG output.
  11. [`.agents/rules/pcap-decompilation-best-practices.md`](.agents/rules/pcap-decompilation-best-practices.md) — 5-stage PCAP/PCAPNG-to-`.fasm` decompilation pipeline, `etherparse 0.21.0` `link_exts` zero-copy slicing, container normalization, fuzz safety, and self-checking compiler oracle (`src/reverse/**`).
  12. [`.agents/rules/rasn-snmp-best-practices.md`](.agents/rules/rasn-snmp-best-practices.md) — `rasn`, `rasn-smi`, and `rasn-snmp 0.28.15` ASN.1 BER/DER encoding & decompilation, and SNMPv1/v2c/v3 / LDAP / Kerberos PDUs.
  13. [`.agents/rules/rustcrypto-best-practices.md`](.agents/rules/rustcrypto-best-practices.md) — RustCrypto SNMPv3 USM RFC 3414/3826/7860 authentication and privacy (`src/builders/l7/snmp/crypto.rs`).
  14. [`.agents/rules/wasm-vscode-best-practices.md`](.agents/rules/wasm-vscode-best-practices.md) — WebAssembly (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`), UTF-16 IDE span mapping, VS Code extension (`@vscode/vsce 4.1.0`), and OIDC Trusted Publishing (`frameassembly-wasm/**`, `frameassembly-vscode/**`).
  15. [`.agents/rules/winnow-best-practices.md`](.agents/rules/winnow-best-practices.md) — `winnow 1.0.5+` and `memchr 2.8.3` `Stream<'i, 'a>` combinator parsers (`src/parser/`).

### 4.2 All 11 Specialized Skills
1. **`frameassembly`**: [`.agents/skills/frameassembly/SKILL.md`](.agents/skills/frameassembly/SKILL.md) — DSL syntax, AST `*Spec` design, parser dispatch, backend state tracking, and forward/reverse pipeline stages.
2. **`networking-pcap`**: [`.agents/skills/networking-pcap/SKILL.md`](.agents/skills/networking-pcap/SKILL.md) — L2–L7 wire builders, RFC checksum engines, and `pcap-file 2.0.0` PCAPNG serialization.
3. **`pcap-decompilation`**: [`.agents/skills/pcap-decompilation/SKILL.md`](.agents/skills/pcap-decompilation/SKILL.md) — 5-stage PCAP/PCAPNG-to-`.fasm` decompilation, `etherparse 0.21.0` slicing, container linktype normalization, and self-checking compiler oracle.
4. **`winnow-parser`**: [`.agents/skills/winnow-parser/SKILL.md`](.agents/skills/winnow-parser/SKILL.md) — Two-phase `logos` + `winnow 1.0.5+` / `memchr 2.8.3` token-slice parsing and `StrContext` diagnostics.
5. **`logos-miette-diagnostics`**: [`.agents/skills/logos-miette-diagnostics/SKILL.md`](.agents/skills/logos-miette-diagnostics/SKILL.md) — Zero-copy `logos 0.14.4` / `0.16.1` tokenizers and `miette 7.6.0` error reporting.
6. **`rasn-snmp-codec`**: [`.agents/skills/rasn-snmp-codec/SKILL.md`](.agents/skills/rasn-snmp-codec/SKILL.md) — `rasn 0.28.15` ASN.1 BER/DER encoding, decoding, and SMIv1/SMIv2/SNMP wire builders.
7. **`rustcrypto-engineering`**: [`.agents/skills/rustcrypto-engineering/SKILL.md`](.agents/skills/rustcrypto-engineering/SKILL.md) — SNMPv3 USM RFC 3414/3826/7860 cryptography with RustCrypto.
8. **`clap-cli`**: [`.agents/skills/clap-cli/SKILL.md`](.agents/skills/clap-cli/SKILL.md) — Modern `clap 4.6.7+`, `anstyle 1.0.14`, and `anstream 1.0.0` CLI engineering.
9. **`rust-modern-qa`**: [`.agents/skills/rust-modern-qa/SKILL.md`](.agents/skills/rust-modern-qa/SKILL.md) — Multi-tier testing, 6-gate corpus & AST-to-builder verification, `proptest`, `cargo-mutants`, `tshark` gates, and `.agents/scripts/file_lock.sh`.
10. **`ai-seo-training-data`**: [`.agents/skills/ai-seo-training-data/SKILL.md`](.agents/skills/ai-seo-training-data/SKILL.md) — LLM pre-training filters, 4-stage RLVR compiler/decompiler rewards, 6-way grammar/IDE/WASM lockstep, and `docs.rs` SEO.
11. **`wasm-vscode`**: [`.agents/skills/wasm-vscode/SKILL.md`](.agents/skills/wasm-vscode/SKILL.md) — WebAssembly (`wasm-bindgen 0.2.130`), UTF-16 IDE diagnostics, VS Code extension (`@vscode/vsce 4.1.0`), and OIDC Trusted Publishing.
