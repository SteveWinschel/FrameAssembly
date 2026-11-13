# CLAUDE.md — FrameAssembly Project Instructions for Claude Code & AI Agents

**FrameAssembly** (`frameassembly` v3.0.0, official website & interactive browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.frasm` network packet specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.frasm` code—across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.frasm` corpus scenarios).

---

## 1. Essential Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (prebuilt release binary fast-path or curl + C linker + rustup >= 1.85 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
# Windows (PowerShell, no Administrator rights): irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and corpus verification tests
cargo test

# Run the corpus verification suite (validates all 2,611 examples/**/*.frasm headers, AST parsing & PCAP output)
cargo test --test corpus_verification_tests

# Compile a single .frasm specification to a .pcap file (default root command; optional 2nd positional path defaults to <input_stem>.pcap)
cargo run -- demo.frasm output.pcap

# Show the terminal packet ladder for a .frasm file without writing a .pcap file
cargo run -- show demo.frasm

# Decompile a .pcap / .pcapng capture into canonical .frasm code (optional 2nd positional path defaults to <input_stem>.frasm)
cargo run -- reverse output.pcap reversed.frasm

# Display CLI usage or active compiler version (default root compile + 4 subcommands: show, reverse, help, version — no -o/--output flags)
cargo run -- help
cargo run -- version
```

---

## 2. Canonical `.frasm` v3.0.0 Language Rules (Zero Hallucinations)

1. **Three-Block Program Structure, Strict-Lowercase Keywords & Flexible Identifiers**:
   - **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`)**: Every built-in keyword, protocol, modifier, and time suffix (`ns`, `us`, `ms`, `s`, `m`) is **strictly lowercase alphanumeric with zero `_` and zero `-`** (no `ignore(ascii_case)`: `host`, `ip`, `mac`, `flow`, `compile`, `tcp`, `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`), backed by self-healing compiler diagnostics (`replace '<raw>' with '<kw>'`).
   - **Flexible User Identifiers**: User-defined `host`, `flow`, and parameter names match `[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*` (allowing uppercase, `_`, and internal `-` like `fw-dmz-01` or `core_sw`). Reverse PCAP decompilation (`frameassembly reverse`) emits `host1`, `host2` without `_`, strict-lowercase `[a-z0-9]+` tokens, and direct flow calls in `compile` with zero `loop` blocks.
   - `host <id> { [ip <ipv4_or_ipv6>] [mac <mac>] }` (at least one of `ip` or `mac` required; MAC-only valid for the 8 L2 protocols `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`; `mac` accepts colon `00:1a:2b:3c:4d:5e`, hyphen `00-1A-2B-3C-4D-5E`, or Cisco dotted-quad `001a.2b3c.4d5e`; never use `ipv4`, `ipv6`, `=`, colons, commas, or `mask`).
   - `flow <id>(<param1>, <param2>, ...) { <src> -> <dst> <protocol> [modifiers...] [wait <int><ns|us|ms|s|m>] }` (never declare parameterless `flow <id> { ... }` or use `from`, `to`, `reverse`, `send`, standalone `wait` lines, or `+5ms` / `[+delay]` prefixes).
   - `compile { <flow_id>(<host1>, <host2>, ...) | <src> -> <dst> <protocol> ... }` (`loop` was removed in v2.0.0; `compile` supports flow invocations and inline frame statements, and every compilable `.frasm` program or Markdown ````frameassembly` code block must include `host`, `flow`, and `compile { ... }`).
2. **Exact Strict-Lowercase Modifier Keywords**:
   - Always use `srcport`, `dstport`, `seq`, `acknum`, `win` or `window`, `sackperm`, and bare TCP flags `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr` (never `sport`, `dport`, `ack_num`, `ack <n>`, `sack_perm`, or `flags [...]`).
   - Always use `ttl` for both IPv4 Time-To-Live and IPv6 Hop Limit (never `hop_limit` or `hoplimit`), `qinq <outer> innervlan <inner>` (never `qinq <a> <b>` or `inner_vlan`), `hosthdr` for HTTP/SSDP Host headers (never `http ... host` or `host_hdr`), `transporthdr` for RTSP Transport headers (never `rtsp ... transport` or `transport_hdr`), and `reqid` (never `req_id`).
3. **Dual-Stack Endpoint Homogeneity**:
   - A `flow` is polymorphic across IPv4 and IPv6, but both endpoints in any single statement (`a -> b` or `a <- b`) must belong to the same IP family (both IPv4 or both IPv6).
4. **Pre-Training Corpus Headers (`examples/**/*.frasm`, `2,611` Files)**:
   - Line 1: `// PROMPT: <natural language description>`
   - Line 2: `// TOKENS: <comma-separated strict-lowercase v3.0.0 lexer tokens>`
   - Preceding every `host`, `flow`, and `compile` block: `// INSTRUCTION: <explanation>`
   - Metrics: `words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50,000` bytes (`< 50 KB` applies to AI-critical `src/**/*.rs`, `tests/*.rs`, and `examples/**/*.frasm` files; human-facing `README.md` and `docs/*.md` have no `< 50 KB` cap and must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` lines, except `docs/13_for_nerds.md`).

---

## 3. Repository Architecture & Documentation Map

- **Compiler Pipeline (`src/`)**:
  - [`src/lexer/mod.rs`](src/lexer/mod.rs) — Zero-copy `logos 0.14.4` strict-lowercase `[a-z0-9]+` tokenizer (`Token<'a>`, no `ignore(ascii_case)`, no `Token::Loop`).
  - [`src/ast/`](src/ast/mod.rs) — Layer-organized AST specifications (`l2/`, `l3/`, `l4/`, `l7/`, `RunStatement::{Invocation, Frame}`).
  - [`src/parser/`](src/parser/mod.rs) — `winnow 1.0.5` combinator parser (`parse_program`), protocol-first `whois` disambiguation, self-healing `replace '<raw>' with '<kw>'` diagnostics, and 2-arg semantic validator (`validate_semantics(&program, &source)`).
  - [`src/builders/`](src/builders/mod.rs) — Wire-level protocol encoders (`l2/`, `l3/`, `l4/`, `l7/`, including RFC 3414/3826/7860 `l7/snmp/`).
  - [`src/backend/mod.rs`](src/backend/mod.rs), [`src/packet.rs`](src/packet.rs), [`src/pcap.rs`](src/pcap.rs) — Stateful 4-tuple TCP sequence progression, Ethernet/IPv4/IPv6 encapsulation, and nanosecond PCAPNG writer.
  - [`src/reverse/`](src/reverse/mod.rs) — Five-stage PCAP/PCAPNG-to-`.frasm` decompiler (`reverse_pcap_reader`, `reverse_pcap_bytes`, `reverse_pcap_file`) organized into `l2/`, `l3/` (including `src/reverse/l3/{ip,ipv6,icmpv6}.rs` alongside the 20 L3 protocol dissectors), `l4/`, and `l7/<protocol>.rs` (including `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors) plus `container.rs`, `topology.rs`, `oracle.rs`, and `shadow_emit.rs` (emitting `host1`, `host2` without `_`, strict lowercase, and zero `loop`).
- **Canonical Documentation (`docs/*.md` — 13 guides)**:
  - [`docs/01_getting_started.md`](docs/01_getting_started.md), [`docs/02_use_cases.md`](docs/02_use_cases.md), [`docs/03_l2_protocols.md`](docs/03_l2_protocols.md), [`docs/04_l3_protocols.md`](docs/04_l3_protocols.md), [`docs/05_l4_transports.md`](docs/05_l4_transports.md), [`docs/06_l7_snmp.md`](docs/06_l7_snmp.md), [`docs/07_l7_infra_and_telemetry.md`](docs/07_l7_infra_and_telemetry.md), [`docs/08_l7_web_and_cloud.md`](docs/08_l7_web_and_cloud.md), [`docs/09_l7_mail_auth_storage_db.md`](docs/09_l7_mail_auth_storage_db.md), [`docs/10_l7_industrial_ot.md`](docs/10_l7_industrial_ot.md), [`docs/11_topologies_and_dual_stack.md`](docs/11_topologies_and_dual_stack.md), [`docs/12_frasm_specification.md`](docs/12_frasm_specification.md), [`docs/13_for_nerds.md`](docs/13_for_nerds.md).
- **Constrained Decoding Grammars, Shell Completions, `.frasm` Registration Artifacts & AI Context Bundles**:
  - [`grammar.ebnf`](grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](frameassembly.gbnf) (`llama.cpp` & `XGrammar` GBNF), [`frameassembly.lark`](frameassembly.lark) (`llguidance` & `Outlines` Lark).
  - [`contrib/completions/`](contrib/completions/README.md), [`contrib/packaging/`](contrib/packaging/README.md), [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md), [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml), [`contrib/linguist/languages.yml`](contrib/linguist/languages.yml), [`contrib/linguist/heuristics.yml`](contrib/linguist/heuristics.yml), [`.gitattributes`](.gitattributes).
  - [`AGENTS.md`](AGENTS.md), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), [`context7.json`](context7.json), [`CITATION.cff`](CITATION.cff), [`codemeta.json`](codemeta.json).
- **Brand, Audience Architecture, Supported Release Channels, Confidentiality & Companion Positioning Rules**:
  - **Audience Architecture & Calling `.frasm` Code (Zero Developer Jargon & Zero Prompt Leaking)**: (1) `llms.txt` (`< 512` lines, `< 25 KB`) is for search engines and AIs with web search, and `llms-full.txt` (`60–250 KB`) is a dedicated context file for purposeful injection inside prompts (never dumping `AGENTS.md` contributor rules, human docs banter, or raw Rust `src/ast/` code); (2) `docs/*.md` are written for networking and cybersecurity professionals in a natural, direct human voice with practical tool examples (`Checkmk`, `Zabbix`, `Wireshark`, `Suricata`, `tcpreplay`); (3) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are tailored to their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, and avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring/cybersecurity solutions), and advantages over other solutions. Never spam filler AI adjectives (`"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`), never parrot repetitive slogans across paragraphs, never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md` or `docs/*.md` (except `docs/13_for_nerds.md`), and never leak or quote informal prompt phrasing into documentation. Always call `.frasm` **code** (`Packets as Code`), never `"plain text"`.
  - Always write `FrameAssembly` as one unspaced CamelCase word (`frameassembly` for crate/CLI/URLs/identifiers); never split `Frame` and `Assembly` into two words or claim zero external crate dependencies (use `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`).
  - Disambiguate FrameAssembly `.frasm` (`text/vnd.frameassembly`) network packet definitions from x86 Flat Assembler and SymbiFlow/F4PGA FPGA FASM files; position FrameAssembly as the upstream companion compiler to `tcpreplay`, `Wireshark`, `tshark`, `Suricata`, and `Zeek` (compare only against `Scapy`, `text2pcap`, and `Ostinato`), and keep `frameassembly-wasm`, `frameassembly-vscode`, `README.md`, `src/lib.rs`, `docs/12_frasm_specification.md`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml` synchronized whenever lexer tokens or supported protocols change.
  - **Supported Release Channels Only**: GitHub Releases + Debian/Ubuntu `.deb`, Crates.io (`frameassembly`), NPM (`frameassembly-wasm`), VS Code Marketplace (`frameassembly-vscode`), and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`)—do not reference or add workflows for any other third-party package or extension registries.
  - **Private User Context Confidentiality**: Never include private background context shared by the user in prompts (such as employer names or employment/apprenticeship status) anywhere in code, comments, examples, documentation, or metadata.
  - Never bump `version` in manifests or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.

---

## 4. Workspace Rules (`.agents/rules/*.md`) & Domain Skills (`.agents/skills/*/SKILL.md`)

### 4.1 All 15 Workspace Rules (`4` `always_on` + `11` `glob`-Scoped)
- **Always-On Rules (`trigger: always_on`)**:
  1. [`.agents/rules/frameassembly-dsl.md`](.agents/rules/frameassembly-dsl.md) — Core v3.0.0 strict-lowercase `.frasm` language syntax, 6-stage forward compiler + reverse PCAP decompiler invariants, 81-protocol rules, confidentiality, and anti-hallucination guardrails.
  2. [`.agents/rules/versioning_and_git.md`](.agents/rules/versioning_and_git.md) — Enforces 4-way ecosystem version synchronization across supported release channels on explicit request and prohibits unrequested version bumps or `git commit`/`push`/`tag`.
  3. [`.agents/rules/temporary_files.md`](.agents/rules/temporary_files.md) — Workspace `temp/` directory and thread-safe RAII cleanup guards for scratch packet captures.
  4. [`.agents/rules/token-and-context-efficiency.md`](.agents/rules/token-and-context-efficiency.md) — 20k-token rules budget discipline, 3-layer parallel multi-agent file locking (`.agents/scripts/file_lock.sh` + `.agents/hooks.json`), subagent context isolation, `/compact` checkpoint persistence, and grounded clarification questions.
- **Glob-Scoped Domain Rules (`trigger: glob`)**:
  5. [`.agents/rules/rust-2024-best-practices.md`](.agents/rules/rust-2024-best-practices.md) — Rust 2024 Edition and `rustc 1.85–1.99.1` standards, `< 50 KB` module ceiling, and error handling (`Cargo.toml`, `src/**/*.rs`, `tests/**/*.rs`, `frameassembly-wasm/**/*.rs`).
  6. [`.agents/rules/publishing_and_docs.md`](.agents/rules/publishing_and_docs.md) — Zero NUL bytes, Rustdoc/`docs.rs` lint gates, Cargo `build.warnings` (Rust 1.97+), `//!` module docstrings, and Crates.io packaging.
  7. [`.agents/rules/ai-seo-best-practices.md`](.agents/rules/ai-seo-best-practices.md) — Pre-training dataset filters, 4-stage RLVR compiler & PCAP-to-`.frasm` decompilation rewards, 6-way grammar/IDE/WASM lockstep, and SEO.
  8. [`.agents/rules/clap-best-practices.md`](.agents/rules/clap-best-practices.md) — `clap 4.6.7+`, `anstyle 1.0.14`, and `anstream 1.0.0` v3.0.0 default-compile + 4-subcommand CLI (`<input.frasm> [output.pcap]`, `show`, `reverse`, `help`, `version`) and shell Tab completions (`src/main.rs`).
  9. [`.agents/rules/logos-miette-best-practices.md`](.agents/rules/logos-miette-best-practices.md) — `logos 0.14.4` / `0.16.1` strict-lowercase lexing (no `ignore(ascii_case)`), 6-tier priority ladder, self-healing keyword suggestions, and `miette 7.6.0` diagnostics (`src/lexer/`, `src/error.rs`).
  10. [`.agents/rules/networking-pcap-best-practices.md`](.agents/rules/networking-pcap-best-practices.md) — L2–L7 RFC wire framing, checksums, 4-tuple state constants, and `pcap-file 2.0.0` PCAPNG output.
  11. [`.agents/rules/pcap-decompilation-best-practices.md`](.agents/rules/pcap-decompilation-best-practices.md) — 5-stage PCAP/PCAPNG-to-`.frasm` decompilation pipeline (`host1`/`host2`, strict lowercase, zero `loop`), `etherparse 0.21.0` `link_exts` zero-copy slicing, container normalization, fuzz safety, and self-checking compiler oracle (`src/reverse/**`).
  12. [`.agents/rules/rasn-snmp-best-practices.md`](.agents/rules/rasn-snmp-best-practices.md) — `rasn`, `rasn-smi`, and `rasn-snmp 0.28.15` ASN.1 BER/DER encoding & decompilation, and SNMPv1/v2c/v3 / LDAP / Kerberos PDUs.
  13. [`.agents/rules/rustcrypto-best-practices.md`](.agents/rules/rustcrypto-best-practices.md) — RustCrypto SNMPv3 USM RFC 3414/3826/7860 authentication and privacy (`src/builders/l7/snmp/crypto.rs`).
  14. [`.agents/rules/wasm-vscode-best-practices.md`](.agents/rules/wasm-vscode-best-practices.md) — WebAssembly (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`), UTF-16 IDE span mapping + Quick Fixes, VS Code Packet Studio (`@vscode/vsce 4.1.0`), and OIDC Trusted Publishing (`frameassembly-wasm/**`, `frameassembly-vscode/**`).
  15. [`.agents/rules/winnow-best-practices.md`](.agents/rules/winnow-best-practices.md) — `winnow 1.0.5+` and `memchr 2.8.3` `Stream<'i, 'a>` combinator parsers (`src/parser/`).

### 4.2 All 11 Specialized Skills
1. **`frameassembly`**: [`.agents/skills/frameassembly/SKILL.md`](.agents/skills/frameassembly/SKILL.md) — v3.0.0 strict-lowercase DSL syntax, AST `*Spec` design, parser dispatch, backend state tracking, and forward/reverse pipeline stages.
2. **`networking-pcap`**: [`.agents/skills/networking-pcap/SKILL.md`](.agents/skills/networking-pcap/SKILL.md) — L2–L7 wire builders, RFC checksum engines, and `pcap-file 2.0.0` PCAPNG serialization.
3. **`pcap-decompilation`**: [`.agents/skills/pcap-decompilation/SKILL.md`](.agents/skills/pcap-decompilation/SKILL.md) — 5-stage PCAP/PCAPNG-to-`.frasm` decompilation, `etherparse 0.21.0` slicing, container linktype normalization, and self-checking compiler oracle.
4. **`winnow-parser`**: [`.agents/skills/winnow-parser/SKILL.md`](.agents/skills/winnow-parser/SKILL.md) — Two-phase `logos` + `winnow 1.0.5+` / `memchr 2.8.3` token-slice parsing and `StrContext` diagnostics.
5. **`logos-miette-diagnostics`**: [`.agents/skills/logos-miette-diagnostics/SKILL.md`](.agents/skills/logos-miette-diagnostics/SKILL.md) — Zero-copy `logos 0.14.4` / `0.16.1` strict-lowercase tokenizers, self-healing keyword diagnostics, and `miette 7.6.0` error reporting.
6. **`rasn-snmp-codec`**: [`.agents/skills/rasn-snmp-codec/SKILL.md`](.agents/skills/rasn-snmp-codec/SKILL.md) — `rasn 0.28.15` ASN.1 BER/DER encoding, decoding, and SMIv1/SMIv2/SNMP wire builders.
7. **`rustcrypto-engineering`**: [`.agents/skills/rustcrypto-engineering/SKILL.md`](.agents/skills/rustcrypto-engineering/SKILL.md) — SNMPv3 USM RFC 3414/3826/7860 cryptography with RustCrypto.
8. **`clap-cli`**: [`.agents/skills/clap-cli/SKILL.md`](.agents/skills/clap-cli/SKILL.md) — Modern `clap 4.6.7+`, `anstyle 1.0.14`, and `anstream 1.0.0` default-compile + 4-subcommand CLI engineering.
9. **`rust-modern-qa`**: [`.agents/skills/rust-modern-qa/SKILL.md`](.agents/skills/rust-modern-qa/SKILL.md) — Multi-tier testing, 6-gate corpus & AST-to-builder verification, `proptest`, `cargo-mutants`, `tshark` gates, and `.agents/scripts/file_lock.sh`.
10. **`ai-seo-training-data`**: [`.agents/skills/ai-seo-training-data/SKILL.md`](.agents/skills/ai-seo-training-data/SKILL.md) — LLM pre-training filters, 4-stage RLVR compiler/decompiler rewards, 6-way grammar/IDE/WASM lockstep, and `docs.rs` SEO.
11. **`wasm-vscode`**: [`.agents/skills/wasm-vscode/SKILL.md`](.agents/skills/wasm-vscode/SKILL.md) — WebAssembly (`wasm-bindgen 0.2.130`), UTF-16 IDE diagnostics + Quick Fixes, VS Code Packet Studio (`@vscode/vsce 4.1.0`), and OIDC Trusted Publishing.
