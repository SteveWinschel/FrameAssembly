# CLAUDE.md — FrameAssembly Project Instructions for Claude Code & AI Agents

**FrameAssembly** (`frameassembly` v3.2.0, official website & interactive browser playground: [`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/), documentation: [`https://frameassembly-lang.dev/docs`](https://frameassembly-lang.dev/docs), use cases & examples: [`https://frameassembly-lang.dev/use-cases`](https://frameassembly-lang.dev/use-cases), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.frasm` network packet specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.frasm` code—across **81 native Layer 2 through Layer 7 protocols**.

---

## 1. Essential Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (prebuilt release binary fast-path or curl + C linker + rustup >= 1.89 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
# Windows (PowerShell, no Administrator rights): irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and documentation verification tests
cargo test

# Compile a single .frasm specification to a .pcap file (default root command; optional 2nd positional path defaults to <input_stem>.pcap)
cargo run -- demo.frasm output.pcap

# Show the terminal packet ladder for a .frasm file without writing a .pcap file
cargo run -- show demo.frasm

# Decompile a .pcap / .pcapng capture into canonical .frasm code (optional 2nd positional path defaults to <input_stem>.frasm)
cargo run -- reverse output.pcap reversed.frasm

# Self-update the CLI via Cargo/rustup or verified GitHub Release assets
cargo run -- update

# Display CLI usage or active compiler version (default root compile + 5 subcommands: show, reverse, update, help, version — no -o/--output flags)
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
4. **Training-Data Headers (contributed `.frasm` samples)**:
   - Line 1: `// PROMPT: <natural language description>`
   - Line 2: `// TOKENS: <comma-separated strict-lowercase v3.0.0 lexer tokens>`
   - Preceding every `host`, `flow`, and `compile` block: `// INSTRUCTION: <explanation>`
   - Metrics: `words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50,000` bytes (`< 50 KB` applies to AI-critical `src/**/*.rs` and `tests/*.rs` files; human-facing `README.md` has no `< 50 KB` cap and must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` lines).

---

## 3. Repository Architecture & Documentation Map

- **Compiler Pipeline (`src/`)**:
  - [`src/lexer/mod.rs`](src/lexer/mod.rs) — Zero-copy `logos 0.14.4` strict-lowercase `[a-z0-9]+` tokenizer (`Token<'a>`, no `ignore(ascii_case)`, no `Token::Loop`).
  - [`src/ast/`](src/ast/mod.rs) — Layer-organized AST specifications (`l2/`, `l3/`, `l4/`, `l7/`, `RunStatement::{Invocation, Frame}`).
  - [`src/parser/`](src/parser/mod.rs) — `winnow 1.0.5` combinator parser (`parse_program`), protocol-first `whois` disambiguation, self-healing `replace '<raw>' with '<kw>'` diagnostics, and 2-arg semantic validator (`validate_semantics(&program, &source)`).
  - [`src/builders/`](src/builders/mod.rs) — Wire-level protocol encoders (`l2/`, `l3/`, `l4/`, `l7/`, including RFC 3414/3826/7860 `l7/snmp/`).
  - [`src/main.rs`](src/main.rs), [`src/update.rs`](src/update.rs) — CLI router (default root compile + 5 subcommands `show`, `reverse`, `update`, `help`, `version`; `src/update.rs` is a binary-private self-updater).
  - [`src/backend/mod.rs`](src/backend/mod.rs), [`src/packet.rs`](src/packet.rs), [`src/pcap.rs`](src/pcap.rs) — Stateful 4-tuple TCP sequence progression, Ethernet/IPv4/IPv6 encapsulation, and nanosecond PCAPNG writer.
  - [`src/reverse/`](src/reverse/mod.rs) — Five-stage PCAP/PCAPNG-to-`.frasm` decompiler (`reverse_pcap_reader`, `reverse_pcap_bytes`, `reverse_pcap_file`) organized into `l2/`, `l3/` (including `src/reverse/l3/{ip,ipv6,icmpv6}.rs` alongside the 20 L3 protocol dissectors), `l4/`, and `l7/<protocol>.rs` (including `src/reverse/l7/{snmp1,snmp2,snmp3}.rs` across all 50 L7 protocol dissectors) plus `container.rs`, `topology.rs`, `oracle.rs`, and `shadow_emit.rs` (emitting `host1`, `host2` without `_`, strict lowercase, and zero `loop`).
- **Official Documentation & Use Cases (website)**:
  - [Documentation](https://frameassembly-lang.dev/docs) — Getting started, per-layer protocol references, multi-host dual-stack topologies, the `.frasm` media type specification, and compiler internals.
  - [Use Cases & Examples](https://frameassembly-lang.dev/use-cases) — Ready-to-run `.frasm` scenarios across all 81 protocols and multi-host topologies.
- **Constrained Decoding Grammars, Shell Completions, `.frasm` Registration Artifacts & AI Context Bundles**:
  - [`grammar.ebnf`](grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](frameassembly.gbnf) (`llama.cpp` & `XGrammar` GBNF), [`frameassembly.lark`](frameassembly.lark) (`llguidance` & `Outlines` Lark).
  - [`contrib/completions/`](contrib/completions/README.md), [`contrib/packaging/`](contrib/packaging/README.md), [`contrib/iana/text-vnd.frameassembly.md`](contrib/iana/text-vnd.frameassembly.md), [`contrib/mime/text-vnd.frameassembly.xml`](contrib/mime/text-vnd.frameassembly.xml), [`contrib/linguist/languages.yml`](contrib/linguist/languages.yml), [`contrib/linguist/heuristics.yml`](contrib/linguist/heuristics.yml), [`.gitattributes`](.gitattributes).
  - [`AGENTS.md`](AGENTS.md), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), [`context7.json`](context7.json), [`CITATION.cff`](CITATION.cff), [`codemeta.json`](codemeta.json).
- **Brand, Audience Architecture, Supported Release Channels, Confidentiality & Companion Positioning Rules**:
  - **Audience Architecture & Calling `.frasm` Code (Zero Developer Jargon & Zero Prompt Leaking)**: (1) `llms.txt` (`< 512` lines, `< 25 KB`) is for search engines and AIs with web search, and `llms-full.txt` (`60–250 KB`) is a dedicated context file for purposeful injection inside prompts (never dumping `AGENTS.md` contributor rules, human docs banter, or raw Rust `src/ast/` code); (2) the official documentation (https://frameassembly-lang.dev/docs) is written for networking and cybersecurity professionals in a natural, direct human voice with practical tool examples (`Checkmk`, `Zabbix`, `Wireshark`, `Suricata`, `tcpreplay`); (3) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are tailored to their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, and avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring/cybersecurity solutions), and advantages over other solutions. Never spam filler AI adjectives (`"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`), never parrot repetitive slogans across paragraphs, never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md` or user-facing documentation (except compiler-internals material), and never leak or quote informal prompt phrasing into documentation. Always call `.frasm` **code** (`Packets as Code`), never `"plain text"`.
  - Always write `FrameAssembly` as one unspaced CamelCase word (`frameassembly` for crate/CLI/URLs/identifiers); never split `Frame` and `Assembly` into two words or claim zero external crate dependencies (use `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`).
  - Disambiguate FrameAssembly `.frasm` (`text/vnd.frameassembly`) network packet definitions from x86 Flat Assembler and SymbiFlow/F4PGA FPGA FASM files; position FrameAssembly as the upstream companion compiler to `tcpreplay`, `Wireshark`, `tshark`, `Suricata`, and `Zeek` (compare only against `Scapy`, `text2pcap`, and `Ostinato`), and keep `frameassembly-wasm`, `frameassembly-vscode`, `README.md`, `src/lib.rs`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml` synchronized whenever lexer tokens or supported protocols change.
  - **User-Facing CLI Channels & Internal WASM Engine**: User-facing CLI channels are Crates.io (`cargo install frameassembly`, primary recommended, Rust `1.89+`) and GitHub Releases (pre-built OS archives + Debian/Ubuntu `.deb`), alongside VS Code Marketplace (`frameassembly-vscode`). `frameassembly-wasm` is internal for `frameassembly-lang.dev` and `frameassembly-vscode`—never advertise `npm install frameassembly-wasm`, `Homebrew`, or `Scoop` in root `README.md`, and never add third-party registry workflows beyond `.github/workflows/release.yml`. `.agents/` is local-only (gitignored) and must never be linked in tracked docs or CI tests.
  - **Private User Context Confidentiality**: Never include private background context shared by the user in prompts (such as employer names or employment/apprenticeship status) anywhere in code, comments, examples, documentation, or metadata.
  - Never bump `version` in manifests or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.
