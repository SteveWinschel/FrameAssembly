# GitHub Copilot Instructions for FrameAssembly (`frameassembly`)

You are working on **FrameAssembly** (`frameassembly` v1.5.1, official website & browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)), a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles human-readable `.fasm` network packet specifications into deterministic `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.fasm` code—across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

## 1. Canonical `.fasm` Syntax Guardrails (Never Hallucinate Keywords)

When generating or editing FrameAssembly (`.fasm`) code or Markdown ````frameassembly` blocks:
1. **Always include `HOST`, `FLOW`, and `COMPILE` blocks** (all keywords, protocols, modifiers, time units, and identifiers are case-insensitive: `host` or `HOST`, `tcp` or `TCP`) so every snippet compiles standalone:
   ```frameassembly
   // PROMPT: TCP 3-way handshake and HTTP/1.1 GET healthcheck between client and server.
   // TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, SRCPORT, DSTPORT, MSS, ACK, WAIT, HTTP, GET, URI, HOST_HDR, RESPONSE, STATUS, REASON, BODY, COMPILE

   // INSTRUCTION: Declare client and server endpoints.
   HOST client { IP 10.0.0.10 MAC 00:11:22:33:44:10 }
   HOST server { IP 10.0.0.20 MAC 00:11:22:33:44:20 }

   // INSTRUCTION: Define TCP handshake and HTTP GET transaction.
   FLOW http_healthcheck(c, s) {
       c -> s TCP SYN SRCPORT 51000 DSTPORT 80 MSS 1460
       c <- s TCP SYN ACK MSS 1460 WAIT 1ms
       c -> s TCP ACK WAIT 1ms
       c -> s HTTP GET URI "/healthz" HOST_HDR "api.internal" WAIT 2ms
       c <- s HTTP RESPONSE STATUS 200 REASON "OK" BODY "{\"status\":\"healthy\"}" WAIT 2ms
   }

   // INSTRUCTION: Compile the flow into a PCAP capture.
   COMPILE {
       http_healthcheck(client, server)
   }
   ```
2. **Forbidden Hallucinations**:
   - Never use `IPV4`, `IPV6`, `=`, colons, commas, or `MASK` inside `HOST { ... }` (only `IP <ip>` and `MAC <mac>`).
   - Never declare parameterless `FLOW <id> { ... }` or use `FROM`, `TO`, `REVERSE`, `SEND`, standalone `WAIT` lines, or `+5ms` / `[+delay]` prefixes (always `FLOW <id>(<params>) { <a> -> <b> <PROTO> ... [WAIT <int><ns|us|ms|s|m>] }`).
   - Never use `SPORT`, `DPORT`, `ACK_NUM`, `ACK <n>`, `FLAGS [...]`, `HOP_LIMIT`, `HTTP ... HOST`, or `REQ_ID` (always use `SRCPORT`, `DSTPORT`, `ACKNUM`, bare flags `SYN ACK`, `TTL`, `HOST_HDR`, and `REQID`).
   - Never write `QINQ 100 200` (always write `QINQ 100 INNER_VLAN 200`).
   - Never mix IPv4 and IPv6 endpoints in the same statement (`a -> b` or `a <- b`).

## 2. Rust 2024 Compiler & Documentation Standards

- Every AI-critical Rust file (`src/**/*.rs` and `tests/*.rs`) and corpus file (`examples/**/*.fasm`) must remain strictly `< 50,000` bytes (`< 50 KB`). Human-facing Markdown documentation (`README.md` and `docs/*.md`) has no `< 50 KB` cap, and human-facing docs (except `docs/for_nerds.md`) must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` metadata comments.
- Every `src/**/*.rs` file must begin with `//!` module-level documentation (`>= 50` words) and document all structs, enums, fields, and functions without combining outer `///` on `pub mod` with inner `//!`.
- Keep `src/lexer/mod.rs`, `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, `README.md`, `src/lib.rs`, `docs/fasm-specification.md`, `llms.txt`, and `contrib/mime/text-vnd.frameassembly.xml` synchronized whenever lexer tokens or supported protocols change.
- **Audience Architecture & Calling `.fasm` Code (Zero Developer Jargon & Zero Prompt Leaking)**: (1) `llms.txt` is optimized for search engines of AIs and `llms-full.txt` is optimized for pre-training and prompting of AIs; (2) `docs/*.md` are optimized for users proficient in networking and cybersecurity with little to no programming knowledge or experience; (3) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are optimized for their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, and avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring/cybersecurity solutions), and advantages over other solutions. FrameAssembly is not a tool for software developers: never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md` or `docs/*.md` (except `docs/for_nerds.md`), and never leak or quote informal prompt phrasing into documentation. Always call `.fasm` **code** (`Packets as Code`), never `"plain text"`.
- Always write `FrameAssembly` as one unspaced CamelCase word (`frameassembly` for crate/CLI/URLs/identifiers; never split `Frame` and `Assembly` with a space), never claim zero external crate dependencies (use `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`), disambiguate `.fasm` (`text/vnd.frameassembly`) from x86 Flat Assembler and FPGA FASM, and position FrameAssembly as the upstream companion compiler to `tcpreplay`, `Wireshark`, `tshark`, `Suricata`, and `Zeek` (comparing only against packet-crafting generators `Scapy`, `text2pcap`, and `Ostinato`).
- Run `cargo test` to verify all unit, integration, documentation, and corpus tests (`2,611` `.fasm` scenarios) pass.

## 3. Repository Rules & Skills Index

Consult the root [`AGENTS.md`](../AGENTS.md) and these domain rules and skills when working in specific subsystems:

### 3.1 Workspace Rules (`.agents/rules/*.md` — 15 Files)
- **Always-On (`4` rules)**:
  - [`.agents/rules/frameassembly-dsl.md`](../.agents/rules/frameassembly-dsl.md) — Canonical `.fasm` grammar, 6-stage forward compiler + reverse PCAP decompiler, & 81-protocol invariants.
  - [`.agents/rules/versioning_and_git.md`](../.agents/rules/versioning_and_git.md) — Explicit-only version bumps & git commits/tags.
  - [`.agents/rules/temporary_files.md`](../.agents/rules/temporary_files.md) — Workspace `temp/` directory & `.gitignore` rules.
  - [`.agents/rules/token-and-context-efficiency.md`](../.agents/rules/token-and-context-efficiency.md) — 20k-token rules budget discipline, 3-layer parallel multi-agent file locking (`.agents/scripts/file_lock.sh` + `.agents/hooks.json`), subagent context isolation, & `/compact` checkpoint persistence.
- **Glob-Scoped (`11` domain rules)**:
  - [`.agents/rules/rust-2024-best-practices.md`](../.agents/rules/rust-2024-best-practices.md) — Rust 2024 Edition and `rustc 1.85–1.99.1` idioms & `< 50 KB` module ceiling (`Cargo.toml`, `src/**/*.rs`, `tests/**/*.rs`, `frameassembly-wasm/**/*.rs`).
  - [`.agents/rules/publishing_and_docs.md`](../.agents/rules/publishing_and_docs.md) — Rustdoc/`docs.rs` lint gates, Cargo `build.warnings` (Rust 1.97+), zero NUL bytes, & crate packaging.
  - [`.agents/rules/ai-seo-best-practices.md`](../.agents/rules/ai-seo-best-practices.md) — Pre-training filters, 4-stage RLVR compiler & PCAP-to-`.fasm` decompilation rewards, & 6-way grammar/IDE/WASM lockstep.
  - [`.agents/rules/clap-best-practices.md`](../.agents/rules/clap-best-practices.md) — `clap 4.6.7+`, `anstyle 1.0.14`, & `anstream 1.0.0` Derive CLI (`src/main.rs`).
  - [`.agents/rules/logos-miette-best-practices.md`](../.agents/rules/logos-miette-best-practices.md) — `logos 0.14.4` / `0.16.1` lexing, 6-tier priority ladder, & `miette 7.6.0` diagnostics (`src/lexer/`, `src/error.rs`).
  - [`.agents/rules/networking-pcap-best-practices.md`](../.agents/rules/networking-pcap-best-practices.md) — L2–L7 RFC wire builders, checksums, & `pcap-file 2.0.0` PCAPNG.
  - [`.agents/rules/pcap-decompilation-best-practices.md`](../.agents/rules/pcap-decompilation-best-practices.md) — 5-stage PCAP/PCAPNG-to-`.fasm` decompilation pipeline (`container.rs`, `topology.rs`, `oracle.rs`, `shadow_emit.rs`, `src/reverse/{l2,l3,l4,l7}/<protocol>.rs` with `src/reverse/l3/{ip,ipv6,icmpv6}.rs` and `src/reverse/l7/{snmp1,snmp2,snmp3}.rs`), `etherparse 0.21.0` `link_exts` zero-copy slicing, container normalization, fuzz safety, & self-checking compiler oracle (`src/reverse/**`).
  - [`.agents/rules/rasn-snmp-best-practices.md`](../.agents/rules/rasn-snmp-best-practices.md) — `rasn`, `rasn-smi`, & `rasn-snmp 0.28.15` ASN.1 BER/DER encoding & decompilation, and SNMPv1/v2c/v3 / LDAP / Kerberos PDUs.
  - [`.agents/rules/rustcrypto-best-practices.md`](../.agents/rules/rustcrypto-best-practices.md) — RustCrypto SNMPv3 USM RFC 3414/3826/7860 (`src/builders/l7/snmp/crypto.rs`).
  - [`.agents/rules/wasm-vscode-best-practices.md`](../.agents/rules/wasm-vscode-best-practices.md) — WebAssembly (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`), UTF-16 IDE span mapping, VS Code extension (`@vscode/vsce 4.1.0`), & OIDC Trusted Publishing (`frameassembly-wasm/**`, `frameassembly-vscode/**`).
  - [`.agents/rules/winnow-best-practices.md`](../.agents/rules/winnow-best-practices.md) — `winnow 1.0.5+` & `memchr 2.8.3` token-slice combinator parsers (`src/parser/`).

### 3.2 Specialized Skills (`.agents/skills/*/SKILL.md` — 11 Skills)
- [`.agents/skills/frameassembly/SKILL.md`](../.agents/skills/frameassembly/SKILL.md) — Compiler pipeline, AST `*Spec` design, 4-tuple state tracking, & forward/reverse pipeline stages.
- [`.agents/skills/networking-pcap/SKILL.md`](../.agents/skills/networking-pcap/SKILL.md) — Native L2–L7 RFC wire framing, checksums, & `pcap-file 2.0.0` PCAPNG serialization.
- [`.agents/skills/pcap-decompilation/SKILL.md`](../.agents/skills/pcap-decompilation/SKILL.md) — 5-stage PCAP/PCAPNG-to-`.fasm` decompilation, `etherparse 0.21.0` slicing, container linktype normalization, & self-checking compiler oracle.
- [`.agents/skills/winnow-parser/SKILL.md`](../.agents/skills/winnow-parser/SKILL.md) — Two-phase `logos` + `winnow 1.0.5+` / `memchr 2.8.3` `Stream<'i, 'a>` parsing.
- [`.agents/skills/logos-miette-diagnostics/SKILL.md`](../.agents/skills/logos-miette-diagnostics/SKILL.md) — `logos 0.14.4` / `0.16.1` tokenization & `miette 7.6.0` graphical diagnostics.
- [`.agents/skills/rasn-snmp-codec/SKILL.md`](../.agents/skills/rasn-snmp-codec/SKILL.md) — `rasn 0.28.15` ASN.1 BER/DER & SMIv1/SMIv2/SNMP wire encoding & decoding.
- [`.agents/skills/rustcrypto-engineering/SKILL.md`](../.agents/skills/rustcrypto-engineering/SKILL.md) — SNMPv3 USM authentication (`MD5`/`SHA`/`SHA-2`) & encryption (`DES`/`AES`).
- [`.agents/skills/clap-cli/SKILL.md`](../.agents/skills/clap-cli/SKILL.md) — `clap 4.6.7+`, `anstyle 1.0.14`, & `anstream 1.0.0` CLI architecture.
- [`.agents/skills/rust-modern-qa/SKILL.md`](../.agents/skills/rust-modern-qa/SKILL.md) — Multi-tier testing, 6-gate corpus & AST-to-builder verification, `proptest`, `cargo-mutants`, `tshark` gates, & `.agents/scripts/file_lock.sh`.
- [`.agents/skills/ai-seo-training-data/SKILL.md`](../.agents/skills/ai-seo-training-data/SKILL.md) — LLM pre-training filters, 4-stage RLVR compiler/decompiler rewards, 6-way grammar/IDE/WASM lockstep, & `docs.rs` SEO.
- [`.agents/skills/wasm-vscode/SKILL.md`](../.agents/skills/wasm-vscode/SKILL.md) — WebAssembly (`wasm-bindgen 0.2.130`), UTF-16 IDE diagnostics, VS Code extension (`@vscode/vsce 4.1.0`), & OIDC Trusted Publishing.
