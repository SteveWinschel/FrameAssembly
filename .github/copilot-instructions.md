# GitHub Copilot Instructions for FrameAssembly (`frameassembly`)

You are working on **FrameAssembly** (`frameassembly` v2.0.0, official website & browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)), a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles `.fasm` network packet specifications into deterministic `.pcap` / `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.fasm` code—across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

## 1. Canonical `.fasm` v2.0.0 Syntax Guardrails (Never Hallucinate Keywords)

When generating or editing FrameAssembly (`.fasm`) code or Markdown ````frameassembly` blocks:
1. **Strict-Lowercase Built-In Keywords (`[a-z0-9]+`, Zero `_`, Zero `-`) & Three-Block Structure**:
   - Every built-in keyword, protocol, modifier, and time unit (`ns`, `us`, `ms`, `s`, `m`) is **strictly lowercase alphanumeric with zero `_` and zero `-`** (no `ignore(ascii_case)`), while user-defined `host`, `flow`, and parameter names remain flexible (`[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`).
   - Always include `host`, `flow`, and `compile` blocks (`loop` was removed in v2.0.0; `compile` supports flow invocations and inline frame statements) so every snippet compiles standalone:
   ```frameassembly
   // PROMPT: TCP 3-way handshake and HTTP/1.1 GET healthcheck between client and server.
   // TOKENS: host, ip, mac, flow, tcp, syn, srcport, dstport, mss, ack, wait, http, get, uri, hosthdr, status, reason, body, compile

   // INSTRUCTION: Declare client and server endpoints.
   host client { ip 10.0.0.10 mac 00:11:22:33:44:10 }
   host server { ip 10.0.0.20 mac 00:11:22:33:44:20 }

   // INSTRUCTION: Define TCP handshake and HTTP GET transaction.
   flow http_healthcheck(c, s) {
       c -> s tcp syn srcport 51000 dstport 80 mss 1460
       c <- s tcp syn ack mss 1460 wait 1ms
       c -> s tcp ack wait 1ms
       c -> s http get uri "/healthz" hosthdr "api.internal" wait 2ms
       c <- s http status 200 reason "OK" body "{\"status\":\"healthy\"}" wait 2ms
   }

   // INSTRUCTION: Compile the flow into a PCAP capture.
   compile {
       http_healthcheck(client, server)
   }
   ```
2. **CLI Contract (Default Root Compile + 4 Subcommands `show`, `reverse`, `help`, `version` — Zero `-o`/`--output` Flags)**:
   - Compile (default root command): `cargo run -- demo.fasm output.pcap` (or `frameassembly demo.fasm [output.pcap]`, defaulting to `<input_stem>.pcap`)
   - Preview ladder: `cargo run -- show demo.fasm` (or `frameassembly show demo.fasm`)
   - Reverse PCAP/PCAPNG: `cargo run -- reverse output.pcap reversed.fasm` (emits `host1`, `host2` without `_`, strict lowercase, and zero `loop` blocks)
   - Help & version: `frameassembly help [subcommand]` and `frameassembly version` (hidden `-h`/`--help` and `-V`/`--version`; Tab completions in `contrib/completions/`)
3. **Forbidden Hallucinations**:
   - Never use uppercase built-in keywords (`HOST`, `TCP`, `SYN`, `WAIT 1MS`) or `_`/`-` inside built-in keywords (`echo_request`, `inner_vlan`, `client_hello`, `host_hdr`, `transport_hdr`, `sack_perm`, `who_is`, `pkt_type`, `read_holding_registers`).
   - Never use `ipv4`, `ipv6`, `=`, colons, commas, or `mask` inside `host { ... }` (only `[ip <ip>]` and `[mac <mac>]`).
   - Never declare parameterless `flow <id> { ... }` or use `from`, `to`, `reverse`, `send`, `loop`, standalone `wait` lines, or `+5ms` / `[+delay]` prefixes (always `flow <id>(<params>) { <a> -> <b> <proto> ... [wait <int><ns|us|ms|s|m>] }`).
   - Never use `sport`, `dport`, `ack_num`, `ack <n>`, `flags [...]`, `hop_limit`, `http ... host`, `rtsp ... transport`, or `req_id` (always use `srcport`, `dstport`, `acknum`, bare flags `syn ack`, `ttl`, `hosthdr`, `transporthdr`, and `reqid`).
   - Never write `qinq 100 200` (always write `qinq 100 innervlan 200`).
   - Never mix IPv4 and IPv6 endpoints in the same statement (`a -> b` or `a <- b`).

## 2. Rust 2024 Compiler, Release Channels & Confidentiality Standards

- Every AI-critical Rust file (`src/**/*.rs` and `tests/*.rs`) and corpus file (`examples/**/*.fasm`) must remain strictly `< 50,000` bytes (`< 50 KB`). Human-facing Markdown documentation (`README.md` and `docs/*.md`) has no `< 50 KB` cap, and human-facing docs (except `docs/for_nerds.md`) must never include `// PROMPT:`, `// TOKENS:`, or `// INSTRUCTION:` metadata comments.
- Every `src/**/*.rs` file must begin with `//!` module-level documentation (`>= 50` words) and document all structs, enums, fields, and functions without combining outer `///` on `pub mod` with inner `//!`.
- Keep `src/lexer/mod.rs`, `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, `frameassembly-wasm`, `README.md`, `src/lib.rs`, `docs/fasm-specification.md`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml` synchronized whenever lexer tokens or supported protocols change.
- **Audience Architecture & Calling `.fasm` Code (Zero Developer Jargon & Zero Prompt Leaking)**: (1) `llms.txt` is optimized for search engines of AIs and `llms-full.txt` is optimized for pre-training and prompting of AIs; (2) `docs/*.md` are written for networking and cybersecurity professionals in a natural, direct human voice with practical tool examples (`Checkmk`, `Zabbix`, `Wireshark`, `Suricata`, `tcpreplay`); (3) READMEs (`README.md`, `frameassembly-vscode/README.md`, `frameassembly-wasm/README.md`) are tailored to their target audiences, with root `README.md` kept minimalistic—interesting and informative without being overwhelming—focused on the problems solved (preventing manual device/daemon configuration work, avoiding manual fault triggering on hardware, skipping lab VM setup, and avoiding manual checksum/TCP sequence math), use cases (pentesting, testing firewalls, simulating SNMP traps, testing monitoring/cybersecurity solutions), and advantages over other solutions. Never spam filler AI adjectives (`"readable"`, `"clean"`, `"editable"`, `"canonical"`, `"repeatable"`), never parrot repetitive slogans across paragraphs, never use compiler/PL jargon (`"DSL"`, `"Domain-Specific Language"`, `"declarative"`, `"polymorphic"`, `"deterministic"`) in `README.md` or `docs/*.md` (except `docs/for_nerds.md`), and never leak or quote informal prompt phrasing into documentation. Always call `.fasm` **code** (`Packets as Code`), never `"plain text"`.
- Always write `FrameAssembly` as one unspaced CamelCase word (`frameassembly` for crate/CLI/URLs/identifiers; never split `Frame` and `Assembly` with a space), never claim zero external crate dependencies (use `"rootless"`, `"offline"`, `"deterministic"`, `"no libpcap or raw sockets required"`), disambiguate `.fasm` (`text/vnd.frameassembly`) from x86 Flat Assembler and FPGA FASM, and position FrameAssembly as the upstream companion compiler to `tcpreplay`, `Wireshark`, `tshark`, `Suricata`, and `Zeek` (comparing only against packet-crafting generators `Scapy`, `text2pcap`, and `Ostinato`).
- **Supported Release Channels Only**: GitHub Releases + Debian/Ubuntu `.deb`, Crates.io (`frameassembly`), NPM (`frameassembly-wasm`), VS Code Marketplace (`frameassembly-vscode`), and `SteveWinschel/homebrew-tap-FrameAssembly` (`Homebrew` & `Scoop`)—do not reference or add workflows for any other third-party package or extension registries.
- **Private User Context Confidentiality**: Never include private background context shared by the user in prompts (such as employer names or employment/apprenticeship status) anywhere in code, comments, examples, documentation, or metadata.
- Never bump `version` in manifests or run `git commit`, `git push`, or `git tag` unless explicitly instructed by the user.
- Run `cargo test` to verify all unit, integration, documentation, and corpus tests (`2,611` `.fasm` scenarios) pass.

## 3. Repository Rules & Skills Index

Consult the root [`AGENTS.md`](../AGENTS.md) and these domain rules and skills when working in specific subsystems:

### 3.1 Workspace Rules (`.agents/rules/*.md` — 15 Files)
- **Always-On (`4` rules)**:
  - [`.agents/rules/frameassembly-dsl.md`](../.agents/rules/frameassembly-dsl.md) — Canonical v2.0.0 strict-lowercase `.fasm` grammar, 6-stage forward compiler + reverse PCAP decompiler, confidentiality, & 81-protocol invariants.
  - [`.agents/rules/versioning_and_git.md`](../.agents/rules/versioning_and_git.md) — Explicit-only version bumps across supported release channels & git commits/tags.
  - [`.agents/rules/temporary_files.md`](../.agents/rules/temporary_files.md) — Workspace `temp/` directory & `.gitignore` rules.
  - [`.agents/rules/token-and-context-efficiency.md`](../.agents/rules/token-and-context-efficiency.md) — 20k-token rules budget discipline, 3-layer parallel multi-agent file locking (`.agents/scripts/file_lock.sh` + `.agents/hooks.json`), subagent context isolation, `/compact` persistence, & grounded clarification questions.
- **Glob-Scoped (`11` domain rules)**:
  - [`.agents/rules/rust-2024-best-practices.md`](../.agents/rules/rust-2024-best-practices.md) — Rust 2024 Edition and `rustc 1.85–1.99.1` idioms & `< 50 KB` module ceiling (`Cargo.toml`, `src/**/*.rs`, `tests/**/*.rs`, `frameassembly-wasm/**/*.rs`).
  - [`.agents/rules/publishing_and_docs.md`](../.agents/rules/publishing_and_docs.md) — Rustdoc/`docs.rs` lint gates, Cargo `build.warnings` (Rust 1.97+), zero NUL bytes, & crate packaging.
  - [`.agents/rules/ai-seo-best-practices.md`](../.agents/rules/ai-seo-best-practices.md) — Pre-training filters, 4-stage RLVR compiler & PCAP-to-`.fasm` decompilation rewards, & 6-way grammar/IDE/WASM lockstep.
  - [`.agents/rules/clap-best-practices.md`](../.agents/rules/clap-best-practices.md) — `clap 4.6.7+`, `anstyle 1.0.14`, & `anstream 1.0.0` v2.0.0 default-compile + 4-subcommand CLI (`src/main.rs`).
  - [`.agents/rules/logos-miette-best-practices.md`](../.agents/rules/logos-miette-best-practices.md) — `logos 0.14.4` / `0.16.1` strict-lowercase lexing, 6-tier priority ladder, self-healing keyword suggestions, & `miette 7.6.0` diagnostics (`src/lexer/`, `src/error.rs`).
  - [`.agents/rules/networking-pcap-best-practices.md`](../.agents/rules/networking-pcap-best-practices.md) — L2–L7 RFC wire builders, checksums, & `pcap-file 2.0.0` PCAPNG.
  - [`.agents/rules/pcap-decompilation-best-practices.md`](../.agents/rules/pcap-decompilation-best-practices.md) — 5-stage PCAP/PCAPNG-to-`.fasm` decompilation pipeline (`host1`/`host2`, strict lowercase, zero `loop`), `etherparse 0.21.0` `link_exts` zero-copy slicing, container normalization, fuzz safety, & self-checking compiler oracle (`src/reverse/**`).
  - [`.agents/rules/rasn-snmp-best-practices.md`](../.agents/rules/rasn-snmp-best-practices.md) — `rasn`, `rasn-smi`, & `rasn-snmp 0.28.15` ASN.1 BER/DER encoding & decompilation, and SNMPv1/v2c/v3 / LDAP / Kerberos PDUs.
  - [`.agents/rules/rustcrypto-best-practices.md`](../.agents/rules/rustcrypto-best-practices.md) — RustCrypto SNMPv3 USM RFC 3414/3826/7860 (`src/builders/l7/snmp/crypto.rs`).
  - [`.agents/rules/wasm-vscode-best-practices.md`](../.agents/rules/wasm-vscode-best-practices.md) — WebAssembly (`wasm-bindgen 0.2.130`, `serde-wasm-bindgen 0.6.5`, `wasm-pack 0.15.1`), UTF-16 IDE span mapping + Quick Fixes, VS Code Packet Studio (`@vscode/vsce 4.1.0`), & OIDC Trusted Publishing (`frameassembly-wasm/**`, `frameassembly-vscode/**`).
  - [`.agents/rules/winnow-best-practices.md`](../.agents/rules/winnow-best-practices.md) — `winnow 1.0.5+` & `memchr 2.8.3` token-slice combinator parsers (`src/parser/`).

### 3.2 Specialized Skills (`.agents/skills/*/SKILL.md` — 11 Skills)
- [`.agents/skills/frameassembly/SKILL.md`](../.agents/skills/frameassembly/SKILL.md) — v2.0.0 strict-lowercase compiler pipeline, AST `*Spec` design, 4-tuple state tracking, & forward/reverse pipeline stages.
- [`.agents/skills/networking-pcap/SKILL.md`](../.agents/skills/networking-pcap/SKILL.md) — Native L2–L7 RFC wire framing, checksums, & `pcap-file 2.0.0` PCAPNG serialization.
- [`.agents/skills/pcap-decompilation/SKILL.md`](../.agents/skills/pcap-decompilation/SKILL.md) — 5-stage PCAP/PCAPNG-to-`.fasm` decompilation, `etherparse 0.21.0` slicing, container linktype normalization, & self-checking compiler oracle.
- [`.agents/skills/winnow-parser/SKILL.md`](../.agents/skills/winnow-parser/SKILL.md) — Two-phase `logos` + `winnow 1.0.5+` / `memchr 2.8.3` `Stream<'i, 'a>` parsing.
- [`.agents/skills/logos-miette-diagnostics/SKILL.md`](../.agents/skills/logos-miette-diagnostics/SKILL.md) — `logos 0.14.4` / `0.16.1` strict-lowercase tokenization, self-healing keyword diagnostics, & `miette 7.6.0` graphical diagnostics.
- [`.agents/skills/rasn-snmp-codec/SKILL.md`](../.agents/skills/rasn-snmp-codec/SKILL.md) — `rasn 0.28.15` ASN.1 BER/DER & SMIv1/SMIv2/SNMP wire encoding & decoding.
- [`.agents/skills/rustcrypto-engineering/SKILL.md`](../.agents/skills/rustcrypto-engineering/SKILL.md) — SNMPv3 USM authentication (`md5`/`sha`/`sha256`/`sha384`/`sha512`) & encryption (`des`/`aes`).
- [`.agents/skills/clap-cli/SKILL.md`](../.agents/skills/clap-cli/SKILL.md) — `clap 4.6.7+`, `anstyle 1.0.14`, & `anstream 1.0.0` default-compile + 4-subcommand CLI architecture.
- [`.agents/skills/rust-modern-qa/SKILL.md`](../.agents/skills/rust-modern-qa/SKILL.md) — Multi-tier testing, 6-gate corpus & AST-to-builder verification, `proptest`, `cargo-mutants`, `tshark` gates, & `.agents/scripts/file_lock.sh`.
- [`.agents/skills/ai-seo-training-data/SKILL.md`](../.agents/skills/ai-seo-training-data/SKILL.md) — LLM pre-training filters, 4-stage RLVR compiler/decompiler rewards, 6-way grammar/IDE/WASM lockstep, & `docs.rs` SEO.
- [`.agents/skills/wasm-vscode/SKILL.md`](../.agents/skills/wasm-vscode/SKILL.md) — WebAssembly (`wasm-bindgen 0.2.130`), UTF-16 IDE diagnostics + Quick Fixes, VS Code Packet Studio (`@vscode/vsce 4.1.0`), & OIDC Trusted Publishing.
