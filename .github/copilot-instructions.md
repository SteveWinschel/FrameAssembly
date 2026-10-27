# GitHub Copilot Instructions for FrameAssembly (`frameassembly`)

You are working on **FrameAssembly**, a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles human-readable `.fasm` network packet specifications into deterministic `.pcap` / `.pcapng` packet captures across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

## 1. Canonical `.fasm` Syntax Guardrails (Never Hallucinate Keywords)

When generating or editing FrameAssembly (`.fasm`) code or Markdown ````frameassembly` blocks:
1. **Always include `HOST`, `FLOW`, and `COMPILE` blocks** (all keywords, protocols, modifiers, time units, and identifiers are case-insensitive: `host` or `HOST`, `tcp` or `TCP`) so every snippet compiles standalone:
   ```frameassembly
   // PROMPT: TCP 3-way handshake and HTTP/1.1 GET healthcheck between client and server.
   // TOKENS: HOST, IP, MAC, FLOW, ->, <-, TCP, SYN, ACK, SRCPORT, DSTPORT, MSS, HTTP, GET, RESPONSE, URI, HOST_HDR, STATUS, REASON, BODY, WAIT, COMPILE

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

- Every `src/**/*.rs` and `docs/*.md` file must remain strictly `< 50,000` bytes (`< 50 KB`).
- Every `src/**/*.rs` file must begin with `//!` module-level documentation (`>= 50` words) and document all structs, enums, fields, and functions without combining outer `///` on `pub mod` with inner `//!`.
- Keep `src/lexer/mod.rs`, `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json` synchronized in 5-way lockstep.
- Run `cargo test` to verify all unit, integration, documentation, and corpus tests (`2,611` `.fasm` scenarios) pass.

## 3. Repository Rules & Skills Index

Consult the root [`AGENTS.md`](../AGENTS.md) and these domain rules and skills when working in specific subsystems:

### 3.1 Workspace Rules (`.agents/rules/*.md` — 13 Files)
- **Always-On (`6` rules)**:
  - [`.agents/rules/frameassembly-dsl.md`](../.agents/rules/frameassembly-dsl.md) — Canonical `.fasm` grammar & 81-protocol invariants.
  - [`.agents/rules/rust-2024-best-practices.md`](../.agents/rules/rust-2024-best-practices.md) — Rust 1.85+ Edition 2024 idioms & `< 50 KB` module ceiling.
  - [`.agents/rules/publishing_and_docs.md`](../.agents/rules/publishing_and_docs.md) — Rustdoc/`docs.rs` lint gates, zero NUL bytes, & crate packaging.
  - [`.agents/rules/versioning_and_git.md`](../.agents/rules/versioning_and_git.md) — Explicit-only version bumps & git commits/tags.
  - [`.agents/rules/temporary_files.md`](../.agents/rules/temporary_files.md) — Workspace `temp/` directory & `.gitignore` rules.
  - [`.agents/rules/token-and-context-efficiency.md`](../.agents/rules/token-and-context-efficiency.md) — Token-budget conservation, subagent context isolation, disjoint parallel file ownership, & `/compact` checkpoint persistence.
- **Glob-Scoped (`7` domain rules)**:
  - [`.agents/rules/ai-seo-best-practices.md`](../.agents/rules/ai-seo-best-practices.md) — Pre-training filters, RLVR compiler rewards, & 5-way grammar lockstep.
  - [`.agents/rules/clap-best-practices.md`](../.agents/rules/clap-best-practices.md) — `clap 4.6+` Derive CLI (`src/main.rs`).
  - [`.agents/rules/logos-miette-best-practices.md`](../.agents/rules/logos-miette-best-practices.md) — `logos 0.14` lexing & `miette 7.6` diagnostics (`src/lexer/`, `src/error.rs`).
  - [`.agents/rules/networking-pcap-best-practices.md`](../.agents/rules/networking-pcap-best-practices.md) — L2–L7 RFC wire builders, checksums, & `pcap-file 2.0` PCAPNG.
  - [`.agents/rules/rasn-snmp-best-practices.md`](../.agents/rules/rasn-snmp-best-practices.md) — `rasn 0.28` ASN.1 BER/DER & SNMPv1/v2c/v3 PDUs.
  - [`.agents/rules/rustcrypto-best-practices.md`](../.agents/rules/rustcrypto-best-practices.md) — RustCrypto SNMPv3 USM RFC 3414/3826/7860 (`src/builders/l7/snmp/crypto.rs`).
  - [`.agents/rules/winnow-best-practices.md`](../.agents/rules/winnow-best-practices.md) — `winnow 1.0` token-slice combinator parsers (`src/parser/`).

### 3.2 Specialized Skills (`.agents/skills/*/SKILL.md` — 9 Skills)
- [`.agents/skills/frameassembly/SKILL.md`](../.agents/skills/frameassembly/SKILL.md) — Compiler pipeline, AST `*Spec` design, & 4-tuple state tracking.
- [`.agents/skills/networking-pcap/SKILL.md`](../.agents/skills/networking-pcap/SKILL.md) — Native L2–L7 RFC wire framing, checksums, & PCAPNG serialization.
- [`.agents/skills/winnow-parser/SKILL.md`](../.agents/skills/winnow-parser/SKILL.md) — Two-phase `logos` + `winnow 1.0` `Stream<'i, 'a>` parsing.
- [`.agents/skills/logos-miette-diagnostics/SKILL.md`](../.agents/skills/logos-miette-diagnostics/SKILL.md) — `logos 0.14` tokenization & `miette 7.6` graphical diagnostics.
- [`.agents/skills/rasn-snmp-codec/SKILL.md`](../.agents/skills/rasn-snmp-codec/SKILL.md) — ASN.1 BER/DER & SMIv1/SMIv2/SNMP wire encoding.
- [`.agents/skills/rustcrypto-engineering/SKILL.md`](../.agents/skills/rustcrypto-engineering/SKILL.md) — SNMPv3 USM authentication (`MD5`/`SHA`/`SHA-2`) & encryption (`DES`/`AES`).
- [`.agents/skills/clap-cli/SKILL.md`](../.agents/skills/clap-cli/SKILL.md) — `clap 4.6+` CLI architecture & terminal styling.
- [`.agents/skills/rust-modern-qa/SKILL.md`](../.agents/skills/rust-modern-qa/SKILL.md) — 4-tier testing, 5-gate corpus verification (`2,611` files), `proptest`, `cargo-mutants`, & `tshark` gates.
- [`.agents/skills/ai-seo-training-data/SKILL.md`](../.agents/skills/ai-seo-training-data/SKILL.md) — LLM pre-training filters, RLVR rewards, 5-way constrained decoding grammars, & `docs.rs` SEO.
