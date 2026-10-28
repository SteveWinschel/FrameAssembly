# CLAUDE.md — FrameAssembly Project Instructions for Claude Code & AI Agents

**FrameAssembly** (`frameassembly` v1.2.1) is a Rust 2024 Domain-Specific Language (DSL) and optimizing compiler that compiles declarative `.fasm` network packet specifications into deterministic, nanosecond-precision `.pcap` / `.pcapng` packet captures across **81 native Layer 2 through Layer 7 protocols** (`2,611` verified `.fasm` corpus scenarios).

---

## 1. Essential Build, Test & Verification Commands

```bash
# Cross-platform bootstrap install (curl + C linker + rustup >= 1.85 + cargo install)
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh

# Build compiler and CLI binary
cargo build --release

# Run all unit, integration, and corpus verification tests
cargo test

# Run the corpus verification suite (validates all 2,611 examples/**/*.fasm headers, AST parsing & PCAP output)
cargo test --test corpus_verification_tests

# Compile a single .fasm specification to a .pcap file
cargo run -- demo.fasm -o output.pcap
```

---

## 2. Canonical `.fasm` Language Rules (Zero Hallucinations)

1. **Three-Block Program Structure & Case-Insensitivity**:
   - All keywords, protocols, modifiers, time suffixes (`ns`, `us`, `ms`, `s`, `m`), and user-defined identifiers (`HOST`, `FLOW`, parameters) are case-insensitive (`host` / `HOST`, `tcp` / `TCP`).
   - `HOST <id> { IP <ipv4_or_ipv6> [MAC <mac>] }` (`MAC` is optional; never use `IPV4`, `IPV6`, `=`, colons, commas, or `MASK`).
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
   - Metrics: `words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50,000` bytes.

---

## 3. Repository Architecture & Documentation Map

- **Compiler Pipeline (`src/`)**:
  - [`src/lexer/mod.rs`](src/lexer/mod.rs) — Zero-copy `logos 0.14` tokenizer (`Token<'a>`).
  - [`src/ast/`](src/ast/mod.rs) — Layer-organized AST specifications (`l2/`, `l3/`, `l4/`, `l7/`).
  - [`src/parser/`](src/parser/mod.rs) — `winnow 1.0` combinator parser (`parse_program`) and 2-arg semantic validator (`validate_semantics(&program, &source)`).
  - [`src/builders/`](src/builders/mod.rs) — Wire-level protocol encoders (`l2/`, `l3/`, `l4/`, `l7/`, including RFC 3414/3826/7860 `l7/snmp/`).
  - [`src/backend/mod.rs`](src/backend/mod.rs), [`src/packet.rs`](src/packet.rs), [`src/pcap.rs`](src/pcap.rs) — Stateful 4-tuple TCP sequence progression, Ethernet/IPv4/IPv6 encapsulation, and nanosecond PCAPNG writer.
- **Canonical Documentation (`docs/*.md`, all `< 50 KB`)**:
  - [`docs/architecture_and_grammar.md`](docs/architecture_and_grammar.md), [`docs/l2_protocols.md`](docs/l2_protocols.md), [`docs/l3_protocols.md`](docs/l3_protocols.md), [`docs/l4_transports.md`](docs/l4_transports.md), [`docs/l7_snmp.md`](docs/l7_snmp.md), [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md), [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md), [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md), [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md), [`docs/topologies_and_dual_stack.md`](docs/topologies_and_dual_stack.md), [`docs/qa_synthesis_guide.md`](docs/qa_synthesis_guide.md).
- **Constrained Decoding Grammars & AI Context Bundles**:
  - [`grammar.ebnf`](grammar.ebnf) (ISO/IEC 14977 EBNF), [`frameassembly.gbnf`](frameassembly.gbnf) (`llama.cpp` & `XGrammar` GBNF), [`frameassembly.lark`](frameassembly.lark) (`llguidance` & `Outlines` Lark).
  - [`AGENTS.md`](AGENTS.md), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), [`context7.json`](context7.json), [`CITATION.cff`](CITATION.cff), [`codemeta.json`](codemeta.json).

---

## 4. Workspace Rules (`.agents/rules/*.md`) & Domain Skills (`.agents/skills/*/SKILL.md`)

### 4.1 All 13 Workspace Rules (`6` `always_on` + `7` `glob`-Scoped)
- **Always-On Rules (`trigger: always_on`)**:
  1. [`.agents/rules/frameassembly-dsl.md`](.agents/rules/frameassembly-dsl.md) — Core `.fasm` language syntax, 81-protocol rules, and anti-hallucination guardrails.
  2. [`.agents/rules/rust-2024-best-practices.md`](.agents/rules/rust-2024-best-practices.md) — Rust 1.85+ Edition 2024 standards, `< 50 KB` module ceiling, and error handling.
  3. [`.agents/rules/publishing_and_docs.md`](.agents/rules/publishing_and_docs.md) — Zero NUL bytes, Rustdoc/`docs.rs` lint gates, `//!` module docstrings, and Crates.io packaging.
  4. [`.agents/rules/versioning_and_git.md`](.agents/rules/versioning_and_git.md) — Prohibits unrequested version bumps or `git commit`/`push`/`tag`.
  5. [`.agents/rules/temporary_files.md`](.agents/rules/temporary_files.md) — Workspace `temp/` directory and `.gitignore` hygiene.
  6. [`.agents/rules/token-and-context-efficiency.md`](.agents/rules/token-and-context-efficiency.md) — Token-budget conservation, subagent context isolation, disjoint parallel file ownership, and `/compact` checkpoint persistence.
- **Glob-Scoped Domain Rules (`trigger: glob`)**:
  7. [`.agents/rules/ai-seo-best-practices.md`](.agents/rules/ai-seo-best-practices.md) — Pre-training dataset filters, RLVR compiler rewards, 5-way grammar lockstep, and SEO.
  8. [`.agents/rules/clap-best-practices.md`](.agents/rules/clap-best-practices.md) — `clap 4.6+` Derive CLI design and value parsers (`src/main.rs`).
  9. [`.agents/rules/logos-miette-best-practices.md`](.agents/rules/logos-miette-best-practices.md) — `logos 0.14` lexing and `miette 7.6` diagnostics (`src/lexer/`, `src/error.rs`).
  10. [`.agents/rules/networking-pcap-best-practices.md`](.agents/rules/networking-pcap-best-practices.md) — L2–L7 RFC wire framing, checksums, and `pcap-file 2.0` PCAPNG output.
  11. [`.agents/rules/rasn-snmp-best-practices.md`](.agents/rules/rasn-snmp-best-practices.md) — `rasn 0.28` ASN.1 BER/DER and SNMPv1/v2c/v3 PDUs (`src/builders/l7/snmp/`).
  12. [`.agents/rules/rustcrypto-best-practices.md`](.agents/rules/rustcrypto-best-practices.md) — RustCrypto SNMPv3 USM RFC 3414/3826/7860 authentication and privacy (`src/builders/l7/snmp/crypto.rs`).
  13. [`.agents/rules/winnow-best-practices.md`](.agents/rules/winnow-best-practices.md) — `winnow 1.0` `Stream<'i, 'a>` combinator parsers (`src/parser/`).

### 4.2 All 9 Specialized Skills
1. **`frameassembly`**: [`.agents/skills/frameassembly/SKILL.md`](.agents/skills/frameassembly/SKILL.md) — DSL syntax, AST `*Spec` design, parser dispatch, and backend state tracking.
2. **`networking-pcap`**: [`.agents/skills/networking-pcap/SKILL.md`](.agents/skills/networking-pcap/SKILL.md) — L2–L7 wire builders, RFC checksum engines, and PCAPNG serialization.
3. **`winnow-parser`**: [`.agents/skills/winnow-parser/SKILL.md`](.agents/skills/winnow-parser/SKILL.md) — Two-phase `logos` + `winnow 1.0` token-slice parsing and `StrContext` diagnostics.
4. **`logos-miette-diagnostics`**: [`.agents/skills/logos-miette-diagnostics/SKILL.md`](.agents/skills/logos-miette-diagnostics/SKILL.md) — Zero-copy `logos 0.14` tokenizers and `miette 7.6` error reporting.
5. **`rasn-snmp-codec`**: [`.agents/skills/rasn-snmp-codec/SKILL.md`](.agents/skills/rasn-snmp-codec/SKILL.md) — ASN.1 BER/DER encoding and SMIv1/SMIv2/SNMP wire builders.
6. **`rustcrypto-engineering`**: [`.agents/skills/rustcrypto-engineering/SKILL.md`](.agents/skills/rustcrypto-engineering/SKILL.md) — SNMPv3 USM RFC 3414/3826/7860 cryptography with RustCrypto.
7. **`clap-cli`**: [`.agents/skills/clap-cli/SKILL.md`](.agents/skills/clap-cli/SKILL.md) — Modern `clap 4.6+` CLI engineering and terminal styling.
8. **`rust-modern-qa`**: [`.agents/skills/rust-modern-qa/SKILL.md`](.agents/skills/rust-modern-qa/SKILL.md) — 4-tier testing, 5-gate corpus verification (`2,611` files), `proptest`, `cargo-mutants`, and `tshark` gates.
9. **`ai-seo-training-data`**: [`.agents/skills/ai-seo-training-data/SKILL.md`](.agents/skills/ai-seo-training-data/SKILL.md) — LLM pre-training filters, RLVR rewards, 5-way constrained decoding grammars, and `docs.rs` SEO.
