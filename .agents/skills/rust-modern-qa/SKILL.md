---
name: rust-modern-qa
description: Comprehensive guide, multi-tier testing architecture, 5-gate corpus verification, proptest AST synthesis, cargo-mutants mutation testing, cargo-llvm-cov / cargo-semver-checks gates, 5-way grammar non-terminal resolution, external tshark dissector validation, and Edition 2024 doctest optimization for modern Rust 1.85+.
---

# Modern Rust (Edition 2024) QA, Corpus Verification & Compiler/Wire Testing Architecture Skill

Use this skill when architecting, implementing, debugging, optimizing, or auditing automated test suites, `.fasm` corpus verification frameworks (`2,611` scenarios / `13,055` synthetic multi-task instances), Markdown/rustdoc code-block compilers, property-based testing (`proptest`), mutation testing (`cargo-mutants`), 5-way grammar resolution checks, external Wireshark (`tshark`) dissector verification, and CI/CD quality gates in modern Rust 1.85+ Edition 2024 projects.

---

## 1. Modern Rust 2024 QA Selection Matrix

| Quality Assurance Goal | Idiomatic Modern Rust 2024 Pattern | Avoid (Suboptimal / Anti-Pattern) |
| :--- | :--- | :--- |
| **Comprehensive Functional Testing** | 4-Tier test hierarchy (`tests/tier1` to `tier4`) + RFC Spec tests | Monolithic, unstructured `tests/integration.rs` |
| **100% Zero-Skip DSL Corpus Verification** | Automated directory scanner validating all `2,611` `.fasm` files (`13,055` multi-task instances) with zero skipped errors | Wrapping `parse_program` in `if let Ok(...)` or asserting `compiled_count >= 800` |
| **`// TOKENS:` Lexer Stream Bijection** | Verify every token listed on Line 2 (`// TOKENS:`) matches actual `Token` variants emitted by `lexer::Token::lexer` | Substring matching (`t in body`) that passes when hallucinated tokens appear in both header and body |
| **Markdown & Rustdoc DSL Block Gate** | Extract and compile every ````frameassembly` and ````fasm` fence in `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `docs/*.md`, `.agents/skills/**/*.md`, and `src/**/*.rs` via `parse_program` + `validate_semantics(&prog, snippet)` + `compile_program` | Leaving uncompilable or drifted `.fasm` examples (e.g., `HTTP ... HOST` instead of `HOST_HDR`) inside Markdown guides |
| **Five-Way Grammar & Non-Terminal Lockstep** | Verify every keyword token in `src/lexer/mod.rs` is wired into `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and TextMate, and assert zero undefined RHS non-terminals | Adding tokens to `lexer` without matching grammar productions, or leaving undefined rules like `string_char` in `grammar.ebnf` |
| **Property-Based Compiler Testing (`proptest`)** | Generate arbitrary valid `.fasm` programs and ASTs via `proptest` strategies; assert `parse_program` $\rightarrow$ `validate_semantics(&prog, &src)` $\rightarrow$ `compile_program` never panics and yields valid L2/L3/L4 headers | Only testing hardcoded static strings and missing edge-case integer/payload boundaries |
| **Mutation Testing (`cargo-mutants`)** | Run `cargo mutants -f src/packet.rs -f src/builders/` to kill surviving checksum, bitmask, and endianness mutants; use `#[mutants::skip]` only on pure display/logging helpers | Assuming 90% line coverage guarantees bit-level RFC wire encoding correctness |
| **Coverage & Semver Gates** | `cargo llvm-cov --all-targets --fail-under-lines 90` and `cargo semver-checks check-release` | Shipping public AST or builder API breaking changes without semver verification |
| **External Dissector Verification (`tshark`)** | Pipe generated PCAPNG captures through `tshark -r out.pcap -V` and assert zero `[Malformed Packet]`, `[Bogus ... length]`, or `[Bad Checksum]` expert infos | Relying exclusively on internal unit tests to validate complex RFC wire framing (self-confirming bias) |
| **Thread-Safe Temp File Generation** | Atomic file naming via `AtomicU64` + PID + RAII cleanup guard (`TempCaptureGuard`) | Fixed temp file names (`/tmp/out.pcap`) causing parallel test collisions |
| **Documentation Test Execution** | Edition 2024 merged single-binary doctests (`cargo test --doc`) with runnable ````rust` API tests | Zero runnable ````rust` doctests (`0 passed`) or broken host references in `src/lib.rs` |
| **Link, Orphan & `< 50 KB` Chunk Gate** | Verify all relative Markdown links resolve on disk, zero orphan files exist in `docs/`, and all `docs/*.md` & `src/**/*.rs` are `< 50,000` bytes (`>= 50` words) | Dead 404 links in `README.md`/`AGENTS.md`/`llms.txt` or `> 50 KB` source modules |

---

## 2. Architecture Decision Guide

### 2.1 The Multi-Tier Testing Hierarchy
To guarantee zero regressions across complex parsers, state machines, and binary protocols, structure tests into a 4-tier taxonomy:

1. **Tier 1: Feature & Protocol Coverage (`tests/tier1_feature_coverage.rs`)**:
   - Validates that every individual protocol builder (across L2, L3, L4, and L7) produces valid byte output for its standard inputs (`src/builders/{l2,l3,l4,l7}/*.rs`).
   - Asserts exact field offsets, magic numbers, and standard header lengths.
2. **Tier 2: Boundary, Overflow & Corner Cases (`tests/tier2_boundary_and_corner_cases.rs`)**:
   - Tests boundary values: 0-byte payloads, maximum 65,535-byte lengths, integer wraps (`u16::MAX`, `u32::MAX`), empty strings, single-byte fragments, and malformed inputs.
   - Verifies that error conditions return clean `DiagnosticError` / `ParseError` variants from `parse_program(&src)` and `validate_semantics(&prog, &src)` rather than panicking.
3. **Tier 3: Cross-Feature Combinations & State Tracking (`tests/tier3_cross_feature_combinations.rs`)**:
   - Verifies interactions between independent subsystems: L2 QinQ + L3 IPv6 Flow Labels + L4 TCP options + L7 encrypted payloads.
   - Validates bidirectional 4-tuple state progression across `->` and `<-` in `src/backend/mod.rs`.
4. **Tier 4: Real-World Application & Network Telemetry Flows (`tests/tier4_real_world_application_flows.rs`)**:
   - End-to-end integration tests executing multi-step conversational flows: 3-way TCP handshakes, TLS handshakes, SNMPv3 USM discovery & encrypted query loops, and industrial SCADA automation cycles.
5. **Spec Regression Suites (`tests/snmp_spec_tests.rs`, `tests/cli_and_backwards_compatibility.rs`)**:
   - Direct conformance testing against published RFC standards (e.g., RFC 1157, RFC 3414, RFC 3826, RFC 7860).

---

### 2.2 Five-Gate Corpus & Documentation Verification Architecture (`tests/corpus_verification_tests.rs`)
In projects maintaining extensive example corpora (`2,611` `.fasm` files across 81 protocols + 100 topologies, yielding `13,055` synthetic multi-task training instances) and AI documentation (`docs/*.md`, `llms.txt`, `llms-full.txt`), `tests/corpus_verification_tests.rs` enforces five strict gates:

1. **Gate 1 — 100% Zero-Skip `.fasm` Corpus Compilation (`2,611` Scenarios)**:
   - Every `.fasm` file in `examples/**/*.fasm` must have `// PROMPT:` on Line 1, `// TOKENS:` on Line 2, and `// INSTRUCTION:` before every `HOST`, `FLOW`, and `COMPILE` block (`words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50,000` bytes).
   - Every file must pass `frameassembly::parser::parse_program(&content)`, `frameassembly::parser::validate_semantics(&program, &content)`, and `frameassembly::backend::generate_pcap(&program, path)` with **zero ignored errors**.
   - The generated PCAPNG file must be non-empty (`>= 28` bytes) and start with the PCAPNG Section Header Block magic (`0x0A0D0D0A`).
2. **Gate 2 — Strict `// TOKENS:` Lexer Stream Bijection**:
   - Tokenize the body of each `.fasm` file using `logos::Logos` (`frameassembly::lexer::Token::lexer`) and verify that every keyword token listed in `// TOKENS:` on Line 2 corresponds to a real uppercase keyword `Token` emitted by the lexer (immediately catching hallucinated keywords like `IPV4`, `IPV6`, `SEND`, `SPORT`, `DPORT`, `REQ_ID`).
3. **Gate 3 — Markdown & Rustdoc Fenced-Block Compilation**:
   - Scan `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `docs/*.md`, `.agents/skills/**/*.md`, and `src/**/*.rs` for all ```` ```frameassembly ```` and ```` ```fasm ```` code blocks.
   - Every block must be a complete program (`HOST` + `FLOW` + `COMPILE`) that passes `parse_program(snippet)`, `validate_semantics(&prog, snippet)`, and `compile_program(&prog)`.
4. **Gate 4 — Five-Way Grammar & Non-Terminal Lockstep**:
   - Verify that every keyword `#[token("...")]` in `src/lexer/mod.rs` is present in `grammar.ebnf`, `frameassembly.gbnf`, and `frameassembly.lark`, that every referenced non-terminal on the RHS of a grammar rule is defined on the LHS, and that `frameassembly.lark` includes contextual uppercase keywords in `str_or_ident`.
5. **Gate 5 — Link, Orphan, Word-Count & `< 50 KB` Chunk Hygiene**:
   - Assert every relative link `[...](path)` in `README.md`, `AGENTS.md`, `CLAUDE.md`, `llms.txt`, and `docs/*.md` resolves to an existing file on disk, zero unindexed orphan `.md` files exist in `docs/`, zero `0x00` NUL bytes exist, and every file in `docs/*.md` and `src/**/*.rs` satisfies `size < 50,000` bytes and `words >= 50` (OpenCoder `opc_data_filtering`).

---

### 2.3 Advanced Compiler & Wire QA Tooling (`proptest`, `cargo-mutants`, `cargo-llvm-cov`, `cargo-semver-checks`, `tshark`)

1. **Property-Based AST & Round-Trip Testing (`proptest`)**:
   - Use `proptest!` to synthesize randomized IPv4/IPv6 host pairs, valid port numbers (`1..=65535`), sequence/acknowledgment numbers (`0..=u32::MAX`), VLAN tags (`1..=4094`), and protocol payloads.
   - Assert three invariants for every generated `.fasm` script:
     1. `parse_program(&fasm)` and `validate_semantics(&prog, &fasm)` never panic.
     2. `compile_program(&prog)` produces exact frame counts matching statement counts (`1 Statement = 1 Frame`).
     3. Every emitted frame has valid Ethernet (`>= 14` bytes), IPv4 (`IHL == 5`, valid RFC 1071 header checksum) or IPv6 (`Version == 6`, payload length matching trailing bytes) framing.
2. **Mutation Testing (`cargo-mutants`)**:
   - Run targeted mutation campaigns on bit-critical modules:
     ```bash
     cargo mutants -f src/packet.rs -f src/builders/l2/ -f src/builders/l3/ -f src/builders/l4/
     ```
   - When `cargo-mutants` replaces `+` with `-`, `&` with `|`, or `>` with `>=` in a header builder or checksum function (`ipv4_checksum`, `transport_checksum`, `crc32c`, `dnp3_crc16`) and all tests still pass, add a Tier 1/Tier 2 byte-offset assertion to kill the surviving mutant.
   - Annotate non-behavioral diagnostic formatting functions with `#[mutants::skip]` so mutation runs focus exclusively on parser/compiler/wire semantics.
3. **Line/Branch Coverage & Semver Gates (`cargo-llvm-cov` & `cargo-semver-checks`)**:
   - Enforce `>= 90%` line coverage across compiler stages and verify zero accidental public API breakage before any release:
     ```bash
     cargo llvm-cov --all-targets --workspace --fail-under-lines 90
     cargo semver-checks check-release
     ```
4. **External Wireshark (`tshark`) Dissector Gate**:
   - Validate compiled `.pcap` / `.pcapng` outputs against Wireshark's official protocol dissectors (`tshark -r capture.pcap -V`) to verify zero `[Malformed Packet]`, `[Bogus ... length]`, or `[Bad Checksum]` expert info warnings across all 81 protocols.

---

### 2.4 Edition 2024 Doctest Optimization (`cargo test --doc`)
In Rust 1.85+ Edition 2024, doctests are compiled into a unified single binary rather than spawning independent `rustc` invocations per code block:
- **Executable Rust API Doctests**: Top-level library modules (`src/lib.rs`, `src/lexer/mod.rs`, `src/parser/mod.rs`, `src/backend/mod.rs`, `src/pcap.rs`) should include runnable ```` ```rust ```` doctests verifying programmatic compilation (`parse_program`, `validate_semantics(&prog, src)`, `compile_program`).
- **Strict Syntax Annotation for DSL Blocks**: Code blocks representing FrameAssembly `.fasm` syntax or CLI commands must use explicit tags with canonical syntax:
  ````markdown
  ```frameassembly
  HOST client { IP 192.168.1.10 MAC 00:11:22:33:44:55 }
  HOST server { IP 192.168.1.20 MAC 00:aa:bb:cc:dd:ee }
  FLOW ping_check(src, dst) {
      src -> dst ICMP ECHO_REQUEST ID 1 SEQ 1
      src <- dst ICMP ECHO_REPLY ID 1 SEQ 1
  }
  COMPILE {
      ping_check(client, server)
  }
  ```
  ````
  Or:
  ````markdown
  ```console
  $ frameassembly demo.fasm -o output.pcap
  ```
  ````

---

### 2.5 Token-Safe Multi-Agent Wave Orchestration Runbook
When executing repository-wide QA across all 81 protocols without exhausting the LLM context window:
1. **Wave 1 (Compiler & 81 Builders)**: Partition across 5 parallel `self` subagents with strictly disjoint file ownership (`1A`: Core/Lexer/Parser/CLI/SNMP; `1B`: Backend & L2/L3/L4; `1C`: L7 Infra/Telemetry/Mail/Auth; `1D`: L7 Web/Cloud/Security/VoIP; `1E`: L7 Storage/DB/Messaging/OT) with `cargo` commands deferred to the lead orchestrator to avoid `target/` lock contention.
2. **Wave 2 (5-Way Grammars, Rustdoc & Docs)**: Partition across parallel subagents for (a) 5-way grammars (`grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly.tmLanguage.json`), (b) AST `/// Syntax mapping:` docstrings, and (c) `docs/*.md` + `README.md` + metadata files.
3. **Wave 3 (Test Chunking `< 50 KB`, Wire Regressions, Gates 4–6 & `llms-full.txt`)**: Partition across parallel subagents for test splitting, wire regression assertions, `corpus_verification_tests.rs` Gates 4–6, and scripted `llms-full.txt` regeneration.
4. **Compact Return Summaries & `/compact` State Persistence**: Require subagents to return concise bulleted summaries (`<= 60` lines), record wave completion in a persistent artifact (`qa_wave_progress.md`), and pause between waves so the user can optionally run `/compact`.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations:
1. **Multi-Tier Test Architecture Implementation (Tiers 1–4 using real 2-arg `validate_semantics(&program, fasm)` and `HOST_HDR` APIs)**
2. **Five-Gate Corpus (`2,611` Files), Lexer Bijection & Markdown Block Verification Engine (`tests/corpus_verification_tests.rs`)**
3. **Automated 5-Way Grammar Lockstep & Non-Terminal Resolution Test Template (`EBNF`, `GBNF`, `Lark`)**
4. **Property-Based Compiler Round-Trip Testing (`proptest`) & External Wireshark (`tshark`) Dissector Gate**
5. **Mutation Testing (`cargo-mutants`), Coverage (`cargo-llvm-cov`) & Semver (`cargo-semver-checks`) CI Pipeline**
