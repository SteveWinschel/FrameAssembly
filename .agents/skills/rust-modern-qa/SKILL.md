---
name: rust-modern-qa
description: Comprehensive guide, multi-tier testing architecture, 6-gate corpus & AST-to-builder wiring verification, proptest AST synthesis with proptest-regressions VCS pinning, cargo-mutants (--in-diff) mutation testing, cargo-nextest / cargo-llvm-cov (--doctests) / cargo-semver-checks gates, 6-way grammar/IDE/WASM lockstep, external tshark dissector validation, Rust 1.89-1.99.1 QA features (assert_matches!, File::lock, build.warnings), and parallel multi-agent file locking (.agents/scripts/file_lock.sh).
---

# Modern Rust (Edition 2024, Rust 1.85–1.99.1) QA, Corpus Verification & Compiler/Wire Testing Skill

Use this skill when architecting, implementing, debugging, optimizing, or auditing automated test suites, `.fasm` corpus verification frameworks (`2,611` scenarios / `13,055` synthetic multi-task instances), Markdown/rustdoc code-block compilers, property-based testing (`proptest`), mutation testing (`cargo-mutants`), 6-way grammar/IDE/WASM lockstep checks, AST `*Spec`-to-builder field wiring verification, external Wireshark (`tshark`) dissector verification, and parallel multi-agent CI/CD quality gates in modern Rust 1.85–1.99.1 (Edition 2024) projects.

---

## 1. Modern Rust 2024 (1.85–1.99.1) QA Selection Matrix

| Quality Assurance Goal | Idiomatic Modern Rust 2024 (1.85–1.99.1) Pattern | Avoid (Suboptimal / Anti-Pattern) |
| :--- | :--- | :--- |
| **Comprehensive Functional Testing** | 4-Tier test hierarchy (`tests/tier1` to `tier4`) + RFC Spec tests | Monolithic, unstructured `tests/integration.rs` |
| **Pattern & Diagnostic Variant Assertions (Rust 1.96+)** | `std::assert_matches::assert_matches!` and `debug_assert_matches!` on `CompilerError::ParseError { .. }` / `SemanticError { .. }` | Verbose `if let Err(CompilerError::SemanticError { .. }) = res {} else { panic!() }` |
| **Zero-Warning CI Enforcement (Rust 1.97+)** | Cargo `build.warnings = "deny"` in `.cargo/config.toml` or `CARGO_BUILD_WARNINGS=deny` alongside workspace `[lints]` | Ad-hoc `RUSTFLAGS="-D warnings"` that breaks third-party path/git dependencies or misses Cargo-level warnings |
| **Cross-Process Test File Locking (Rust 1.89+)** | `std::fs::File::lock()` / `lock_shared()` / `try_lock()` for cross-process test synchronization + `AtomicU64` + PID temp paths | Fixed temp file names (`/tmp/out.pcap`) or external `fs2`/`fd-lock` crates for simple advisory file locks |
| **100% Zero-Skip DSL Corpus Verification** | 6-Gate automated verifier (`tests/corpus_verification_tests.rs`) validating all `2,611` `.fasm` files (`13,055` multi-task instances) with zero skipped errors | Wrapping `parse_program` in `if let Ok(...)` or asserting `compiled_count >= 800` |
| **`// TOKENS:` Lexer Stream Bijection** | Verify every token listed on Line 2 (`// TOKENS:`) matches actual strict-lowercase `[a-z0-9]+` `Token` variants emitted by `lexer::Token::lexer` | Substring matching (`t in body`) that passes when hallucinated tokens appear in both header and body |
| **Markdown & Rustdoc DSL Block Gate** | Extract and compile every ````frameassembly` and ````fasm` fence in `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `docs/*.md`, `.agents/skills/**/*.md`, and `src/**/*.rs` via `parse_program` + `validate_semantics` + `compile_program` | Leaving uncompilable or drifted `.fasm` examples (e.g., `http ... host` instead of `hosthdr`, uppercase/underscore v1.x keywords, or removed `loop` blocks) inside Markdown guides |
| **6-Way Grammar, IDE & WASM Lockstep** | Verify every strict-lowercase `[a-z0-9]+` keyword token in `src/lexer/mod.rs` (zero `_`, zero `-`, no `ignore(ascii_case)`, no `loop`) is wired into `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly.tmLanguage.json`, and `frameassembly-wasm`, and assert zero undefined RHS non-terminals | Adding tokens to `lexer` without matching grammar/TextMate rules, or leaving undefined rules like `string_char` in `grammar.ebnf` |
| **AST `*Spec`-to-Builder Field Wiring (Gate 6)** | Scan every `pub` field on all 81 AST `*Spec` structs (`src/ast/{l2,l3,l4,l7}/*.rs`) and assert it is referenced in `src/builders/`, `src/packet.rs`, or `src/backend/` | Parsing a `.fasm` modifier into an AST `*Spec` struct field that the wire builder silently ignores |
| **Property-Based Compiler Testing (`proptest`)** | Generate arbitrary valid `.fasm` programs and ASTs via `proptest` strategies and commit `proptest-regressions/` to VCS | Only testing hardcoded static strings or git-ignoring `proptest-regressions/` seed files |
| **Mutation Testing (`cargo-mutants`)** | Run `cargo mutants -f src/packet.rs -f src/builders/` and `cargo mutants --in-diff git.diff` on parsers/crypto/validators; use `#[mutants::skip]` only on display helpers | Assuming 90% line coverage guarantees bit-level RFC wire encoding or cryptographic correctness |
| **Nextest, Doctest Coverage & Semver Gates** | `cargo nextest run`, `cargo llvm-cov --all-targets --doctests --fail-under-lines 90`, and `cargo semver-checks check-release` | Omitting `--doctests` from coverage or shipping public AST/builder API breaking changes without semver checks |
| **External Dissector Verification (`tshark`)** | Pipe generated PCAPNG captures through `tshark -r out.pcap -V` and assert zero `[Malformed Packet]`, `[Bogus ... length]`, or `[Bad Checksum]` expert infos | Relying exclusively on internal unit tests to validate complex RFC wire framing (self-confirming bias) |
| **Parallel Multi-Agent File Locking** | `.agents/scripts/file_lock.sh acquire <agent> <ttl> <files...>` before editing and `exec cargo-target -- cargo test` to serialize Cargo builds | Concurrent agents editing overlapping files or deadlocking on `target/` Cargo build locks |

---

## 2. Architecture Decision Guide

### 2.1 The Multi-Tier Testing Hierarchy
To guarantee zero regressions across complex parsers, state machines, and binary protocols, structure tests into a 4-tier taxonomy:

1. **Tier 1: Feature & Protocol Coverage (`tests/tier1_feature_coverage.rs`)**:
   - Validates that every individual protocol builder (across L2, L3, L4, and L7) produces valid byte output for its standard inputs (`src/builders/{l2,l3,l4,l7}/*.rs`).
   - Asserts exact field offsets, magic numbers, and standard header lengths.
2. **Tier 2: Boundary, Overflow & Corner Cases (`tests/tier2_boundary_and_corner_cases.rs`)**:
   - Tests boundary values: 0-byte payloads, maximum 65,535-byte lengths, integer wraps (`u16::MAX`, `u32::MAX`), empty strings, single-byte fragments, and malformed inputs.
   - Verifies that error conditions return clean `CompilerError::ParseError` / `SemanticError` variants (checked cleanly with Rust 1.96+ `assert_matches!`) rather than panicking.
3. **Tier 3: Cross-Feature Combinations & State Tracking (`tests/tier3_cross_feature_combinations.rs`)**:
   - Verifies interactions between independent subsystems: L2 QinQ + L3 IPv6 Flow Labels + L4 TCP options + L7 encrypted payloads.
   - Validates bidirectional 4-tuple state progression across `->` and `<-` in `src/backend/mod.rs`.
4. **Tier 4: Real-World Application & Network Telemetry Flows (`tests/tier4_real_world_application_flows.rs`)**:
   - End-to-end integration tests executing multi-step conversational flows: 3-way TCP handshakes, TLS handshakes, SNMPv3 USM discovery & encrypted query loops, and industrial SCADA automation cycles.
5. **Spec Regression Suites (`tests/snmp_spec_tests.rs`, `tests/cli_and_backwards_compatibility.rs`)**:
   - Direct conformance testing against published RFC standards (e.g., RFC 1157, RFC 3414, RFC 3826, RFC 7860).

---

### 2.2 Six-Gate Corpus, Grammar & AST Wiring Verification Architecture (`tests/corpus_verification_tests.rs`)
In projects maintaining extensive example corpora (`2,611` `.fasm` files across 81 protocols + 100 topologies, yielding `13,055` synthetic multi-task training instances) and AI documentation (`docs/*.md`, `llms.txt`, `llms-full.txt`), `tests/corpus_verification_tests.rs` enforces six strict verification gates (plus Gate 7 release artifact & `llms-full.txt` bundle synchronization):

1. **Gate 1 — 100% Zero-Skip `.fasm` Corpus Compilation (`2,611` Scenarios)**:
   - Every `.fasm` file in `examples/**/*.fasm` must have `// PROMPT:` on Line 1, `// TOKENS:` on Line 2, and `// INSTRUCTION:` before every `host`, `flow`, and `compile` block (`words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50,000` bytes).
   - Every file must pass `frameassembly::parser::parse_program(&content)`, `frameassembly::parser::validate_semantics(&program, &content)`, and `frameassembly::backend::generate_pcap(&program, path)` with **zero ignored errors**, emitting a PCAPNG file (`>= 28` bytes) starting with Section Header Block magic `0x0A0D0D0A`.
2. **Gate 2 — Strict `// TOKENS:` Lexer Stream Bijection**:
   - Tokenize the body of each `.fasm` file using `logos::Logos` (`frameassembly::lexer::Token::lexer`) and verify that every keyword token listed in `// TOKENS:` on Line 2 corresponds to a real strict-lowercase `[a-z0-9]+` keyword `Token` emitted by `src/lexer/mod.rs` (immediately catching hallucinated or legacy keywords like `ipv4`, `ipv6`, `send`, `sport`, `dport`, `req_id`, `loop`, or uppercase tokens).
3. **Gate 3 — Markdown & Rustdoc Fenced-Block Compilation**:
   - Scan `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `llms.txt`, `docs/*.md`, `contrib/**/*.md`, `.agents/skills/**/*.md`, and `src/**/*.rs` for all ```` ```frameassembly ```` and ```` ```fasm ```` code blocks.
   - Every block must be a complete v2.0.0 program (`host` + `flow` + `compile`, strict lowercase keywords without `_` or `-`, and zero `loop` blocks) that passes `parse_program(snippet)`, `validate_semantics(&prog, snippet)`, and `compile_program(&prog)`.
4. **Gate 4 — Six-Way Grammar, IDE & WASM Lockstep + Non-Terminal Resolution**:
   - Verify that every strict-lowercase `[a-z0-9]+` keyword `#[token("...")]` in `src/lexer/mod.rs` (`>= 640` keywords, zero `_`, zero `-`, no `ignore(ascii_case)`, no `Token::Loop`) is present in `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, that `frameassembly-wasm` exposes current compiler diagnostics/PCAPNG bytes, that every referenced non-terminal on the RHS of `grammar.ebnf` and `frameassembly.gbnf` is defined on the LHS, and that `frameassembly.lark` includes contextual lowercase keywords in `str_or_ident`.
5. **Gate 5 — Link, Orphan, `//!` Word-Count & `< 50 KB` Rust Source Hygiene**:
   - Assert every relative link `[...](path)` resolves on disk, `docs/` contains the exact 13 canonical guides with zero orphans, zero `0x00` NUL bytes exist, every file in `src/**/*.rs`, `tests/*.rs`, and `examples/**/*.fasm` satisfies `size < 50,000` bytes, and every file in `docs/*.md`, `src/**/*.rs`, and `tests/*.rs` (`//!` module header) satisfies `words >= 50` (OpenCoder `opc_data_filtering`).
6. **Gate 6 — AST `*Spec` Fields Wired to Wire Builders**:
   - Inspect every `pub` field on every protocol `*Spec` struct (plus `TcpOptions` and `SctpParams`, `>= 75` structs and `>= 500` fields) in `src/ast/{l2,l3,l4,l7}/*.rs` and verify that each field is referenced by its corresponding wire builder (`src/builders/{l2,l3,l4,l7}/*.rs`), `src/packet.rs`, or `src/backend/`, preventing dead AST fields.

---

### 2.3 Modern Rust 1.89–1.99.1 QA Tooling (`assert_matches!`, `File::lock`, `build.warnings`, `proptest`, `cargo-mutants`, `cargo-nextest`, `tshark`)

1. **Rust 1.89–1.99.1 Standard Library & Cargo QA Enhancements**:
   - **`std::assert_matches::assert_matches!` & `debug_assert_matches!` (Stabilized in Rust 1.96)**: Replace verbose `match` / `if let` boilerplate when asserting `CompilerError` variants, AST node shapes, or parser outputs.
   - **`std::fs::File::lock()` / `lock_shared()` / `try_lock()` (Stabilized in Rust 1.89)**: Use native OS advisory locks in integration tests that coordinate shared fixture files across test binaries without external locking crates.
   - **Cargo `build.warnings = "deny"` (Stabilized in Rust 1.97)**: Configure `[build] warnings = "deny"` (or `CARGO_BUILD_WARNINGS=deny` in CI) so compiler and rustdoc warnings fail the build cleanly without fragile `RUSTFLAGS` overrides.
2. **Property-Based AST & Round-Trip Testing (`proptest` + `proptest-regressions/`)**:
   - Use `proptest!` to synthesize randomized IPv4/IPv6 host pairs, valid port numbers (`1..=65535`), sequence/acknowledgment numbers (`0..=u32::MAX`), VLAN tags (`1..=4094`), and protocol payloads, plus PCAP-to-`.fasm` decompilation (`src/reverse/`, emitting `host1`, `host2`, strict lowercase keywords without `_`, and direct flow invocations without `loop`) round-trip invariants.
   - Always track `proptest-regressions/` files in Git so discovered edge-case seeds replay deterministically on every `cargo test` run.
3. **Targeted Diff & Module Mutation Testing (`cargo-mutants`)**:
   - Run targeted mutation campaigns on wire builders, parsers, semantic validators, and USM cryptography, or scope directly to a PR/commit diff using `--in-diff`:
     ```bash
     git diff origin/main...HEAD > temp/changes.diff
     cargo mutants --in-diff temp/changes.diff
     cargo mutants -f src/packet.rs -f src/parser/validation.rs -f src/builders/l7/snmp/crypto.rs
     ```
   - Annotate pure diagnostic display helpers with `#[mutants::skip]`.
4. **Fast Parallel Runner, Doctest Coverage & Semver Gates (`cargo-nextest`, `cargo-llvm-cov`, `cargo-semver-checks`)**:
   - Run isolated parallel test processes with `cargo nextest run`, enforce `>= 90%` line coverage including Edition 2024 merged doctests (`--doctests`), and verify zero accidental public API breakage:
     ```bash
     cargo nextest run --all-targets
     cargo llvm-cov --all-targets --doctests --workspace --fail-under-lines 90
     cargo semver-checks check-release
     ```
5. **External Wireshark (`tshark`) Dissector Gate**:
   - Validate compiled `.pcap` / `.pcapng` outputs against Wireshark's official protocol dissectors (`tshark -r capture.pcap -V`) to verify zero `[Malformed Packet]`, `[Bogus ... length]`, or `[Bad Checksum]` expert info warnings across all 81 protocols.

---

### 2.4 Edition 2024 Doctest Optimization (`cargo test --doc`)
In Rust 1.85+ Edition 2024, doctests are compiled into a unified single binary:
- **Executable Rust API Doctests**: Top-level library modules (`src/lib.rs`, `src/lexer/mod.rs`, `src/parser/mod.rs`, `src/backend/mod.rs`, `src/pcap.rs`) should include runnable ```` ```rust ```` doctests verifying programmatic compilation (`parse_program`, `validate_semantics(&prog, src)`, `compile_program`).
- **Strict Syntax Annotation for `.fasm` Code Blocks**: Code blocks representing FrameAssembly `.fasm` code must use explicit tags with complete, compilable v2.0.0 strict-lowercase `host` + `flow` + `compile` structure (never put intentionally invalid syntax inside ````fasm` or ````frameassembly` fences—use ````text` for invalid anti-examples):
  ````markdown
  ```frameassembly
  host client { ip 192.168.1.10 mac 00:11:22:33:44:55 }
  host server { ip 192.168.1.20 mac 00:aa:bb:cc:dd:ee }
  flow ping_check(src, dst) {
      src -> dst icmp echorequest id 1 seq 1
      src <- dst icmp echoreply id 1 seq 1
  }
  compile {
      ping_check(client, server)
  }
  ```
  ````

---

### 2.5 Token-Safe Multi-Agent Wave Orchestration & `.agents/scripts/file_lock.sh` Workflow
When executing repository-wide QA or parallel multi-agent edits across FrameAssembly:
1. **Acquire Disjoint File Locks First (`.agents/scripts/file_lock.sh`)**:
   - Every parallel worker must acquire a lease lock on its assigned file partition before modifying any file and release it upon completion:
     ```bash
     .agents/scripts/file_lock.sh acquire worker_id 600 <file1> <file2> ...
     # ... perform edits ...
     .agents/scripts/file_lock.sh release worker_id <file1> <file2> ...
     ```
   - To prevent Cargo `target/` directory lock contention when multiple agents need to run `cargo check` or `cargo test`, either defer `cargo test` to the lead orchestrator after all workers release their locks or wrap Cargo invocations in `.agents/scripts/file_lock.sh exec cargo-target -- cargo test`.
2. **Disjoint Wave Partitioning**:
   - **Wave 1 (Compiler & 81 Builders)**: Partition across parallel subagents with strictly disjoint file ownership (`1A`: Core/Lexer/Parser/CLI/SNMP; `1B`: Backend & L2/L3/L4; `1C`: L7 Infra/Telemetry/Mail/Auth; `1D`: L7 Web/Cloud/Security/VoIP; `1E`: L7 Storage/DB/Messaging/OT).
   - **Wave 2 (6-Way Grammars, IDE/WASM, Rustdoc & Docs)**: Partition across parallel subagents for (a) 6-way grammars (`grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, `frameassembly.tmLanguage.json`, `frameassembly-wasm`), (b) AST `/// Syntax mapping:` docstrings, and (c) `docs/*.md` + `README.md` + metadata files.
   - **Wave 3 (Test Chunking `< 50 KB`, Wire Regressions, Gates 1–6 & `llms-full.txt`)**: Partition across parallel subagents for test splitting, wire regression assertions, `corpus_verification_tests.rs` Gates 1–6, and scripted `llms-full.txt` synchronization.
3. **Compact Return Summaries & `/compact` State Persistence**: Require subagents to return concise bulleted summaries (`<= 60` lines) and record wave completion in a persistent checkpoint artifact.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable production implementations:
1. **Multi-Tier Test Architecture Implementation (Tiers 1–4 with Rust 1.96+ `assert_matches!` & Rust 1.89+ `File::lock`)**
2. **Six-Gate Corpus (`2,611` Files), Lexer Bijection, Markdown Block & AST `*Spec`-to-Builder Wiring Engine (`tests/corpus_verification_tests.rs`)**
3. **Automated 6-Way Grammar Lockstep & Non-Terminal Resolution Test Template (`EBNF`, `GBNF`, `Lark`, `TextMate`)**
4. **Property-Based Compiler Round-Trip Testing (`proptest` + `proptest-regressions/`) & External Wireshark (`tshark`) Dissector Gate**
5. **Mutation Testing (`cargo-mutants --in-diff`), Doctest Coverage (`cargo-llvm-cov --doctests`), Semver (`cargo-semver-checks`) & `.agents/scripts/file_lock.sh` Workflow**
