# Original User Request

## 2026-10-24T20:58:16Z

Optimize the `frameassembly` repository (`https://github.com/SteveWinschel/FrameAssembly`) and crate (`https://crates.io/crates/frameassembly`) for AI pre-training datasets and search engines, expand the verified `.fasm` example corpus in `examples/` to 1,200+ scenarios (~15+ per protocol directory), and exhaustively research all 17 `Cargo.toml` crates plus Rust 1.99.1 (Edition 2024) to upgrade and create QA skills and rules in `.agents/` without modifying `src/`.

Working directory: `/home/steve/frameassembly`
Integrity mode: development

## Verification Resources

- Corpus verification suite: `cargo test --test corpus_verification_tests` (in `/home/steve/frameassembly/tests/corpus_verification_tests.rs`)
- Full test suite: `cargo test`
- Existing DSL & packaging rules: `/home/steve/frameassembly/.agents/rules/frameassembly-dsl.md` and `/home/steve/frameassembly/.agents/rules/publishing_and_docs.md`

## Requirements

### R1. AI Training Data & Search Engine Optimization (Web Research + Repo Optimization + Skills/Rules)
Conduct exhaustive web research on how open-source repositories, crates, and custom DSLs are discovered, filtered, scored, and ingested by LLM pre-training pipelines (The Stack v2, FineWeb, Dolma, StarCoder2, Qwen2.5-Coder, DeepSeek-Coder), AI code assistants/RAG indexers (`llms.txt`, Context7, Docs.rs/Crates.io crawlers), and search engines. Using these findings:
1. Create `.agents/skills/ai-seo-training-data/` (`SKILL.md` + `references/patterns.md`) and `.agents/rules/ai-seo-best-practices.md`.
2. Optimize `README.md`, `llms.txt`, `llms-full.txt`, and `.gitattributes`.
3. Create chunked `docs/*.md` files (`< 50 KB` per file covering L2, L3, L4, L7, SNMP, topologies, and Q&A instruction-tuning pairs so the corpus survives `go-enry` unknown-extension and `.txt` 512-line pre-training filters), formal grammar files (`grammar.ebnf` and `frameassembly.gbnf`), `CITATION.cff`, and `AGENTS.md`.
4. Ensure `Cargo.toml`'s `exclude` list keeps heavy AI/docs files excluded from the crates.io tarball while preserving the exact `version = "1.0.1"`.

### R2. Massive Parallel Expansion of Verified `.fasm` Examples (`examples/`)
Expand the verified `.fasm` corpus across all 82 directories (`examples/l2/*`, `examples/l3/*`, `examples/l4/*`, `examples/l7/*`, `examples/l7/snmp/*`, `examples/topologies/`) to **at least 1,200 total `.fasm` examples (~15+ per protocol directory)**.
- Partition example generation across parallel coding shards by disjoint folder groups so zero file write collisions occur.
- Cover exhaustive permutations of protocol sub-keywords, L2–L4 modifiers (`VLAN`, `QINQ`, `MPLS`, `TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `DF`/`MF`/`FRAGOFFSET`, TCP options), transport overrides, timing patterns (`WAIT`), `LOOP` blocks, dual-stack IPv4/IPv6 flows, security/IDS/anomaly tests, and cross-layer topologies.
- Enforce strict `// PROMPT:`, `// TOKENS:`, and `// INSTRUCTION:` header discipline, line-length guardrails (`avg_line_length <= 85`, `max_line_length <= 200`), and high lexical/IP/hostname diversity so every file survives MinHash LSH near-deduplication.

### R3. Exhaustive Crate & Rust 1.99.1 (Edition 2024) QA Research, Skills & Rules (`.agents/`)
Exhaustively research all 17 crates in `Cargo.toml` (`aes 0.9.3`, `block-padding 0.4.2`, `cbc 0.2.1`, `cfb-mode 0.9.1`, `clap 4.6.7`, `des 0.9.0`, `hmac 0.13.0`, `logos 0.14.3`, `md-5 0.11.0`, `miette 7.6.0`, `pcap-file 2.0.0`, `rasn 0.28.15`, `rasn-smi 0.28.15`, `rasn-snmp 0.28.15`, `sha1 0.11.0`, `sha2 0.11.0`, `winnow 1.0.4`) and the newest stable Rust language release (`1.99.1`, Edition 2024) across documentation, codebases, and forums:
1. Deeply upgrade all 6 existing skills (`clap-cli`, `logos-miette-diagnostics`, `networking-pcap` [updating stale `etherparse` assumptions to match native RFC wire builders + `pcap-file 2.0.0`], `rasn-snmp-codec`, `rustcrypto-engineering`, `winnow-parser`) and their matching `.agents/rules/*-best-practices.md` files.
2. Populate `.agents/skills/frameassembly/` (`SKILL.md` + `references/patterns.md`).
3. Create `.agents/skills/rust-modern-qa/` (`SKILL.md` + `references/patterns.md`) and expand `.agents/rules/rust-2024-best-practices.md`.

### R4. Hard Repository Guardrails
- Do NOT modify any file inside `/home/steve/frameassembly/src/`.
- Do NOT bump the `version` field in `/home/steve/frameassembly/Cargo.toml`.
- Do NOT run `git commit`, `git push`, or `git tag`.

## Acceptance Criteria

### Corpus & Compilation Verification
- [ ] Total `.fasm` file count in `examples/` is `>= 1,200`, with every one of the 81 protocol folders (and `topologies/`) containing `>= 14–15+` `.fasm` scenarios.
- [ ] `cargo test --test corpus_verification_tests` and `cargo test` pass with 0 failures and 0 warnings.
- [ ] Every `.fasm` file has `// PROMPT:` on line 1, `// TOKENS:` on line 2, `// INSTRUCTION:` before every block, `avg_line_length <= 85`, and `max_line_length <= 200`.

### AI/SEO & Documentation Verification
- [ ] `README.md`, `llms.txt`, `llms-full.txt`, `AGENTS.md`, `CITATION.cff`, `grammar.ebnf`, `frameassembly.gbnf`, and `docs/*.md` exist, contain zero NUL bytes (`0x00`), have `docs/*.md` chunks strictly `< 50 KB` each, and accurately reflect the final reconciled example counts across all layers.

### Customizations & Guardrail Verification
- [ ] All 9 skills in `.agents/skills/` (`ai-seo-training-data`, `clap-cli`, `frameassembly`, `logos-miette-diagnostics`, `networking-pcap`, `rasn-snmp-codec`, `rust-modern-qa`, `rustcrypto-engineering`, `winnow-parser`) contain valid YAML frontmatter in `SKILL.md` and comprehensive `references/patterns.md` guides.
- [ ] `git diff src/` is completely empty, and `Cargo.toml` `version` remains `"1.0.1"`.

## 2026-10-25T13:21:36Z

This is a single self-contained fix; keep it small and focused. Create a cross-platform `install.sh` bootstrap script for FrameAssembly (`frameassembly`) that installs missing system prerequisites (`curl` and a C linker), installs Rust/Cargo via `rustup`, and installs `frameassembly` via `cargo`, along with updating `README.md` and repository metadata files.

Working directory: /home/steve/frameassembly
Integrity mode: development

Reference links:
- Crates.io: https://crates.io/crates/frameassembly
- GitHub Repository: https://github.com/SteveWinschel/FrameAssembly

## Requirements

### R1. Cross-Platform `install.sh` Bootstrap Script
Provide a POSIX-compliant, executable `install.sh` script at the repository root that:
1. Detects and installs `curl` and a system C compiler/linker (`cc` / `gcc` / `clang`) if missing, supporting major cross-platform package managers (`apt-get`, `dnf`, `yum`, `pacman`, `apk`, `zypper`, `xbps-install`, `emerge`, `nix-env`, `pkg`, `pkg_add`, `pkgin`, `opkg`, `brew`, `port`, `winget`, `choco`, `scoop`) with automatic privilege escalation (`sudo`, `doas`, `su -c`, or running as `root`).
2. Installs the Rust toolchain (`rustup` and `cargo`) via `https://sh.rustup.rs` (`-y`) if `cargo` is not already installed, and sources `"$HOME/.cargo/env"` into `PATH`.
3. Installs `frameassembly` from `crates.io` (`cargo install frameassembly`) by default, while supporting a `--local` flag to install from the local repository checkout (`cargo install --path .`) and a `--help` / `-h` flag for usage instructions.
4. Verifies the installed `frameassembly` binary (`frameassembly --version`).

### R2. Repository Documentation, Packaging & Hygiene Updates
Update the surrounding repository files so documentation, packaging, and AI discovery metadata stay synchronized:
1. Update `README.md` ("Getting Started" / "Installation") to document the one-liner (`curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh`) as well as `./install.sh` and `./install.sh --local`, while ensuring `README.md` remains strictly `< 50,000` bytes.
2. Add `"install.sh"` to the `exclude` list in `Cargo.toml` so the `crates.io` tarball remains lean (do NOT bump the `version` field in `Cargo.toml`, and do NOT run `git commit`, `git push`, or `git tag`).
3. Add `*.sh text eol=lf` to `.gitattributes` so `install.sh` always uses LF line endings across all platforms.
4. Update `AGENTS.md`, `CLAUDE.md`, and `llms.txt` to mention `install.sh` where appropriate, and remove the stray 0-byte `=` file in the repository root.

## Acceptance Criteria

### Script Verification
- [ ] `install.sh` exists at `/home/steve/frameassembly/install.sh`, is executable (`-x`), and passes `sh -n install.sh` and `bash -n install.sh` with zero warnings or syntax errors.
- [ ] Running `./install.sh --help` prints usage instructions and exits with status `0`.
- [ ] `install.sh` handles missing `curl`, missing `cc` linker, missing `cargo` (`rustup`), default `cargo install frameassembly`, and `--local` (`cargo install --path .`).

### Repository & Test Suite Verification
- [ ] `README.md` documents `install.sh` and its total size is strictly `< 50,000` bytes (`wc -c < README.md`) with zero NUL (`0x00`) bytes.
- [ ] `Cargo.toml` includes `"install.sh"` in `exclude` and keeps `version = "1.0.1"` unchanged.
- [ ] `.gitattributes` includes `*.sh text eol=lf`.
- [ ] The stray 0-byte `=` file in `/home/steve/frameassembly` is removed.
- [ ] `cargo test` passes completely with zero failures.
## 2026-10-25T14:19:19Z

Use a very large team of agents. Exhaustively research all direct and transitive crates in `/home/steve/frameassembly/Cargo.toml` and `/home/steve/frameassembly/Cargo.lock`, the latest stable Rust toolchain (`1.85` through `1.99.1+` Edition 2024), wire-level RFC invariants across all 81 L2–L7 protocols, external dissector verification (`tshark` / `tcpdump` / `Suricata` / `Zeek`), constrained decoding grammars (`EBNF`, `llama.cpp`/`XGrammar` `GBNF`, `llguidance`/`Outlines` `Lark`, VS Code TextMate), and AI/SEO pre-training dataset filters to deeply upgrade all 12 rules in `.agents/rules/*.md`, all 9 existing skills in `.agents/skills/*`, and create a new 10th skill `.agents/skills/rust-2024-idioms/`, while keeping `/home/steve/frameassembly/src` **100% unchanged**.

Working directory: `/home/steve/frameassembly`
Integrity mode: `development`

## Requirements

### R1. Strict Preservation of `src/` (Zero Source Code Changes)
Do NOT modify any file inside `/home/steve/frameassembly/src/`, `Cargo.toml`, or `Cargo.lock`. All deliverables must be written exclusively to `/home/steve/frameassembly/.agents/rules/` and `/home/steve/frameassembly/.agents/skills/`.

### R2. Exhaustive Crate & Rust 1.85–1.99.1+ Research & Skill/Rule Upgrades
Research all 17 direct dependencies (`aes 0.9.3`, `block-padding 0.4.2`, `cbc 0.2.1`, `cfb-mode 0.9.1`, `clap 4.6.7`, `des 0.9.0`, `hmac 0.13.0`, `logos 0.14.3/0.14.4`, `md-5 0.11.0`, `miette 7.6.0`, `pcap-file 2.0.0`, `rasn 0.28.15`, `rasn-smi 0.28.15`, `rasn-snmp 0.28.15`, `sha1 0.11.0`, `sha2 0.11.0/0.11.1`, `winnow 1.0.4`), key transitive crates in `Cargo.lock` (`anstream 1.0.0`, `anstyle 1.0.14`, `clap_builder 4.6.7`, `clap_lex 1.1.1`, `cipher 0.5.2`, `digest 0.11.3`, `crypto-common 0.2.2`, `inout 0.2.5`, `hybrid-array 0.4.15`, `typenum 1.20.1`, `ctutils 0.4.5`, `cmov 0.5.4`, `const-oid 0.10.2`, `cpufeatures 0.3.1`, `bitvec 1.1.1`, `bytes 1.12.1`, `num-bigint 0.4.8`, `chrono 0.4.45`, `memchr 2.8.3`, `owo-colors 4.4.0`, `textwrap 0.16.4`, `thiserror 1.0.69`, `snafu 0.8.9`, `displaydoc 0.2.7`, `byteorder 1.5.0`, `byteorder_slice 3.0.0`, `derive-into-owned 0.2.0`), and stable Rust `1.85`–`1.99.1+` features (Edition 2024, `let` chains, `if let` guards, `+ use<...>`, `as_chunks`, `as_array`, `array_windows`, `get_disjoint_mut`, `Atomic<T>`, `LazyLock`, `unsafe extern "C"`, `safe fn`, `&raw const/mut`, Cargo `resolver = "3"`, `[lints]`, merged doctests, `rustdoc` SEO, and Clippy `pedantic`/`nursery`/`cargo` lints).

### R3. Upgrade All 9 Existing Skills + Create New `rust-2024-idioms` Skill
1. Create `.agents/skills/rust-2024-idioms/` (`SKILL.md`, `references/patterns.md`, `references/rust_185_to_199_changelog.md`, `scripts/audit_rust_2024_idioms.sh`) covering Rust 1.85–1.99.1+ language idioms, std/core APIs, Clippy lints, Cargo manifests, and `rustdoc` optimization.
2. Upgrade all 9 existing skills (`winnow-parser`, `logos-miette-diagnostics`, `clap-cli`, `rasn-snmp-codec`, `rustcrypto-engineering`, `networking-pcap`, `frameassembly`, `rust-modern-qa`, `ai-seo-training-data`) with:
   - Complete `references/*.md` files (fixing missing templates 3–5 in `rust-modern-qa/references/patterns.md`, adding `references/protocol_rfc_matrix.md` covering all 81 L2–L7 protocols, adding transitive crate guides, and adding external `tshark`/`tcpdump` wire-dissector QA patterns).
   - Executable read-only QA helper scripts in `scripts/*.sh` (`chmod +x`) for future QA runs.

### R4. Upgrade All 12 Rules & Fix Context Budget / Syntax Drift (`agy-customizations`)
1. Add proper `agy-customizations` YAML frontmatter (`trigger: glob` or `trigger: model_decision` with `description`) to domain-specific rules in `.agents/rules/*.md` so `always_on` rules stay well under the `20,000`-token `defaultRulesBudget` and every rule file is strictly `< 24,000` bytes.
2. Fix the syntax contradiction in `.agents/rules/frameassembly-dsl.md` (`WAIT <int><unit>` is a valid inline statement modifier; ban standalone `WAIT` lines and ban hallucinated `+5ms` / `[+delay]` prefixes).
3. Update corpus counts (`2,600+` `.fasm` files across 81 protocols + topologies) and Five-Way Grammar Lockstep (`src/lexer/mod.rs`, `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, plus VS Code TextMate `frameassembly.tmLanguage.json`).

## Acceptance Criteria

### Programmatic & Structural Verification Gates
- [ ] `git status --porcelain src/ Cargo.toml Cargo.lock` is completely empty (`src/`, `Cargo.toml`, and `Cargo.lock` are 100% untouched).
- [ ] All 10 skills in `.agents/skills/` (`ai-seo-training-data`, `clap-cli`, `frameassembly`, `logos-miette-diagnostics`, `networking-pcap`, `rasn-snmp-codec`, `rust-2024-idioms`, `rust-modern-qa`, `rustcrypto-engineering`, `winnow-parser`) have valid `SKILL.md` YAML frontmatter (`name`, `description`), `references/patterns.md`, and executable read-only `scripts/*.sh` where applicable.
- [ ] Every file in `.agents/skills/**/*.md` is strictly `< 50,000` bytes (`50 KB`) and `>= 50` words; every file in `.agents/rules/*.md` is strictly `< 24,000` bytes (`24 KB`); and zero files contain literal NUL bytes (`0x00`).
- [ ] `cargo test --test corpus_verification_tests` passes 100% (verifying that every ````frameassembly` and ````fasm` code block inside `.agents/skills/**/*.md` compiles cleanly with zero errors).
