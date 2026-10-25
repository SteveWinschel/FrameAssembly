# Dispatch Log

## 2026-10-24T20:59:24Z

You are the Project Orchestrator for the frameassembly repository task.

Your working directory is: `/home/steve/frameassembly/.agents/teamwork/orchestrator_1/`
The authoritative verbatim user request is recorded in: `/home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md`
Project root: `/home/steve/frameassembly`

## Your Mission
Lead the execution of the full user request per `ORIGINAL_REQUEST.md`:
1. **R1: AI Training Data & Search Engine Optimization**:
   - Web research on LLM pre-training pipelines & AI code assistant / RAG indexing.
   - Create `.agents/skills/ai-seo-training-data/` (`SKILL.md` + `references/patterns.md`) and `.agents/rules/ai-seo-best-practices.md`.
   - Optimize `README.md`, `llms.txt`, `llms-full.txt`, and `.gitattributes`.
   - Create chunked `docs/*.md` files (< 50 KB each), formal grammar files (`grammar.ebnf` and `frameassembly.gbnf`), `CITATION.cff`, and `AGENTS.md`.
   - Update `Cargo.toml`'s `exclude` list to exclude heavy AI/docs files from crates.io tarball while preserving `version = "1.0.1"`.
2. **R2: Massive Parallel Expansion of Verified `.fasm` Examples**:
   - Expand verified `.fasm` corpus across all 82 directories (`examples/l2/*`, `examples/l3/*`, `examples/l4/*`, `examples/l7/*`, `examples/l7/snmp/*`, `examples/topologies/`) to at least 1,200 total `.fasm` examples (~15+ per protocol directory).
   - Partition work across parallel worker shards by disjoint folder groups.
   - Enforce header discipline (`// PROMPT:`, `// TOKENS:`, `// INSTRUCTION:`), line-length limits (`avg_line_length <= 85`, `max_line_length <= 200`), lexical diversity.
   - Verify with `cargo test --test corpus_verification_tests` and `cargo test`.
3. **R3: Crate & Rust 1.99.1 (Edition 2024) QA Research, Skills & Rules**:
   - Research all 17 Cargo.toml crates and Rust 1.99.1 Edition 2024.
   - Deeply upgrade all 6 existing skills (`clap-cli`, `logos-miette-diagnostics`, `networking-pcap`, `rasn-snmp-codec`, `rustcrypto-engineering`, `winnow-parser`) and their matching rules files.
   - Populate `.agents/skills/frameassembly/` (`SKILL.md` + `references/patterns.md`).
   - Create `.agents/skills/rust-modern-qa/` (`SKILL.md` + `references/patterns.md`) and expand `.agents/rules/rust-2024-best-practices.md`.
4. **Hard Repository Guardrails**:
   - NEVER modify any file inside `/home/steve/frameassembly/src/`.
   - NEVER bump `version` in `Cargo.toml` (`version = "1.0.1"` must be strictly preserved).
   - NEVER run `git commit`, `git push`, or `git tag`.
   - Write docstrings for all code.
