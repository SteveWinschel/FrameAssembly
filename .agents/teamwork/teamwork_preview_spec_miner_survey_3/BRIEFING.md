# BRIEFING — 2026-10-24T21:07:30Z

## Mission
Survey and research AI SEO, pre-training data ingestion, and repo documentation to plan skills, rules, docs, grammars, and metadata specs for FrameAssembly.

## 🔒 My Identity
- Archetype: Specification Miner
- Roles: AI SEO & Docs Spec Miner, Teamwork specialist
- Working directory: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_spec_miner_survey_3
- Original parent: 580aed78-587f-435d-8769-216b74758b9e
- Milestone: Specification Mining / Survey

## 🔒 Key Constraints
- Read-only on codebase / external specs: do NOT implement source code, do not edit files outside working directory
- Do NOT touch `src/`
- NEVER bump `version` in `Cargo.toml` (must preserve `version = "1.0.1"`)
- NEVER run `git commit`, `git push`, or `git tag`
- Write only to `.agents/teamwork/teamwork_preview_spec_miner_survey_3/`
- Never name any file `AGENTS.md` or `GEMINI.md` within `.agents/teamwork/`
- Docstrings / documentation for everything

## Current Parent
- Conversation ID: 580aed78-587f-435d-8769-216b74758b9e
- Updated: 2026-10-24T21:07:30Z

## Task Summary
- **What to research & plan**:
  1. LLM pre-training data ingestion pipelines (The Stack v2, FineWeb, Dolma, StarCoder2, Qwen2.5-Coder, DeepSeek-Coder), filters (go-enry, line lengths, deduplication MinHash LSH, toxicity/quality heuristics, star thresholds, license filters).
  2. AI code assistants & RAG indexers (`llms.txt`, Context7, Docs.rs/Crates.io crawlers, Cursor, Copilot, Cody).
  3. Search engines & indexers (Google, Bing, GitHub search, Crates.io metadata, lib.rs).
  4. Repository artifacts analysis: existing `README.md`, `llms.txt`, `llms-full.txt`, `.gitattributes`, `Cargo.toml` (`exclude` list).
  5. Specification and architecture plan for `.agents/skills/ai-seo-training-data/` (`SKILL.md` + `references/patterns.md`) and `.agents/rules/ai-seo-best-practices.md`.
  6. Specification and architecture plan for chunked `docs/*.md` files (< 50 KB each, L2, L3, L4, L7, SNMP, topologies, Q&A instruction pairs), formal grammars (`grammar.ebnf` and `frameassembly.gbnf`), `CITATION.cff`, and root `AGENTS.md`.
- **Success criteria**: Comprehensive, authoritative handoff report in `handoff.md` with Features Discovered, Edge Cases, Observation, Logic Chain, Caveats, Conclusion, Verification Method.

## Loaded Skills
- None loaded (read-only research/spec mining role).

## Key Decisions Made
- Discovered that monolithic `.txt` files (`llms-full.txt` > 12,000 lines) are filtered out by pre-training pipelines enforcing the 512-line cap on text formats.
- Discovered that `.fasm` custom extensions are not recognized by default by `go-enry` and get pruned by language allowlists unless dual-homed in standard Markdown (`docs/*.md`).
- Designed an 11-file chunked documentation plan under `docs/` (`< 50 KB` each) to survive crawler filters and match RAG context windows (8K-16K tokens).
- Architected dual formal grammars: ISO/IEC 14977 `grammar.ebnf` for mathematical specification and llama.cpp `frameassembly.gbnf` for constrained decoding.
- Formulated exact plans for `.gitattributes`, `Cargo.toml` (`exclude` list expansion preserving `version = "1.0.1"`), `CITATION.cff` 1.2.0, root `AGENTS.md`, `.agents/skills/ai-seo-training-data/`, and `.agents/rules/ai-seo-best-practices.md`.

## Artifact Index
- `DISPATCH.md` — Initial task dispatch
- `BRIEFING.md` — Persistent state and working memory
- `progress.md` — Liveness heartbeat and milestone tracking
- `handoff.md` — Comprehensive specification mining report
