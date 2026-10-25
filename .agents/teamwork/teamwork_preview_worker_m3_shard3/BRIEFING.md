# BRIEFING — 2026-10-24T21:10:00Z

## Mission
Expand the FrameAssembly L3 corpus (Shard 3: Routing B) by generating 120 new verified, high-diversity, correctly commented .fasm files across 10 protocol subdirectories.

## 🔒 My Identity
- Archetype: teamwork_preview_worker_m3_shard3
- Roles: implementer, qa, specialist
- Working directory: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3
- Original parent: 580aed78-587f-435d-8769-216b74758b9e
- Milestone: M3 (Corpus Expansion)

## 🔒 Key Constraints
- Never modify any file inside `/home/steve/frameassembly/src/`.
- Never bump `version` in `Cargo.toml`.
- Never run `git commit`, `git push`, or `git tag`.
- Exclusive write boundaries:
  - examples/l3/ipsec/ (12 new -> 15 total)
  - examples/l3/mld/ (12 new -> 15 total)
  - examples/l3/ndp/ (12 new -> 15 total)
  - examples/l3/openflow/ (12 new -> 15 total)
  - examples/l3/ospf/ (12 new -> 15 total)
  - examples/l3/pim/ (12 new -> 15 total)
  - examples/l3/rip/ (12 new -> 15 total)
  - examples/l3/vrrp/ (12 new -> 15 total)
  - examples/l3/vxlan/ (12 new -> 15 total)
  - examples/l3/wireguard/ (12 new -> 15 total)
- File format requirements:
  - Line 1: `// PROMPT: <scenario description>`
  - Line 2: `// TOKENS: <comma-separated tokens>`
  - Line 3+: `// INSTRUCTION: <block description>` before every block
  - Strictly non-numeric naming for new files
  - Line length: `avg_line_length <= 85` and `max_line_length <= 200`
  - High lexical, IP, and hostname diversity
  - Zero syntax errors: verify with `cargo test --test corpus_verification_tests`

## Current Parent
- Conversation ID: 580aed78-587f-435d-8769-216b74758b9e
- Updated: not yet

## Task Summary
- **What to build**: 120 new `.fasm` files across 10 L3 protocol directories (12 per dir, bringing each from 3 to 15).
- **Success criteria**: All 120 files compile and pass `cargo test --test corpus_verification_tests`, comply with PROMPT/TOKENS/INSTRUCTION header & comment rules, non-numeric naming, line length limits, and high diversity.
- **Interface contracts**: FrameAssembly syntax specification, corpus verification tests.
- **Code layout**: `examples/l3/<protocol>/*.fasm`

## Key Decisions Made
- Will inspect existing 3 files in each directory first to understand exact syntax, tokens, and blocks.
- Will inspect `tests/corpus_verification_tests.rs` to understand exact verification rules and assertions.

## Artifact Index
- `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3/DISPATCH.md` — Dispatch instructions
- `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3/BRIEFING.md` — Situational awareness
- `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3/progress.md` — Liveness heartbeat
- `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3/handoff.md` — Final handoff report

## Change Tracker
- **Files modified**: None yet
- **Build status**: Untested
- **Pending issues**: None

## Quality Status
- **Build/test result**: Untested
- **Lint status**: Untested
- **Tests added/modified**: 0 / 120 new files created

## Loaded Skills
- **Source**: /home/steve/frameassembly/.agents/skills/networking-pcap/SKILL.md
  - **Local copy**: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3/skills/networking-pcap.md
  - **Core methodology**: Wire protocol specifications, headers, framing, fields, IP/routing protocol behavior
- **Source**: /home/steve/frameassembly/.agents/skills/ai-seo-training-data/SKILL.md
  - **Local copy**: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard3/skills/ai-seo-training-data.md
  - **Core methodology**: LLM pre-training dataset optimization, prompt/token annotations, formatting and diversity
