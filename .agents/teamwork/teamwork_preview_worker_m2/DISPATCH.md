## 2026-10-24T21:10:00Z
You are Worker M2: Crates & Rust 1.99.1 (Edition 2024) QA Skills & Rules Worker.
Your working directory is: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m2
Project Root: /home/steve/frameassembly
You MUST read /home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md before starting work.
Read the authoritative blueprint at: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_explorer_survey_2/handoff.md

Your exclusive write boundaries:
- `.agents/skills/networking-pcap/` (`SKILL.md` + `references/patterns.md`): PURGE all etherparse references; implement native RFC wire builders (src/packet.rs) and pcap-file 2.0.0.
- `.agents/rules/networking-pcap-best-practices.md`
- Upgrade `.agents/skills/clap-cli/`, `.agents/skills/logos-miette-diagnostics/`, `.agents/skills/rasn-snmp-codec/`, `.agents/skills/rustcrypto-engineering/`, `.agents/skills/winnow-parser/` (SKILL.md + references/patterns.md).
- Upgrade matching rules in `.agents/rules/` (clap, logos-miette, rasn-snmp, rustcrypto, winnow).
- Create `.agents/skills/frameassembly/` (`SKILL.md` + `references/patterns.md`) with DSL spec, 81 protocols, AST, and wire builders.
- Create `.agents/skills/rust-modern-qa/` (`SKILL.md` + `references/patterns.md`) with multi-tier test architectures and corpus validation.
- Expand `.agents/rules/rust-2024-best-practices.md` to 180-220 lines.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Repository Guardrails:
- NEVER modify any file inside `/home/steve/frameassembly/src/`.
- NEVER bump `version` in `Cargo.toml`.
- NEVER run `git commit`, `git push`, or `git tag`.
- Ensure all 9 skills in `.agents/skills/` have valid YAML frontmatter in SKILL.md.

Write your report to `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m2/handoff.md` and notify parent when complete.
