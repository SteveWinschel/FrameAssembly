## 2026-10-25T14:22:33Z
[Message] timestamp=2026-10-25T14:22:33Z sender=f0e4cf46-ddf0-4dfb-bd39-ca7c67c506fe priority=MESSAGE_PRIORITY_HIGH content=You are the Rules & Grammar Surveyor (teamwork_preview_explorer).
Your working directory is `/home/steve/frameassembly/.agents/teamwork/explorer_survey_rules/`.
Read `/home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md` (specifically section `## 2026-10-25T14:19:19Z`) and `/home/steve/frameassembly/.agents/teamwork/orchestrator_2/context.md`.

YOUR MISSION:
Exhaustively survey all 12 existing rule files in `/home/steve/frameassembly/.agents/rules/*.md`:
1. Inspect each rule file, its current size, line count, and current YAML frontmatter.
2. Check against the requirements:
   - Must have proper `agy-customizations` YAML frontmatter:
     - Determine which rules should be `trigger: always_on` vs `trigger: glob` vs `trigger: model_decision` with clear description so always_on rules stay well under the 20,000-token `defaultRulesBudget`.
     - Strict file size limit: each rule file must be strictly `< 24,000` bytes (< 24 KB).
   - In `/home/steve/frameassembly/.agents/rules/frameassembly-dsl.md`:
     - Detail the syntax contradiction regarding `WAIT`: `WAIT <int><unit>` is a valid inline statement modifier (e.g., `s1 -> s2 TCP WAIT 10ms SYN`); ban standalone `WAIT` lines and ban hallucinated `+5ms` / `[+delay]` prefixes.
     - Document where and how this must be corrected.
   - Update corpus counts in rules from old numbers (e.g., 1,200) to `2,600+` `.fasm` files across all 81 protocols + topologies.
   - Document Five-Way Grammar Lockstep across:
     1) `src/lexer/mod.rs`
     2) `src/parser/`
     3) `grammar.ebnf`
     4) `frameassembly.gbnf`
     5) `frameassembly.lark`
     plus VS Code TextMate `frameassembly.tmLanguage.json`.
3. Check for any literal NUL bytes (`0x00`) or formatting anomalies in existing rules.

HARD CONSTRAINTS:
- You are read-only. Do NOT modify any file outside your directory `/home/steve/frameassembly/.agents/teamwork/explorer_survey_rules/`.
- Do NOT touch `src/`, `Cargo.toml`, or `Cargo.lock`.
- Deliver your comprehensive survey report to `/home/steve/frameassembly/.agents/teamwork/explorer_survey_rules/survey_report.md` and write a standard `handoff.md` in your directory.
- Use `send_message` to report your completion back to your caller (orchestrator_2).
