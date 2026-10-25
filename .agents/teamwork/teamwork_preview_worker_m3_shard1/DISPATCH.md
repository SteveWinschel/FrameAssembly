## 2026-10-24T21:10:00Z
You are Worker M3 Shard 1: Corpus Expansion for L2 & L4 SCTP.
Your working directory is: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard1
Project Root: /home/steve/frameassembly
You MUST read /home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md before starting work.
Read the sharding plan at: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_explorer_survey_1/handoff.md §3 Shard 1

Your exclusive write boundaries:
- `examples/l2/eapol/` (generate 12 new .fasm files -> 15 total)
- `examples/l2/lacp/` (generate 12 new .fasm files -> 15 total)
- `examples/l2/lldp/` (generate 12 new .fasm files -> 15 total)
- `examples/l2/mpls/` (generate 12 new .fasm files -> 15 total)
- `examples/l2/qinq/` (generate 12 new .fasm files -> 15 total)
- `examples/l2/stp/` (generate 12 new .fasm files -> 15 total)
- `examples/l2/vlan/` (generate 12 new .fasm files -> 15 total)
- `examples/l4/sctp/` (generate 11 new .fasm files -> 15 total)
Total: 95 new verified .fasm files.

Requirements for each file:
- Line 1: `// PROMPT: <scenario description>`
- Line 2: `// TOKENS: <comma-separated tokens>`
- Line 3+: `// INSTRUCTION: <block description>` before every block (HOST, FLOW, COMPILE)
- Non-numeric naming (e.g. `eapol_tls_handshake.fasm`, NOT `04_eapol.fasm`)
- Line length: `avg_line_length <= 85` and `max_line_length <= 200`
- High lexical, IP, and hostname diversity (defeats MinHash LSH deduplication)
- Zero syntax errors: verify with `cargo test --test corpus_verification_tests`

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Repository Guardrails:
- NEVER modify any file inside `/home/steve/frameassembly/src/`.
- NEVER bump `version` in `Cargo.toml`.
- NEVER run `git commit`, `git push`, or `git tag`.

Write your report to `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard1/handoff.md` and notify parent when complete.
