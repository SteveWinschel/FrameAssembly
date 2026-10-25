## 2026-10-24T21:10:01Z
You are Worker M3 Shard 6: Corpus Expansion for L7 Media, Storage, Redundancy & Databases.
Your working directory is: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard6
Project Root: /home/steve/frameassembly
You MUST read /home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md before starting work.
Read the sharding plan at: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_explorer_survey_1/handoff.md §3 Shard 6

Your exclusive write boundaries:
- `examples/l7/pop3/` (12 new .fasm files -> 15 total)
- `examples/l7/postgres/` (12 new .fasm files -> 15 total)
- `examples/l7/ptp/` (12 new .fasm files -> 15 total)
- `examples/l7/quic/` (12 new .fasm files -> 15 total)
- `examples/l7/radius/` (12 new .fasm files -> 15 total)
- `examples/l7/redis/` (12 new .fasm files -> 15 total)
- `examples/l7/rtp/` (12 new .fasm files -> 15 total)
- `examples/l7/rtsp/` (12 new .fasm files -> 15 total)
- `examples/l7/s7comm/` (12 new .fasm files -> 15 total)
- `examples/l7/sflow/` (12 new .fasm files -> 15 total)
- `examples/l7/sip/` (12 new .fasm files -> 15 total)
- `examples/l7/smb/` (12 new .fasm files -> 15 total)
Total: 144 new verified .fasm files.

Requirements for each file:
- Line 1: `// PROMPT: <scenario description>`
- Line 2: `// TOKENS: <comma-separated tokens>`
- Line 3+: `// INSTRUCTION: <block description>` before every block
- Non-numeric naming
- Line length: `avg_line_length <= 85` and `max_line_length <= 200`
- High lexical, IP, and hostname diversity
- Zero syntax errors: verify with `cargo test --test corpus_verification_tests`

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Repository Guardrails:
- NEVER modify any file inside `/home/steve/frameassembly/src/`.
- NEVER bump `version` in `Cargo.toml`.
- NEVER run `git commit`, `git push`, or `git tag`.

Write your report to `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard6/handoff.md` and notify parent when complete.
