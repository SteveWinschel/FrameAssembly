## 2026-10-24T21:10:01Z

You are Worker M3 Shard 7: Corpus Expansion for L7 Security, Remote Access, Utilities & Line-Length Normalization.
Your working directory is: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard7
Project Root: /home/steve/frameassembly
You MUST read /home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md before starting work.
Read the sharding plan at: /home/steve/frameassembly/.agents/teamwork/teamwork_preview_explorer_survey_1/handoff.md §3 Shard 7

Your exclusive write boundaries:
- `examples/l7/smtp/` (12 new .fasm files -> 15 total)
- `examples/l7/ssdp/` (12 new .fasm files -> 15 total)
- `examples/l7/ssh/` (12 new .fasm files -> 15 total)
- `examples/l7/stun/` (12 new .fasm files -> 15 total)
- `examples/l7/syslog/` (12 new .fasm files -> 15 total)
- `examples/l7/tacacs/` (12 new .fasm files -> 15 total)
- `examples/l7/telnet/` (12 new .fasm files -> 15 total)
- `examples/l7/tftp/` (12 new .fasm files -> 15 total)
- `examples/l7/tls/` (12 new .fasm files -> 15 total)
- `examples/l7/websocket/` (12 new .fasm files -> 15 total)
- `examples/l7/whois/` (12 new .fasm files -> 15 total)
Total new files: 132 new verified .fasm files.
Line-length normalization:
- Wrap long lines in the 51 files across `examples/l7/snmp/snmpv1/` (10 files), `examples/l7/snmp/snmpv2c/` (13 files), `examples/l7/snmp/snmpv3/` (20 files), and `examples/topologies/` (8 files) so all lines satisfy `avg_line_length <= 85` and `max_line_length <= 200`. Use 4-space indentation when splitting VARBIND or multi-parameter statements.

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

Write your report to `/home/steve/frameassembly/.agents/teamwork/teamwork_preview_worker_m3_shard7/handoff.md` and notify parent when complete.
