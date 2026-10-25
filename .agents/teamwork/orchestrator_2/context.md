# Dispatch Context for Project Orchestrator (orchestrator_2)

## Request Reference
See `/home/steve/frameassembly/.agents/teamwork/ORIGINAL_REQUEST.md`, section `## 2026-10-25T14:19:19Z`.

## Working Directory
`/home/steve/frameassembly/.agents/teamwork/orchestrator_2`

## Key Constraints
- Do NOT modify any file inside `/home/steve/frameassembly/src/`.
- Do NOT modify `Cargo.toml` or `Cargo.lock`.
- All deliverables must be written exclusively to `/home/steve/frameassembly/.agents/rules/` and `/home/steve/frameassembly/.agents/skills/`.
- Do NOT run `git commit`, `git push`, or `git tag`.
- Never write literal NUL bytes (`0x00`).
- Ensure all markdown files adhere to size limits: `< 24,000` bytes for `.agents/rules/*.md`, `< 50,000` bytes and `>= 50` words for `.agents/skills/**/*.md`.
- Ensure `cargo test --test corpus_verification_tests` passes 100%.
