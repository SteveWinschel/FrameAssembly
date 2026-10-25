---
trigger: always_on
description: "Token-budget conservation, subagent context isolation, disjoint parallel file ownership, and /compact checkpoint persistence."
---

# Token Budget, Context Window & Multi-Agent Orchestration Rule

## 1. Subagent Context Isolation & Disjoint File Ownership
- **Delegate Multi-File Sweeps to Subagents**: Whenever a task touches more than `8` files (e.g., auditing 81 protocol builders, updating AST docstrings, or synchronizing `docs/*.md`), partition the work across parallel `self` or `research` subagents (`<= 16` files per subagent) with **100% disjoint file ownership**.
- **No Orchestrator Bulk Reads**: Keep bulk `view_file` and `replace_file_content` calls inside subagent contexts so intermediate file contents never accumulate in the parent orchestrator's context window.
- **Concise Subagent Return Summaries**: Instruct every subagent to return a compact bulleted summary (`<= 60` lines) of modified files and fixes—never full file contents or raw diffs.

## 2. Zero Build-Lock Contention & Targeted File Slicing
- **Single-Point `cargo` Verification**: When multiple subagents edit files concurrently in `Workspace: "inherit"`, prohibit subagents from running `cargo check`, `cargo test`, or `cargo clippy` during their edit phase (preventing `target/` lock contention and mid-edit compile failures). Run a single consolidated `cargo` verification pass in the lead orchestrator after the wave completes.
- **Targeted Line-Range Reads**: Always use `grep_search` or `view_file` with `StartLine`/`EndLine` slices when inspecting large files rather than reading entire `40–50 KB` files repeatedly.
- **Scripted Bulk File Generation**: Regenerate large composite files (such as `llms-full.txt`) using deterministic shell/script concatenation rather than emitting hundreds of kilobytes through LLM tool call arguments.

## 3. Staged Wave Checkpoints & `/compact` State Persistence
- **Persistent Wave Tracker Artifact**: For multi-wave tasks, maintain a persistent progress artifact (`qa_wave_progress.md`) recording completed items, remaining waves, and verification status.
- **`/compact` Checkpoint Handoffs**: Pause between waves after running verification gates so the user can review progress and optionally run `/compact` to reclaim context window capacity without losing state.
