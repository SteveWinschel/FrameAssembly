---
trigger: always_on
description: "Token-budget conservation, 20k rules budget discipline, 3-layer parallel multi-agent file locking (.agents/scripts/file_lock.sh + PreToolUse hook), subagent context isolation, and /compact checkpoint persistence."
---

# Token Budget, Context Window & Multi-Agent File-Locking Rule

## 1. Antigravity Rules Budget & 3-Tier Progressive Skill Disclosure
- **20,000-Token Rules Budget Discipline**: Antigravity enforces a `20,000`-token `defaultRulesBudget` (`24,576` bytes per rule file). Reserve `trigger: always_on` strictly for universal workspace invariants (`frameassembly-dsl.md`, `versioning_and_git.md`, `temporary_files.md`, `token-and-context-efficiency.md`), and scope all crate-specific or subsystem-specific rules with `trigger: glob` (`globs: "..."`) so they load only when matching files are active.
- **Zero Global/Workspace Rule Duplication**: Never duplicate workspace rules inside `~/.gemini/config/rules/`. Global rules load first and consume the shared `20,000`-token budget before workspace rules are evaluated.
- **3-Tier Skill Progressive Disclosure**:
  1. **Discovery Metadata**: Keep YAML frontmatter (`name` + `description` with trigger keywords) concise so routing scans cost minimal tokens.
  2. **Core Instructions (`SKILL.md`, `< 25 KB`)**: Put architecture matrices, core API selection tables, and mandatory invariants in `SKILL.md`.
  3. **On-Demand Reference Templates (`references/patterns.md`, `< 50 KB`)**: Place full copy-paste production Rust templates, RFC test vectors, and extended code recipes in `references/patterns.md`, loaded via `read_file` only when implementing or debugging that subsystem.

## 2. 3-Layer Parallel Multi-Agent File Locking (`Workspace: "inherit"`)
- **Layer 1 — Disjoint Partition Assignment**: Whenever a task touches more than `8` files, partition the work across parallel subagents (`<= 16` files per subagent) with **100% disjoint file ownership**. Never assign the same file or overlapping directory glob to two concurrent subagents.
- **Layer 2 — Explicit Atomic `flock` Lease Acquisition (`.agents/scripts/file_lock.sh`)**:
  - Before editing any shared or partitioned file in a multi-agent wave, subagents must acquire an exclusive lease backed by `temp/.locks/lock_<slug>.{flock,meta}`:
    ```bash
    .agents/scripts/file_lock.sh acquire <agent-id> <ttl-secs> <file1> [file2 ...]
    ```
  - Release leases immediately after completing verification on the partition:
    ```bash
    .agents/scripts/file_lock.sh release <agent-id> <file1> [file2 ...]
    ```
  - Inspect active leases with `.agents/scripts/file_lock.sh status` and reclaim expired leases with `.agents/scripts/file_lock.sh gc`.
- **Layer 3 — Automated `PreToolUse` Hook Guard (`.agents/hooks.json`)**:
  - `.agents/hooks.json` registers `.agents/scripts/pre_tool_file_lock_guard.sh` on `edit_file|write_file|replace_file_content|multi_replace_file_content`. If another active agent holds a non-expired lease on the target path (or parent directory), the hook blocks the write (`{"decision":"block"}`) and reports the lock owner and expiration timestamp.

## 3. Zero Build-Lock Contention & Subagent Context Isolation
- **Single-Point `cargo` Verification (`__cargo_target__` Lock)**: Prohibit parallel subagents from running `cargo check`, `cargo test`, or `cargo clippy` concurrently during their edit phase (which causes `Blocking waiting for file lock on build directory` in `target/`). Either run a single consolidated `cargo` verification pass in the lead orchestrator after all subagents release their file locks, or serialize build commands through `.agents/scripts/file_lock.sh exec __cargo_target__ -- cargo test ...`.
- **No Orchestrator Bulk Reads**: Keep bulk `read_file` and `edit_file` calls inside subagent contexts so intermediate file contents never accumulate in the parent orchestrator's context window. Instruct subagents to return compact bulleted summaries (`<= 60` lines) rather than raw diffs.
- **Targeted Line-Range Reads & Scripted Concatenation**: Always use `StartLine`/`EndLine` slices when inspecting large files (`30–50 KB`), and regenerate composite bundles (`llms-full.txt`) using deterministic shell scripts rather than LLM tool arguments.
- **Staged Wave Checkpoints & `/compact` Persistence**: For multi-wave tasks, persist progress in a workspace artifact and pause between waves so the user can review or run `/compact` to reclaim context window capacity.
- **Grounded Clarification Questions (Zero Premature Bundling)**: When interviewing the user about changing an existing file or CLI interface, strictly separate **what currently exists in the codebase** from **proposed new additions**. Never embed unapproved subcommands or features into multiple-choice options as if they already exist or were already decided.


