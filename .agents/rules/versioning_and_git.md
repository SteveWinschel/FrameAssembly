---
trigger: always_on
description: "Prohibits automatic version bumping and unrequested git commit, push, or tag operations."
---

# Versioning & Git Workflow Rule

- **Explicit Version Bumping Only**: NEVER bump the version number in `Cargo.toml` or `frameassembly-vscode/package.json` automatically during code changes, bug fixes, or feature implementations. Only bump the version number when explicitly instructed by the user.
- **Keep Versions Synchronized**: When the user explicitly asks to bump the version number, always update both `Cargo.toml` (and `Cargo.lock`) and `frameassembly-vscode/package.json` to the same version so the CLI crate and VS Code extension stay in sync.
- **Explicit Git Commit/Push Only**: NEVER run `git commit`, `git push`, or `git tag` unless the user explicitly instructs you to do so in their prompt. Read-only git commands (such as `git status`, `git diff`, and `git log`) may be used freely.
