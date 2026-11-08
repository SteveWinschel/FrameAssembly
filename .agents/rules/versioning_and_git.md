---
trigger: always_on
description: "Enforces 4-way version synchronization on explicit request and prohibits unrequested version bumps or git write operations."
---

# Versioning & Git Workflow Rule

- **Explicit Version Bumping Only**: NEVER bump version numbers automatically during bug fixes, refactors, documentation updates, or feature work. Only update version strings when explicitly instructed by the user.
- **4-Way Ecosystem Version Lockstep**: Whenever the user explicitly asks to bump the version to `X.Y.Z`, synchronize all published surfaces and metadata manifests in lockstep:
  1. **Rust Crate & CLI**: `Cargo.toml` (`version = "X.Y.Z"`) and `Cargo.lock`, plus version references in `src/lib.rs`, `llms.txt`, and `llms-full.txt`.
  2. **WebAssembly Package (`npm`)**: `frameassembly-wasm/Cargo.toml` (including any `frameassembly` dependency pin) and `frameassembly-wasm/package.json`.
  3. **VS Code Extension (`Marketplace` / `VSIX`)**: `frameassembly-vscode/package.json` and `install.sh` `.vsix` artifact references.
  4. **Citation & Academic Metadata**: `CITATION.cff` and `codemeta.json`.
- **Explicit Git Write Operations Only**: NEVER run `git commit`, `git push`, `git tag`, `cargo publish`, `npm publish`, or `npx @vscode/vsce publish` unless the user explicitly instructs you to do so in their current prompt. Read-only inspection commands (`git status`, `git diff`, `git log`) may be run freely.