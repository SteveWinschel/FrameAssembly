---
trigger: always_on
description: "Enforces ecosystem-wide version synchronization on explicit request across supported distribution channels and prohibits unrequested version bumps or git write operations."
---

# Versioning & Git Workflow Rule

- **Explicit Version Bumping Only**: NEVER bump version numbers automatically during bug fixes, refactors, documentation updates, or feature work. Only update version strings when explicitly instructed by the user.
- **Ecosystem Version Lockstep**: Whenever the user explicitly asks to bump the version to `X.Y.Z`, synchronize all published surfaces and supported packaging manifests in lockstep:
  1. **Rust Crate & CLI**: `Cargo.toml` (`version = "X.Y.Z"`) and `Cargo.lock`, plus version references in `src/lib.rs`, `llms.txt`, and `llms-full.txt`.
  2. **WebAssembly Package (`npm`)**: `frameassembly-wasm/Cargo.toml` (including any `frameassembly` dependency pin) and `frameassembly-wasm/package.json`.
  3. **VS Code Packet Studio (`Marketplace` / `VSIX`)**: `frameassembly-vscode/package.json`, packaged `frameassembly-vscode-<X.Y.Z>.vsix`, and `install.sh` `.vsix` artifact references.
  4. **Citation, Academic & Supported Packaging Metadata**: `CITATION.cff`, `codemeta.json`, and active `contrib/packaging/` manifests (`.deb` and `SteveWinschel/homebrew-tap-FrameAssembly` for `Homebrew` & `Scoop`—do not add manifests for any other third-party package or extension registries).
- **Explicit Git Write Operations Only**: NEVER run `git commit`, `git push`, `git tag`, `cargo publish`, `npm publish`, or `npx @vscode/vsce publish` unless the user explicitly instructs you to do so in their current prompt. Read-only inspection commands (`git status`, `git diff`, `git log`) may be run freely.
