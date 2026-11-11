# FrameAssembly Multi-Platform Packaging & Release Maintainer Guide

This directory contains official packaging recipes, manifests, formulas, and distribution templates for **FrameAssembly** (`frameassembly` v2.0.0, official website & browser playground: [`https://frameassembly.ai.studio/`](https://frameassembly.ai.studio/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) across supported operating systems and package managers:

- **Debian / Ubuntu (`APT`)**: Standalone `.deb` package builder and control templates (`contrib/packaging/apt/`), bundling MIME, file magic, and Bash/Zsh/Fish Tab completions
- **macOS & Linux (`Homebrew`)**: Multi-architecture Ruby formula for [`SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly) (`contrib/packaging/homebrew/`)
- **Windows (`Scoop`)**: Self-updating JSON manifest synced to [`SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly) (`contrib/packaging/scoop/`)
- **WebAssembly (`NPM`)**: Browser/Node.js WebAssembly package `frameassembly-wasm` (`frameassembly-wasm/`)
- **VS Code Marketplace**: Interactive Packet Studio extension `frameassembly-vscode` bundling the WASM compiler and decompiler (`frameassembly-vscode/`)

---

Pre-built static binary packages are provided across APT (`.deb`), macOS & Linux Homebrew (`brew`), and Windows Scoop (`scoop`), with zero runtime library dependencies and automatic MIME, file magic, and shell completion registration on Debian/Ubuntu.

---

## 1. Distribution Ecosystem & Architecture Matrix

| Package Manager | Target Platform | Architecture | Upstream Registry / Repository | Package Identifier |
| :--- | :--- | :--- | :--- | :--- |
| **APT** | Debian 11+, Ubuntu 20.04+ | `amd64`, `arm64` | GitHub Releases (`*.deb`) | `frameassembly` |
| **Homebrew** | macOS (Apple Silicon / Intel), Linux | `aarch64`, `x86_64` | `SteveWinschel/homebrew-tap-FrameAssembly` | `frameassembly` |
| **Scoop** | Windows 10/11, Windows Server | `64bit`, `arm64` | `SteveWinschel/homebrew-tap-FrameAssembly` | `frameassembly` |
| **NPM (WASM)** | Web browsers, Web Workers, Node.js | Universal (`wasm32`) | `npmjs.com/package/frameassembly-wasm` | `frameassembly-wasm` |
| **Crates.io** | Rust developers, Cargo users | Source / native | `crates.io/crates/frameassembly` | `frameassembly` |
| **VS Code Marketplace** | Cross-platform (VS Code, `.vsix` for Cursor, Windsurf, VSCodium) | Universal | Visual Studio Marketplace | `SteveWinschel.frameassembly-vscode` |

All native packages distribute static `musl` binaries on Linux, statically linked MSVC C runtime binaries on Windows, and Mach-O release binaries on macOS.

Debian (`.deb`) packages automatically bundle the Freedesktop shared MIME type definition (`contrib/mime/text-vnd.frameassembly.xml` -> `/usr/share/mime/packages/text-vnd.frameassembly.xml`), file magic rules (`contrib/magic/frameassembly.magic` -> `/usr/share/file/magic/frameassembly`), and Tab completions for Bash (`/usr/share/bash-completion/completions/frameassembly`), Zsh (`/usr/share/zsh/vendor-completions/_frameassembly`), and Fish (`/usr/share/fish/vendor_completions.d/frameassembly.fish`).

---

## 2. GitHub Actions CI/CD Automated Publishing Matrix & Credentials

Automated CI release publication and registry synchronization are managed by `.github/workflows/release.yml`. The workflow triggers on pushes to `main` modifying `Cargo.toml` (auto-creating tag `v<version>`) and manual `workflow_dispatch`.

Every external registry upload is guarded by optional GitHub Actions secrets or OIDC Trusted Publishing:
- **Zero Secrets Configured (`0 secrets set`)**: On forks or dry-runs with zero secrets configured, the workflow still compiles all 6 native matrix targets, packages Debian `.deb` archives with shell completions, compiles the WebAssembly NPM tarball, bundles the WASM runtime into the VS Code `.vsix`, generates SLSA provenance attestations, computes `SHA256SUMS.txt`, and publishes the GitHub Release cleanly.
- **With Credentials Configured**: Registry publishing and Homebrew/Scoop repository synchronization activate automatically.

### Supported Secret & OIDC Specification Matrix

| # | Secret Name | Target Ecosystem & Scope | Purpose & Automated Action |
| :- | :--- | :--- | :--- |
| 1 | `NPM_TOKEN` | NPM Registry (`registry.npmjs.org`) | Publishes WebAssembly package `frameassembly-wasm` (with OIDC Trusted Publisher fallback) after patching `pkg/package.json` metadata and SEO keywords. |
| 2 | `CARGO_REGISTRY_TOKEN` | Crates.io (`crates.io`) | Publishes the `frameassembly` CLI and library crate to crates.io via `cargo publish --token`. |
| 3 | `VSCE_PAT` | Visual Studio Marketplace (`marketplace.visualstudio.com`) | Publishes `frameassembly-vscode` `.vsix` (with `--oidc` Trusted Publisher fallback) after bundling `frameassembly-wasm` into `frameassembly-vscode/wasm/`. |
| 4 | `HOMEBREW_TAP_TOKEN` | GitHub Tap & Scoop Bucket (`SteveWinschel/homebrew-tap-FrameAssembly`) | GitHub PAT with repo write access to auto-sync `Formula/frameassembly.rb` and `bucket/frameassembly.json` to `SteveWinschel/homebrew-tap-FrameAssembly`. |

---

## 3. Step-by-Step Publication Instructions

### 3.0 Automated Release Checksum Stamping (`update-checksums.sh`)

Every tagged GitHub release runs `.github/workflows/release.yml`, compiling binaries across 6 matrix targets, building `.deb`, WASM, and `.vsix` artifacts, generating SLSA provenance attestations, and publishing `SHA256SUMS.txt`.

`contrib/packaging/update-checksums.sh` reads or downloads `SHA256SUMS.txt` and stamps verified 64-character SHA-256 hashes into:
- **Homebrew**: `contrib/packaging/homebrew/Formula/frameassembly.rb` (all 4 macOS/Linux architecture blocks)
- **Scoop**: `contrib/packaging/scoop/frameassembly.json` (`64bit` and `arm64`)

```bash
# Stamp checksums from a published GitHub Release tag
./contrib/packaging/update-checksums.sh v2.0.0

# Offline or local dry-run with a local SHA256SUMS.txt file
./contrib/packaging/update-checksums.sh --sums-file path/to/SHA256SUMS.txt 2.0.0
```

---

### 3.1 Debian / Ubuntu (APT `.deb`)

#### Local Build & Verification
```bash
# Build amd64 deb package
contrib/packaging/apt/build-deb.sh 2.0.0 target/release/frameassembly amd64 dist/

# Build arm64 deb package
contrib/packaging/apt/build-deb.sh 2.0.0 target/aarch64-unknown-linux-musl/release/frameassembly arm64 dist/

# Verify generated package metadata and bundled completions
dpkg-deb --info dist/frameassembly_2.0.0_amd64.deb
dpkg-deb --contents dist/frameassembly_2.0.0_amd64.deb
```

#### End-User Installation Command
```bash
# Clean one-line download and install of the latest stable Debian/Ubuntu package (amd64)
curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb

# For ARM64 (aarch64) systems:
curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_arm64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb
```

---

### 3.2 macOS & Linux Homebrew Tap (`SteveWinschel/homebrew-tap-FrameAssembly`)

The release workflow syncs `Formula/frameassembly.rb` directly to [`https://github.com/SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly) (checking `homebrew-tap-FrameAssembly`, `homebrew-tap`, `homebrew-frameassembly`, and `tap-FrameAssembly` in sequence).

#### Manual Sync
```bash
git clone https://github.com/SteveWinschel/homebrew-tap-FrameAssembly.git
cd homebrew-tap-FrameAssembly
mkdir -p Formula
cp /path/to/frameassembly/contrib/packaging/homebrew/Formula/frameassembly.rb Formula/
git add Formula/frameassembly.rb
git commit -m "frameassembly 2.0.0"
git push origin main
```

#### End-User Installation Command
```bash
brew install SteveWinschel/tap-FrameAssembly/frameassembly
```

---

### 3.3 Windows Scoop (`SteveWinschel/homebrew-tap-FrameAssembly`)

The Scoop manifest (`contrib/packaging/scoop/frameassembly.json`) is hosted inside the `bucket/` directory of [`https://github.com/SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly) and updated automatically on every release alongside the Homebrew formula.

#### End-User Installation Command
```powershell
scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly
scoop install frameassembly
```

---

### 3.4 Visual Studio Marketplace (`frameassembly-vscode`)

`frameassembly-vscode` bundles the compiled `frameassembly-wasm` engine inside `frameassembly-vscode/wasm/` so live `.fasm` diagnostics, protocol-scoped autocomplete, interactive Packet Ladder previews, and right-click `.pcap` / `.pcapng` reversal run offline inside VS Code.

#### Local Packaging & Publishing
```bash
env CARGO_PROFILE_RELEASE_STRIP=none wasm-pack build frameassembly-wasm --release --target web
mkdir -p frameassembly-vscode/wasm
cp frameassembly-wasm/pkg/frameassembly_wasm.js \
   frameassembly-wasm/pkg/frameassembly_wasm_bg.wasm \
   frameassembly-wasm/pkg/frameassembly_wasm.d.ts \
   frameassembly-vscode/wasm/

cd frameassembly-vscode
npx --yes @vscode/vsce package --no-git-tag-version --no-update-package-json -o frameassembly-vscode-2.0.0.vsix
npx @vscode/vsce publish -p "$VSCE_PAT" --packagePath frameassembly-vscode-2.0.0.vsix
```

#### End-User Installation Command
```bash
code --install-extension SteveWinschel.frameassembly-vscode
```

---

## 4. Local Validation & Quality Assurance

```bash
# 1. Shell script syntax linting
bash -n contrib/packaging/apt/build-deb.sh
bash -n contrib/packaging/update-checksums.sh
bash -n contrib/completions/frameassembly.bash
bash -n install.sh

# 2. Scoop JSON validation
jq . contrib/packaging/scoop/frameassembly.json

# 3. Debian package assembly test
contrib/packaging/apt/build-deb.sh 2.0.0 target/debug/frameassembly amd64 temp/
rm -rf temp/frameassembly_2.0.0_amd64.deb temp/frameassembly_amd64.deb
```
