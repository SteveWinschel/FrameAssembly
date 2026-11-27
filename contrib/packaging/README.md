# FrameAssembly Multi-Platform Packaging & Release Maintainer Guide

This directory contains official packaging recipes, manifests, formulas, and distribution templates for **FrameAssembly** (`frameassembly` v3.3.1, official website & browser playground: [`https://frameassembly-lang.dev/`](https://frameassembly-lang.dev/), repository: [`https://github.com/SteveWinschel/FrameAssembly`](https://github.com/SteveWinschel/FrameAssembly)) across supported operating systems and package managers:

- **Crates.io (`cargo install frameassembly` — Recommended CLI Install)**: Native source build from [`crates.io/crates/frameassembly`](https://crates.io/crates/frameassembly) across Linux, macOS, Windows, and BSD (`Rust 1.89+`)
- **Debian / Ubuntu (`APT`)**: Standalone `.deb` package builder and control templates (`contrib/packaging/apt/`), bundling MIME (`postinst`/`postrm` `update-mime-database`), file magic, and Bash/Zsh/Fish Tab completions
- **macOS & Linux (`Homebrew`)**: Multi-architecture Ruby formula for [`SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly) (`contrib/packaging/homebrew/`)
- **Windows (`Scoop` & PowerShell)**: Self-updating JSON manifest synced to [`SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly) (`contrib/packaging/scoop/`), zero-Admin `install.ps1`, and Windows Explorer drag-and-drop support on `frameassembly.exe`
- **WebAssembly (`frameassembly-wasm`)**: Internal browser/WASM compiler package powering `frameassembly-lang.dev` and `frameassembly-vscode` (`frameassembly-wasm/`)
- **VS Code Marketplace**: Official extension `frameassembly-vscode` providing `.frasm` TextMate syntax highlighting, live inline WASM error checking, and 1-click typo Quick Fixes (`frameassembly-vscode/`)

---

## Recommended CLI Installation

When Rust (`1.89+`) is installed, `cargo install frameassembly` is the recommended cross-platform CLI install method:

```bash
cargo install frameassembly
```

Once installed, run the zero-flag `frameassembly update` subcommand anytime to upgrade: it runs Cargo/`rustup`-first with an upfront `rustc >= 1.89` and C/MSVC linker preflight, falling back to `SHA256SUMS.txt`-verified GitHub Release binaries and refreshing already-installed completion scripts on disk.

Pre-built static binary bundles (`frameassembly-{windows,macos,linux}-{x64,arm64}.{zip,tar.gz}`) on GitHub Releases include the `frameassembly` binary, `quickstart.frasm`, shell Tab completions (`completions/`), and `install.sh` / `install.ps1` for air-gapped labs. Documentation lives at [https://frameassembly-lang.dev/docs](https://frameassembly-lang.dev/docs) and use cases at [https://frameassembly-lang.dev/use-cases](https://frameassembly-lang.dev/use-cases).

---

## 1. Distribution Ecosystem & Architecture Matrix

| Package Manager | Target Platform | Architecture | Upstream Registry / Repository | Package Identifier |
| :--- | :--- | :--- | :--- | :--- |
| **Crates.io (Recommended)** | Linux, macOS, Windows, BSD | Source / native | `crates.io/crates/frameassembly` | `frameassembly` |
| **APT** | Debian 11+, Ubuntu 20.04+ | `amd64`, `arm64` | GitHub Releases (`frameassembly_{amd64,arm64}.deb` & `frameassembly_3.3.1_{amd64,arm64}.deb`) | `frameassembly` |
| **Homebrew** | macOS (Apple Silicon / Intel), Linux | `arm64`, `x64` | `SteveWinschel/homebrew-tap-FrameAssembly` | `frameassembly` |
| **Scoop** | Windows 10/11, Windows Server | `64bit`, `arm64` | `SteveWinschel/homebrew-tap-FrameAssembly` | `frameassembly` |
| **Internal WASM Engine** | `frameassembly-lang.dev` & `frameassembly-vscode` | Universal (`wasm32`) | Internal engine (`frameassembly-wasm/`, bundled into `frameassembly-vscode`) | `frameassembly-wasm` |
| **VS Code Marketplace** | Cross-platform (VS Code, `.vsix` for Cursor, Windsurf, VSCodium) | Universal | Visual Studio Marketplace | `SteveWinschel.frameassembly-vscode` |

All native packages distribute static `musl` binaries on Linux (`frameassembly-linux-x64.tar.gz`, `frameassembly-linux-arm64.tar.gz`), statically linked MSVC C runtime binaries on Windows (`frameassembly-windows-x64.zip`, `frameassembly-windows-arm64.zip`), and Mach-O release binaries on macOS (`frameassembly-macos-arm64.tar.gz`, `frameassembly-macos-x64.tar.gz`). Each GitHub Release publishes all 6 OS archives, both unversioned (`frameassembly_{amd64,arm64}.deb`) and versioned (`frameassembly_<version>_{amd64,arm64}.deb`) Debian packages, `frameassembly-vscode.vsix`, and `SHA256SUMS.txt` covering every binary, `.deb`, and `.vsix` asset.

Debian (`.deb`) packages bundle the Freedesktop shared MIME type definition (`contrib/mime/text-vnd.frameassembly.xml` -> `/usr/share/mime/packages/text-vnd.frameassembly.xml` with `DEBIAN/postinst` and `DEBIAN/postrm` refreshing `/usr/share/mime`), file magic rules (`contrib/magic/frameassembly.magic` -> `/usr/share/file/magic/frameassembly`), and Tab completions for Bash (`/usr/share/bash-completion/completions/frameassembly`), Zsh (`/usr/share/zsh/vendor-completions/_frameassembly`), and Fish (`/usr/share/fish/vendor_completions.d/frameassembly.fish`).

---

## 2. GitHub Actions CI/CD Automated Publishing Matrix & Credentials

Automated CI release publication and registry synchronization are managed by `.github/workflows/release.yml`. The workflow triggers on pushes to `main` modifying `Cargo.toml` (auto-creating tag `v<version>`) and manual `workflow_dispatch`.

Every external registry upload is guarded by optional GitHub Actions secrets or OIDC Trusted Publishing:
- **Zero Secrets Configured (`0 secrets set`)**: On forks or dry-runs with zero secrets configured, the workflow compiles all 6 native matrix targets, packages Debian `.deb` archives with shell completions, compiles the WebAssembly NPM tarball, bundles the WASM runtime into `frameassembly-vscode.vsix`, generates SLSA provenance attestations, computes `SHA256SUMS.txt` across all archives/debs/vsix, and publishes the GitHub Release cleanly.
- **With Credentials Configured**: Registry publishing and Homebrew/Scoop repository synchronization activate automatically.

### Supported Secret & OIDC Specification Matrix

| # | Secret Name | Target Ecosystem & Scope | Purpose & Automated Action |
| :- | :--- | :--- | :--- |
| 1 | `NPM_TOKEN` | NPM Registry (`registry.npmjs.org`) | Publishes WebAssembly package `frameassembly-wasm` (with OIDC Trusted Publisher fallback) after syncing `pkg/package.json` metadata. |
| 2 | `CARGO_REGISTRY_TOKEN` | Crates.io (`crates.io`) | Publishes the `frameassembly` CLI and library crate to crates.io from the exact release git tag via `cargo publish --locked`. |
| 3 | `VSCE_PAT` | Visual Studio Marketplace (`marketplace.visualstudio.com`) | Publishes `frameassembly-vscode` `.vsix` (with `--oidc` Trusted Publisher fallback) after bundling `frameassembly-wasm` into `frameassembly-vscode/wasm/`. |
| 4 | `HOMEBREW_TAP_TOKEN` | GitHub Tap & Scoop Bucket (`SteveWinschel/homebrew-tap-FrameAssembly`) | GitHub PAT with repo write access to auto-sync `Formula/frameassembly.rb` and `bucket/frameassembly.json` to `SteveWinschel/homebrew-tap-FrameAssembly`. |

---

## 3. Step-by-Step Publication & Offline Lab Instructions

### 3.0 Automated Release Checksum Stamping (`update-checksums.sh`)

`contrib/packaging/update-checksums.sh` reads or downloads `SHA256SUMS.txt` and stamps verified 64-character SHA-256 hashes and version strings into:
- **Homebrew**: `contrib/packaging/homebrew/Formula/frameassembly.rb` (all 4 macOS/Linux architecture blocks)
- **Scoop**: `contrib/packaging/scoop/frameassembly.json` (`64bit` and `arm64`)
- **Debian Control**: `contrib/packaging/apt/debian/control`
- **Bootstrap Installers**: `install.sh` (`RELEASE_VERSION` / `VSIX_VERSION`) and `install.ps1` (`$ReleaseVersion` / `$VsixVersion`)

```bash
# Stamp checksums from a published GitHub Release tag
./contrib/packaging/update-checksums.sh v3.3.1

# Offline or local dry-run with a local SHA256SUMS.txt file
./contrib/packaging/update-checksums.sh --sums-file path/to/SHA256SUMS.txt 3.3.1
```

---

### 3.1 Debian / Ubuntu (APT `.deb`)

#### Local Build & Verification
```bash
# Build amd64 deb package (emits both frameassembly_3.3.1_amd64.deb and frameassembly_amd64.deb)
contrib/packaging/apt/build-deb.sh 3.3.1 target/release/frameassembly amd64 dist/

# Build arm64 deb package
contrib/packaging/apt/build-deb.sh 3.3.1 target/aarch64-unknown-linux-musl/release/frameassembly arm64 dist/

# Verify generated package metadata and bundled completions
dpkg-deb --info dist/frameassembly_3.3.1_amd64.deb
dpkg-deb --contents dist/frameassembly_3.3.1_amd64.deb
```

#### End-User Installation Command
Downloading into the current directory (`./frameassembly_amd64.deb`) avoids APT's `_apt` privilege-drop warning on sticky `/tmp` directories:

```bash
# Latest stable Debian/Ubuntu package (amd64)
curl -fsSLo ./frameassembly_amd64.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y ./frameassembly_amd64.deb && rm -f ./frameassembly_amd64.deb

# Latest stable Debian/Ubuntu package (arm64 / aarch64)
curl -fsSLo ./frameassembly_arm64.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_arm64.deb && sudo apt install -y ./frameassembly_arm64.deb && rm -f ./frameassembly_arm64.deb

# Pinned versioned asset (v3.3.1)
curl -fsSLo ./frameassembly_3.3.1_amd64.deb https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly_3.3.1_amd64.deb && sudo apt install -y ./frameassembly_3.3.1_amd64.deb && rm -f ./frameassembly_3.3.1_amd64.deb
```

---

### 3.2 macOS & Linux Homebrew Tap (`SteveWinschel/homebrew-tap-FrameAssembly`)

The release workflow syncs `Formula/frameassembly.rb` directly to [`https://github.com/SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly).

#### Manual Sync
```bash
git clone https://github.com/SteveWinschel/homebrew-tap-FrameAssembly.git
cd homebrew-tap-FrameAssembly
mkdir -p Formula
cp /path/to/frameassembly/contrib/packaging/homebrew/Formula/frameassembly.rb Formula/
git add Formula/frameassembly.rb
git commit -m "frameassembly 3.3.1"
git push origin main
```

#### End-User Installation Command
```bash
brew install SteveWinschel/tap-FrameAssembly/frameassembly
```

---

### 3.3 Windows Scoop, PowerShell & Explorer Drag-and-Drop

The Scoop manifest (`contrib/packaging/scoop/frameassembly.json`) is hosted inside `bucket/` on [`https://github.com/SteveWinschel/homebrew-tap-FrameAssembly`](https://github.com/SteveWinschel/homebrew-tap-FrameAssembly).

#### End-User Installation & Explorer Workflow
```powershell
# Recommended if Rust is installed:
cargo install frameassembly

# Scoop:
scoop bucket add frameassembly https://github.com/SteveWinschel/homebrew-tap-FrameAssembly
scoop install frameassembly

# Or zero-Admin PowerShell installer:
irm https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.ps1 | iex
```

On Windows File Explorer, extracting `frameassembly-windows-x64.zip` also works without opening a terminal:
- **Double-click `frameassembly.exe`**: Prints quickstart instructions and waits for `Enter` instead of flashing closed.
- **Drag a `.frasm` file onto `frameassembly.exe`**: Compiles `<name>.pcap` next to the input file and pauses so you can read the summary.
- **Drag a `.pcap` or `.pcapng` file onto `frameassembly.exe`**: Reverses the capture into `<name>.frasm` and pauses.

---

### 3.4 Air-Gapped & Offline Lab Archives (`.zip` / `.tar.gz`)

Every OS `.tar.gz` and `.zip` release bundle carries `quickstart.frasm` and `completions/`. Copy the archive (plus `SHA256SUMS.txt` and optional `frameassembly-vscode.vsix`) onto a jump-host:

```bash
# Linux / macOS offline install (verifies SHA256SUMS.txt in the same folder; pass --skip-checksum if omitted)
./install.sh --offline ./frameassembly-linux-x64.tar.gz
```

```powershell
# Windows offline install
.\install.ps1 -OfflineArchive .\frameassembly-windows-x64.zip
```

---

### 3.5 Visual Studio Marketplace (`frameassembly-vscode`)

`frameassembly-vscode` bundles the read-only `frameassembly-wasm` linter inside `frameassembly-vscode/wasm/` for offline `.frasm` syntax highlighting, live inline error diagnostics, and 1-click typo Quick Fixes across trusted, untrusted, and virtual workspaces.

#### Local Packaging & Publishing
```bash
env CARGO_PROFILE_RELEASE_STRIP=none wasm-pack build frameassembly-wasm --release --target web
mkdir -p frameassembly-vscode/wasm
cp frameassembly-wasm/pkg/frameassembly_wasm.js \
   frameassembly-wasm/pkg/frameassembly_wasm_bg.wasm \
   frameassembly-vscode/wasm/

cd frameassembly-vscode
npx --yes @vscode/vsce package --no-git-tag-version --no-update-package-json -o frameassembly-vscode-3.3.1.vsix
npx @vscode/vsce publish -p "$VSCE_PAT" --packagePath frameassembly-vscode-3.3.1.vsix
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
contrib/packaging/apt/build-deb.sh 3.3.1 target/debug/frameassembly amd64 temp/
rm -rf temp/frameassembly_3.3.1_amd64.deb temp/frameassembly_amd64.deb
```
