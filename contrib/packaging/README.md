# FrameAssembly Multi-Platform Packaging & Release Maintainer Guide

This directory contains official packaging recipes, manifests, formulas, and distribution templates for **FrameAssembly** (`frameassembly` v1.4.3) across major operating systems and package management ecosystems:

- **Debian / Ubuntu (`APT`)**: Standalone `.deb` package builder and control templates (`contrib/packaging/apt/`)
- **Arch Linux (`AUR`)**: Binary `PKGBUILD` and `.SRCINFO` for `frameassembly-bin` (`contrib/packaging/aur/`)
- **Windows Package Manager (`WinGet`)**: Schema v1.6.0 manifests for `microsoft/winget-pkgs` (`contrib/packaging/winget/`)
- **macOS & Linux (`Homebrew`)**: Multi-architecture Ruby formula for `SteveWinschel/homebrew-tap` (`contrib/packaging/homebrew/`)
- **Windows (`Scoop`)**: Self-updating JSON manifest for `SteveWinschel/scoop-bucket` (`contrib/packaging/scoop/`)
- **WebAssembly (`NPM`)**: Browser/Node.js WebAssembly package `frameassembly-wasm` (`frameassembly-wasm/`)
- **VS Code / Open VSX**: Universal extension package `frameassembly-vscode` (`frameassembly-vscode/`)

---

Pre-built static binary packages are provided across APT (`.deb`), Arch Linux AUR (`frameassembly-bin`), Windows Package Manager (`winget`), macOS & Linux Homebrew (`brew`), and Windows Scoop (`scoop`), with zero runtime library dependencies and automatic MIME/magic registration on Linux.

---

## 1. Distribution Ecosystem & Architecture Matrix

| Package Manager | Target Platform | Architecture | Upstream Registry / Repository | Package Identifier |
| :--- | :--- | :--- | :--- | :--- |
| **APT** | Debian 11+, Ubuntu 20.04+ | `amd64`, `arm64` | GitHub Releases (`*.deb`) | `frameassembly` |
| **AUR** | Arch Linux, Manjaro, EndeavourOS | `x86_64`, `aarch64` | `aur.archlinux.org` | `frameassembly-bin` |
| **WinGet** | Windows 10/11, Windows Server | `x64`, `arm64` | `microsoft/winget-pkgs` | `SteveWinschel.FrameAssembly` |
| **Homebrew** | macOS (Apple Silicon / Intel), Linux | `aarch64`, `x86_64` | `SteveWinschel/homebrew-tap` | `frameassembly` |
| **Scoop** | Windows 10/11, Windows Server | `64bit`, `arm64` | `SteveWinschel/scoop-bucket` | `frameassembly` |
| **NPM (WASM)** | Web browsers, Web Workers, Node.js | Universal (`wasm32`) | `npmjs.com/package/frameassembly-wasm` | `frameassembly-wasm` |
| **Crates.io** | Rust developers, Cargo users | Source / native | `crates.io/crates/frameassembly` | `frameassembly` |
| **VS Code / Open VSX** | Cross-platform (VS Code, Cursor, Windsurf, VSCodium) | Universal | Visual Studio Marketplace / Open VSX | `SteveWinschel.frameassembly-vscode` |

All packages distribute static `musl` binaries on Linux, statically linked MSVC C runtime binaries on Windows, and Universal Mach-O release binaries on macOS. This guarantees zero runtime library dependency conflicts on target machines.

Both Debian (`.deb`) and Arch Linux AUR (`frameassembly-bin`) packages automatically bundle and register the official Freedesktop shared MIME type definition (`contrib/mime/text-vnd.frameassembly.xml` installed to `/usr/share/mime/packages/text-vnd.frameassembly.xml`) and file magic signatures (installed to `/usr/share/file/magic/frameassembly` when present), enabling immediate file-manager icon association and `file(1)` command identification for `.fasm` specifications upon installation.

---

## 2. GitHub Actions CI/CD Automated Publishing Matrix & Secrets

Automated CI release publication and multi-store distribution are managed by `.github/workflows/release.yml`. The workflow triggers on tag pushes (`v*`), pushes to `main` modifying `Cargo.toml` (with automated git tag creation and release pipeline trigger), and manual `workflow_dispatch`.

Every release step is **guarded by optional GitHub Actions secrets**, providing zero-secret graceful degradation:
- **Zero Secrets Configured (`0 secrets set`)**: When run on personal forks or local runs with zero secrets configured, the workflow still compiles all 6 native matrix targets, packages Debian `.deb`, builds the VS Code `.vsix`, compiles the WebAssembly NPM tarball, generates SLSA provenance attestations, computes `SHA256SUMS.txt`, and publishes the full GitHub Release without any failures.
- **As Secrets Are Added**: Upstream package distribution and registry synchronization seamlessly activate without workflow modifications.

### Complete 7-Secret Specification Matrix

| # | Secret Name | Target Ecosystem & Scope | Purpose & Automated Action |
| :- | :--- | :--- | :--- |
| 1 | `NPM_TOKEN` | NPM Registry (`registry.npmjs.org`) | Publishes WebAssembly package `frameassembly-wasm` via `npm publish --access public` after `wasm-pack build --release --target web`. |
| 2 | `CARGO_REGISTRY_TOKEN` | Crates.io (`crates.io`) | Publishes the core `frameassembly` compiler CLI crate to crates.io via `cargo publish --token`. |
| 3 | `VSCE_PAT` | Visual Studio Marketplace (`marketplace.visualstudio.com`) | Publishes `frameassembly-vscode` extension via `npx @vscode/vsce publish -p`. |
| 4 | `OVSX_PAT` | Open VSX Registry (`open-vsx.org`) | Publishes `frameassembly-vscode` to Open VSX (Antigravity IDE, Cursor, Windsurf, VSCodium) via `npx ovsx publish -p`. |
| 5 | `AUR_SSH_PRIVATE_KEY` | Arch User Repository (`aur.archlinux.org`) | SSH private key to authenticate to `aur@aur.archlinux.org`, clone `frameassembly-bin.git`, copy updated `PKGBUILD` and `.SRCINFO`, and push. |
| 6 | `WINGET_TOKEN` | Windows Package Manager (`microsoft/winget-pkgs`) | GitHub PAT (`public_repo` scope) to submit automated WinGet package manifest updates. |
| 7 | `HOMEBREW_TAP_TOKEN` | GitHub Tap & Scoop Bucket Repositories | GitHub PAT with repo write access to auto-sync `Formula/frameassembly.rb` in `SteveWinschel/homebrew-tap` and `frameassembly.json` in `SteveWinschel/scoop-bucket`. |

---

## 3. Step-by-Step Publication Instructions

### 3.0 Automated Release Checksum Stamping (`update-checksums.sh`)

Every tagged GitHub release triggers `.github/workflows/release.yml`, which compiles binaries across 6 matrix targets, builds `.deb` and `.vsix` packages, compiles WebAssembly artifacts, generates SLSA build provenance attestations, and publishes release archives accompanied by `SHA256SUMS.txt`.

The automated checksum tool `contrib/packaging/update-checksums.sh` reads or downloads `SHA256SUMS.txt` and stamps verified 64-character SHA-256 hashes directly into all packaging manifests:
- **AUR**: `contrib/packaging/aur/PKGBUILD` and `contrib/packaging/aur/.SRCINFO`
- **WinGet**: `contrib/packaging/winget/manifests/s/SteveWinschel/FrameAssembly/<version>/SteveWinschel.FrameAssembly.installer.yaml`
- **Homebrew**: `contrib/packaging/homebrew/Formula/frameassembly.rb` (all 4 architecture blocks)
- **Scoop**: `contrib/packaging/scoop/frameassembly.json` (`64bit` and `arm64`)

#### 4-Step Maintainer Release Workflow
1. **Tag and push release on GitHub**:
   ```bash
   git tag v1.4.3
   git push origin v1.4.3
   ```
   *(Or bump `version = "1.4.3"` in root `Cargo.toml` and push to `main`; CI will auto-create tag `v1.4.3` and run the full release pipeline).*
2. **Wait for CI artifact generation**:
   GitHub Actions `.github/workflows/release.yml` completes builds and uploads `SHA256SUMS.txt` to the release.
3. **Run the checksum updater**:
   ```bash
   ./contrib/packaging/update-checksums.sh v1.4.3
   ```
   *(For offline or local dry-runs with a pre-existing checksum file, run: `./contrib/packaging/update-checksums.sh --sums-file path/to/SHA256SUMS.txt 1.4.3`)*
4. **Submit updated manifests to upstream ecosystems**:
   Submit WinGet PR via `wingetcreate`, push AUR update to `frameassembly-bin.git`, and copy formulas to `homebrew-tap` and `scoop-bucket` as detailed below.

---

### 3.1 Debian / Ubuntu (APT `.deb`)

Debian packages are automatically built in CI during tagged releases via `.github/workflows/release.yml`. Maintainers can also generate packages locally with a single command.

#### Local Build & Verification
```bash
# Build amd64 deb package
contrib/packaging/apt/build-deb.sh 1.4.3 target/release/frameassembly amd64 dist/

# Build arm64 deb package
contrib/packaging/apt/build-deb.sh 1.4.3 target/aarch64-unknown-linux-musl/release/frameassembly arm64 dist/

# Verify generated package structure and metadata
dpkg-deb --info dist/frameassembly_1.4.3_amd64.deb
dpkg-deb --contents dist/frameassembly_1.4.3_amd64.deb
```

#### Uploading to GitHub Release
```bash
# Attach Debian packages directly to the release
gh release upload v1.4.3 \
  dist/frameassembly_1.4.3_amd64.deb \
  dist/frameassembly_1.4.3_arm64.deb
```

#### End-User Installation Command
```bash
# Clean one-line download and install of the latest stable Debian/Ubuntu package (amd64)
curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb

# For ARM64 (aarch64) systems:
curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_arm64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb
```

Or install a specific version directly via dpkg:
```bash
curl -fsSL https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly_1.4.3_amd64.deb -o frameassembly.deb
sudo dpkg -i frameassembly.deb
```

---

### 3.2 Arch User Repository (AUR `frameassembly-bin`)

#### One-Time Initial Setup
1. Register an account on [https://aur.archlinux.org/register](https://aur.archlinux.org/register).
2. Upload your SSH public key (`~/.ssh/id_ed25519.pub`) under Account Details.
3. Clone the new package repository:
```bash
git clone ssh://aur@aur.archlinux.org/frameassembly-bin.git
cd frameassembly-bin
```

#### Publishing or Updating a Release
```bash
# Copy recipe files from FrameAssembly repository
cp /path/to/frameassembly/contrib/packaging/aur/PKGBUILD .

# Update checksums against published release tarballs
updpkgsums

# Generate synced .SRCINFO metadata
makepkg --printsrcinfo > .SRCINFO

# Verify PKGBUILD syntax
bash -n PKGBUILD

# Commit and publish to AUR
git add PKGBUILD .SRCINFO
git commit -m "chore(release): bump frameassembly-bin to v1.4.3"
git push origin master
```

#### End-User Installation Command
```bash
# Using yay
yay -S frameassembly-bin

# Using paru
paru -S frameassembly-bin
```

---

### 3.3 Microsoft Windows Package Manager (WinGet)

#### One-Command Update via `wingetcreate`
The official `wingetcreate` CLI tool automatically calculates SHA-256 hashes, generates the 3-file manifest structure, and creates an upstream pull request against `microsoft/winget-pkgs`.

```powershell
# Install wingetcreate (if not already installed)
winget install Microsoft.WingetCreate

# Submit new release to microsoft/winget-pkgs
wingetcreate update SteveWinschel.FrameAssembly `
  --version 1.4.3 `
  --urls "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly-v1.4.3-x86_64-pc-windows-msvc.zip" `
         "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly-v1.4.3-aarch64-pc-windows-msvc.zip" `
  --token $env:WINGET_TOKEN `
  --submit
```

#### Manual Submission or Validation
To test local manifest files before submission:
```powershell
winget validate --manifest contrib/packaging/winget/manifests/s/SteveWinschel/FrameAssembly/1.4.3/
```

#### End-User Installation Command
```powershell
winget install SteveWinschel.FrameAssembly
```

---

### 3.4 macOS & Linux Homebrew Tap (`SteveWinschel/homebrew-tap-FrameAssembly`)

#### Repository Resolution & 4-Repo Fallback
The release automation workflow (`.github/workflows/release.yml`) supports automated formula synchronization across four candidate repository names in sequence:
1. `SteveWinschel/homebrew-tap-FrameAssembly` (primary tap repository)
2. `SteveWinschel/homebrew-tap` (canonical tap repository)
3. `SteveWinschel/homebrew-frameassembly` (dedicated formula tap)
4. `SteveWinschel/tap-FrameAssembly` (alternative tap name)

The CI pipeline attempts to clone each candidate repository using `HOMEBREW_TAP_TOKEN` and updates `Formula/frameassembly.rb` in whichever repository exists, committing with `frameassembly 1.4.3` [skip ci].

#### One-Time Initial Setup
1. Create a public tap repository (e.g. `SteveWinschel/homebrew-tap-FrameAssembly`, `SteveWinschel/tap-FrameAssembly`, or `SteveWinschel/homebrew-tap`) on GitHub.
2. Initialize directory `Formula/` inside the repository.

#### Publishing an Update
```bash
# Clone the tap repository
git clone https://github.com/SteveWinschel/homebrew-tap-FrameAssembly.git
cd homebrew-tap-FrameAssembly

# Copy the updated formula
cp /path/to/frameassembly/contrib/packaging/homebrew/Formula/frameassembly.rb Formula/

# Update SHA-256 checksums if not automated
# curl -fsSL <release_tarball_url> | sha256sum

# Commit and push
git add Formula/frameassembly.rb
git commit -m "frameassembly 1.4.3"
git push origin main
```

#### End-User Installation Command
```bash
# Direct install from tap
brew install SteveWinschel/tap/frameassembly
```

---

### 3.5 Windows Scoop (`SteveWinschel/scoop-bucket`)

#### One-Time Initial Setup
1. Create a public repository named `SteveWinschel/scoop-bucket` on GitHub.
2. Copy `contrib/packaging/scoop/frameassembly.json` to `bucket/frameassembly.json` in the bucket repo.

#### Autoupdate Maintenance
Because the manifest configures `"checkver": "github"` and an `"autoupdate"` block with `"$url.sha256"`, standard Scoop maintenance bots automatically discover new releases, update the download URLs and hashes, and commit without manual intervention.

To manually trigger an update verification in the bucket:
```powershell
# Run Scoop checkver from scoop repo
bin/checkver -u frameassembly
```

#### End-User Installation Command
```powershell
# Add the bucket and install
scoop bucket add frameassembly https://github.com/SteveWinschel/scoop-bucket
scoop install frameassembly

# Or install directly from raw GitHub URL
scoop install https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/contrib/packaging/scoop/frameassembly.json
```

---

### 3.6 Visual Studio Marketplace & Open VSX Registry (`frameassembly-vscode`)

The official FrameAssembly VS Code extension (`frameassembly-vscode`) provides full syntax highlighting for all 81 protocols, 16 tab-completable `.fasm` snippets, and MIME/file identification.

#### One-Time Publisher Namespace Creation
1. **Visual Studio Marketplace (`marketplace.visualstudio.com`)**:
   - Log into the [Visual Studio Marketplace Management Portal](https://marketplace.visualstudio.com/manage) with your Microsoft account.
   - Create publisher namespace `SteveWinschel`.
   - In Azure DevOps (`dev.azure.com`), generate a Personal Access Token (PAT) with `Marketplace (Manage)` scope.
   - Save the token as environment variable `VSCE_PAT` (or GitHub Actions secret `VSCE_PAT`).
2. **Open VSX Registry (`open-vsx.org`)**:
   - Log into [Open VSX Registry](https://open-vsx.org) via GitHub authentication.
   - Create publisher namespace `SteveWinschel` under Account Settings.
   - Generate an access token and save as environment variable `OVSX_PAT` (or GitHub Actions secret `OVSX_PAT`).

#### Local Packaging & Verification
```bash
cd frameassembly-vscode
npx --yes @vscode/vsce package --no-git-tag-version --no-update-package-json
```

#### Publishing Commands
```bash
# 1. Publish to Visual Studio Marketplace
npx @vscode/vsce publish -p "$VSCE_PAT"

# 2. Publish to Open VSX Registry (Antigravity IDE, Cursor, Windsurf, VSCodium)
npx ovsx publish -p "$OVSX_PAT"
```

#### End-User Installation Command
```bash
# Install in VS Code or Cursor
code --install-extension SteveWinschel.frameassembly-vscode
```

---

## 4. Local Validation & Quality Assurance

Maintainers must run the following validation checks prior to committing packaging changes:

```bash
# 1. Shell script syntax linting
bash -n contrib/packaging/apt/build-deb.sh
bash -n contrib/packaging/aur/PKGBUILD
bash -n contrib/packaging/update-checksums.sh
bash -n install.sh

# 2. Scoop JSON schema validation
jq . contrib/packaging/scoop/frameassembly.json

# 3. WinGet YAML syntax verification
python3 -c "import yaml; [yaml.safe_load(open(f)) for f in [
  'contrib/packaging/winget/manifests/s/SteveWinschel/FrameAssembly/1.4.3/SteveWinschel.FrameAssembly.yaml',
  'contrib/packaging/winget/manifests/s/SteveWinschel/FrameAssembly/1.4.3/SteveWinschel.FrameAssembly.installer.yaml',
  'contrib/packaging/winget/manifests/s/SteveWinschel/FrameAssembly/1.4.3/SteveWinschel.FrameAssembly.locale.en-US.yaml'
]]; print('WinGet YAML valid.')"

# 4. Debian package assembly test
contrib/packaging/apt/build-deb.sh 1.4.3 target/debug/frameassembly amd64 temp/
rm -rf temp/frameassembly_1.4.3_amd64.deb
```

---

## 5. Upstream PR & Review Policies

- **WinGet (`microsoft/winget-pkgs`)**: PRs submitted via `wingetcreate` trigger automated GitHub Actions workflows that validate manifest syntax and run automated installation/uninstallation checks in an isolated Windows Sandbox VM. Once validation passes, the bot merges the PR automatically within 1–2 hours.
- **AUR (`aur.archlinux.org`)**: Pushes to `ssh://aur@aur.archlinux.org/frameassembly-bin.git` are immediate. Maintainers must ensure `PKGBUILD` and `.SRCINFO` remain strictly synchronized (`makepkg --printsrcinfo > .SRCINFO`).
- **Homebrew Core vs. Tap**: Maintainer distribution uses the official tap `SteveWinschel/homebrew-tap`. Submission to `homebrew/homebrew-core` requires building from source with Cargo rather than distributing pre-built binary tarballs.
