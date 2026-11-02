#!/usr/bin/env bash
# FrameAssembly Manifest Checksum Updater
# Stamping release SHA-256 hashes across AUR, WinGet, Homebrew, and Scoop manifests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VERSION=""
SUMS_FILE=""
REPO_ROOT="${DEFAULT_REPO_ROOT}"
CLEANUP_TEMP=0
TEMP_SUMS=""

show_help() {
    cat <<'EOF'
FrameAssembly Manifest Checksum Updater

Usage:
  ./contrib/packaging/update-checksums.sh [OPTIONS] [VERSION|TAG]

Arguments:
  VERSION | TAG            Release version (e.g. '1.4.3' or 'v1.4.3').
                           If omitted, auto-detected from Cargo.toml or PKGBUILD.

Options:
  -s, --sums-file <PATH>   Path to local SHA256SUMS.txt file (for testing/dry-run).
                           If omitted, downloads from GitHub Releases for TAG.
  -r, --repo-root <PATH>   Path to repository root (defaults to auto-detected root).
  -h, --help               Show this help message and exit.

Manifests Updated:
  1. Arch Linux AUR:       contrib/packaging/aur/PKGBUILD & .SRCINFO
  2. Microsoft WinGet:     contrib/packaging/winget/manifests/.../*.installer.yaml
  3. macOS & Linux Brew:   contrib/packaging/homebrew/Formula/frameassembly.rb
  4. Windows Scoop:        contrib/packaging/scoop/frameassembly.json
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -s|--sums-file)
            if [[ $# -lt 2 ]]; then
                echo "Error: --sums-file requires a file path argument" >&2
                exit 1
            fi
            SUMS_FILE="$2"
            shift 2
            ;;
        -r|--repo-root|--root)
            if [[ $# -lt 2 ]]; then
                echo "Error: --repo-root requires a directory path argument" >&2
                exit 1
            fi
            REPO_ROOT="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option '$1'" >&2
            echo "Run '$0 --help' for usage." >&2
            exit 1
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
                shift
            else
                echo "Error: Unexpected positional argument '$1'" >&2
                echo "Run '$0 --help' for usage." >&2
                exit 1
            fi
            ;;
    esac
done

# Resolve VERSION if not supplied
if [[ -z "$VERSION" ]]; then
    if [[ -f "${REPO_ROOT}/Cargo.toml" ]]; then
        VERSION="$(grep -m1 '^version[[:space:]]*=' "${REPO_ROOT}/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    fi
    if [[ -z "$VERSION" && -f "${REPO_ROOT}/contrib/packaging/aur/PKGBUILD" ]]; then
        VERSION="$(grep -m1 '^pkgver=' "${REPO_ROOT}/contrib/packaging/aur/PKGBUILD" | cut -d= -f2 || true)"
    fi
fi

if [[ -z "$VERSION" ]]; then
    echo "Error: Version could not be determined. Please specify VERSION (e.g. 1.4.3 or v1.4.3)." >&2
    exit 1
fi

# Normalize version and tag
VERSION="${VERSION#v}"
TAG="v${VERSION}"

echo "==> FrameAssembly Release Checksum Updater"
echo "    Version: ${VERSION} (${TAG})"
echo "    Repo root: ${REPO_ROOT}"

# Obtain SHA256SUMS.txt
if [[ -n "$SUMS_FILE" ]]; then
    if [[ ! -f "$SUMS_FILE" ]]; then
        echo "Error: Specified checksums file not found: '$SUMS_FILE'" >&2
        exit 1
    fi
    echo "    Checksums source: local file (${SUMS_FILE})"
else
    SUMS_URL="https://github.com/SteveWinschel/FrameAssembly/releases/download/${TAG}/SHA256SUMS.txt"
    echo "    Checksums source: ${SUMS_URL}"
    TEMP_SUMS="$(mktemp -t frameassembly-sums-XXXXXX.txt)"
    CLEANUP_TEMP=1
    trap '[[ $CLEANUP_TEMP -eq 1 ]] && rm -f "$TEMP_SUMS"' EXIT

    DOWNLOAD_OK=0
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "$SUMS_URL" -o "$TEMP_SUMS"; then
            DOWNLOAD_OK=1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -qO "$TEMP_SUMS" "$SUMS_URL"; then
            DOWNLOAD_OK=1
        fi
    else
        echo "Error: Neither curl nor wget is available to download SHA256SUMS.txt" >&2
        exit 1
    fi

    if [[ $DOWNLOAD_OK -ne 1 || ! -s "$TEMP_SUMS" ]]; then
        echo "Error: Failed to fetch SHA256SUMS.txt from ${SUMS_URL}" >&2
        echo "Remediation:" >&2
        echo "  1. Ensure the release tag '${TAG}' has been created and pushed to GitHub." >&2
        echo "  2. Ensure GitHub Actions (.github/workflows/release.yml) has finished building artifacts." >&2
        echo "  3. For local or offline dry-runs, run with: $0 --sums-file <path_to_SHA256SUMS.txt> ${VERSION}" >&2
        exit 1
    fi
    SUMS_FILE="$TEMP_SUMS"
fi

# Function to extract and validate a 64-char hex sha256 hash for a filename pattern
extract_hash() {
    local pattern="$1"
    local line
    line="$(grep -Ei "[0-9a-f]{64}[[:space:]]+(\*|\./)?[^[:space:]]*${pattern}" "$SUMS_FILE" | head -n1 || true)"
    if [[ -z "$line" ]]; then
        echo ""
        return
    fi
    local hash
    hash="$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
    if [[ "$hash" =~ ^[0-9a-f]{64}$ ]]; then
        echo "$hash"
    else
        echo ""
    fi
}

echo "==> Extracting SHA-256 hashes from checksums file..."

HASH_LINUX_X86_64="$(extract_hash "x86_64-unknown-linux-musl\.tar\.gz")"
HASH_LINUX_AARCH64="$(extract_hash "aarch64-unknown-linux-musl\.tar\.gz")"
HASH_DARWIN_X86_64="$(extract_hash "x86_64-apple-darwin\.tar\.gz")"
HASH_DARWIN_AARCH64="$(extract_hash "aarch64-apple-darwin\.tar\.gz")"
HASH_WINDOWS_X86_64="$(extract_hash "x86_64-pc-windows-msvc\.zip")"
HASH_WINDOWS_AARCH64="$(extract_hash "aarch64-pc-windows-msvc\.zip")"

MISSING_HASHES=0
check_hash() {
    local name="$1"
    local val="$2"
    if [[ -z "$val" ]]; then
        echo "  [FAIL] Missing or invalid SHA-256 for: ${name}" >&2
        MISSING_HASHES=1
    else
        echo "  [OK]   ${name}: ${val}"
    fi
}

check_hash "Linux x86_64 (musl tar.gz)   " "$HASH_LINUX_X86_64"
check_hash "Linux aarch64 (musl tar.gz) " "$HASH_LINUX_AARCH64"
check_hash "macOS x86_64 (darwin tar.gz) " "$HASH_DARWIN_X86_64"
check_hash "macOS aarch64 (darwin tar.gz)" "$HASH_DARWIN_AARCH64"
check_hash "Windows x86_64 (msvc zip)   " "$HASH_WINDOWS_X86_64"
check_hash "Windows aarch64 (msvc zip)  " "$HASH_WINDOWS_AARCH64"

if [[ $MISSING_HASHES -ne 0 ]]; then
    echo "Error: One or more target archive hashes could not be found in '${SUMS_FILE}'." >&2
    exit 1
fi

echo "==> Updating package manifests in '${REPO_ROOT}'..."

# ------------------------------------------------------------------------------
# 1. Arch Linux AUR (PKGBUILD & .SRCINFO)
# ------------------------------------------------------------------------------
AUR_DIR="${REPO_ROOT}/contrib/packaging/aur"
PKGBUILD="${AUR_DIR}/PKGBUILD"
SRCINFO="${AUR_DIR}/.SRCINFO"

if [[ -f "$PKGBUILD" ]]; then
    awk -v h_x86="$HASH_LINUX_X86_64" -v h_arm="$HASH_LINUX_AARCH64" -v ver="$VERSION" '
        /^pkgver=/ { print "pkgver=" ver; next }
        /^sha256sums_x86_64=/ { print "sha256sums_x86_64=(\x27" h_x86 "\x27)"; next }
        /^sha256sums_aarch64=/ { print "sha256sums_aarch64=(\x27" h_arm "\x27)"; next }
        { print }
    ' "$PKGBUILD" > "${PKGBUILD}.tmp" && mv "${PKGBUILD}.tmp" "$PKGBUILD"
    echo "  [OK] Updated AUR PKGBUILD: ${PKGBUILD}"
else
    echo "  [SKIP] AUR PKGBUILD not found at: ${PKGBUILD}"
fi

if [[ -f "$SRCINFO" ]]; then
    awk -v h_x86="$HASH_LINUX_X86_64" -v h_arm="$HASH_LINUX_AARCH64" -v ver="$VERSION" '
        /^[[:space:]]*pkgver[[:space:]]*=/ { print "\tpkgver = " ver; next }
        /^[[:space:]]*sha256sums_x86_64[[:space:]]*=/ { print "\tsha256sums_x86_64 = " h_x86; next }
        /^[[:space:]]*sha256sums_aarch64[[:space:]]*=/ { print "\tsha256sums_aarch64 = " h_arm; next }
        /^[[:space:]]*source_x86_64[[:space:]]*=/ {
            sub(/\/v[0-9.]+\/frameassembly-v[0-9.]+-/, "/v" ver "/frameassembly-v" ver "-")
            print
            next
        }
        /^[[:space:]]*source_aarch64[[:space:]]*=/ {
            sub(/\/v[0-9.]+\/frameassembly-v[0-9.]+-/, "/v" ver "/frameassembly-v" ver "-")
            print
            next
        }
        { print }
    ' "$SRCINFO" > "${SRCINFO}.tmp" && mv "${SRCINFO}.tmp" "$SRCINFO"
    echo "  [OK] Updated AUR .SRCINFO: ${SRCINFO}"
else
    echo "  [SKIP] AUR .SRCINFO not found at: ${SRCINFO}"
fi

# ------------------------------------------------------------------------------
# 2. Microsoft Windows Package Manager (WinGet)
# ------------------------------------------------------------------------------
WINGET_BASE="${REPO_ROOT}/contrib/packaging/winget/manifests/s/SteveWinschel/FrameAssembly"
WINGET_INSTALLER=""

if [[ -d "$WINGET_BASE" ]]; then
    if [[ -f "${WINGET_BASE}/${VERSION}/SteveWinschel.FrameAssembly.installer.yaml" ]]; then
        WINGET_INSTALLER="${WINGET_BASE}/${VERSION}/SteveWinschel.FrameAssembly.installer.yaml"
    else
        WINGET_INSTALLER="$(find "$WINGET_BASE" -name "SteveWinschel.FrameAssembly.installer.yaml" | sort -V | tail -n1 || true)"
    fi
fi

if [[ -n "$WINGET_INSTALLER" && -f "$WINGET_INSTALLER" ]]; then
    awk -v h_x64="$HASH_WINDOWS_X86_64" -v h_arm64="$HASH_WINDOWS_AARCH64" '
        /Architecture: x64/ { in_x64=1; in_arm64=0 }
        /Architecture: arm64/ { in_arm64=1; in_x64=0 }
        in_x64 && /InstallerSha256:/ {
            sub(/InstallerSha256:[[:space:]]*"[^"]*"/, "InstallerSha256: \"" h_x64 "\"")
            in_x64=0
        }
        in_arm64 && /InstallerSha256:/ {
            sub(/InstallerSha256:[[:space:]]*"[^"]*"/, "InstallerSha256: \"" h_arm64 "\"")
            in_arm64=0
        }
        { print }
    ' "$WINGET_INSTALLER" > "${WINGET_INSTALLER}.tmp" && mv "${WINGET_INSTALLER}.tmp" "$WINGET_INSTALLER"
    echo "  [OK] Updated WinGet Installer Manifest: ${WINGET_INSTALLER}"
else
    echo "  [SKIP] WinGet installer manifest not found under: ${WINGET_BASE}"
fi

# ------------------------------------------------------------------------------
# 3. macOS & Linux Homebrew Tap (Formula/frameassembly.rb)
# ------------------------------------------------------------------------------
HOMEBREW_FORMULA="${REPO_ROOT}/contrib/packaging/homebrew/Formula/frameassembly.rb"

if [[ -f "$HOMEBREW_FORMULA" ]]; then
    awk -v h_mac_arm="$HASH_DARWIN_AARCH64" \
        -v h_mac_x86="$HASH_DARWIN_X86_64" \
        -v h_lin_arm="$HASH_LINUX_AARCH64" \
        -v h_lin_x86="$HASH_LINUX_X86_64" \
        -v ver="$VERSION" '
        /^[[:space:]]*version[[:space:]]+"[^"]*"/ {
            sub(/version[[:space:]]+"[^"]*"/, "version \"" ver "\"")
        }
        /aarch64-apple-darwin/ { target="mac_arm" }
        /x86_64-apple-darwin/ { target="mac_x86" }
        /aarch64-unknown-linux-musl/ { target="lin_arm" }
        /x86_64-unknown-linux-musl/ { target="lin_x86" }
        target == "mac_arm" && /sha256/ {
            sub(/sha256[[:space:]]+"[^"]*"/, "sha256 \"" h_mac_arm "\"")
            target=""
        }
        target == "mac_x86" && /sha256/ {
            sub(/sha256[[:space:]]+"[^"]*"/, "sha256 \"" h_mac_x86 "\"")
            target=""
        }
        target == "lin_arm" && /sha256/ {
            sub(/sha256[[:space:]]+"[^"]*"/, "sha256 \"" h_lin_arm "\"")
            target=""
        }
        target == "lin_x86" && /sha256/ {
            sub(/sha256[[:space:]]+"[^"]*"/, "sha256 \"" h_lin_x86 "\"")
            target=""
        }
        { print }
    ' "$HOMEBREW_FORMULA" > "${HOMEBREW_FORMULA}.tmp" && mv "${HOMEBREW_FORMULA}.tmp" "$HOMEBREW_FORMULA"
    echo "  [OK] Updated Homebrew Formula: ${HOMEBREW_FORMULA}"
else
    echo "  [SKIP] Homebrew formula not found at: ${HOMEBREW_FORMULA}"
fi

# ------------------------------------------------------------------------------
# 4. Windows Scoop (frameassembly.json)
# ------------------------------------------------------------------------------
SCOOP_JSON="${REPO_ROOT}/contrib/packaging/scoop/frameassembly.json"

if [[ -f "$SCOOP_JSON" ]]; then
    awk -v h_64="$HASH_WINDOWS_X86_64" -v h_arm="$HASH_WINDOWS_AARCH64" -v ver="$VERSION" '
        /"version":[[:space:]]*"[^"]*"/ {
            sub(/"version":[[:space:]]*"[^"]*"/, "\"version\": \"" ver "\"")
        }
        /"64bit":[[:space:]]*\{/ { in_64=1; in_arm=0 }
        /"arm64":[[:space:]]*\{/ { in_arm=1; in_64=0 }
        in_64 && /"hash":[[:space:]]*"[^"]*"/ {
            sub(/"hash":[[:space:]]*"[^"]*"/, "\"hash\": \"" h_64 "\"")
            in_64=0
        }
        in_arm && /"hash":[[:space:]]*"[^"]*"/ {
            sub(/"hash":[[:space:]]*"[^"]*"/, "\"hash\": \"" h_arm "\"")
            in_arm=0
        }
        { print }
    ' "$SCOOP_JSON" > "${SCOOP_JSON}.tmp" && mv "${SCOOP_JSON}.tmp" "$SCOOP_JSON"
    echo "  [OK] Updated Scoop Manifest: ${SCOOP_JSON}"
else
    echo "  [SKIP] Scoop manifest not found at: ${SCOOP_JSON}"
fi

echo "======================================================================"
echo "All packaging manifests successfully updated with release SHA-256 sums."
echo "Next Maintainer Steps:"
echo "  1. Review git diff: git diff contrib/packaging/"
echo "  2. Submit WinGet PR: wingetcreate update SteveWinschel.FrameAssembly --version ${VERSION} --submit"
echo "  3. Push AUR update: git commit -am 'chore(release): bump to v${VERSION}' && git push"
echo "  4. Update Homebrew tap: copy Formula/frameassembly.rb to homebrew-tap"
echo "  5. Update Scoop bucket: copy scoop/frameassembly.json to scoop-bucket"
echo "======================================================================"
