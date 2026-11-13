#!/usr/bin/env bash
# FrameAssembly Manifest Checksum Updater
# Stamping release SHA-256 hashes across Homebrew and Scoop manifests.

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
  VERSION | TAG            Release version (e.g. '3.0.0' or 'v3.0.0').
                           If omitted, auto-detected from Cargo.toml.

Options:
  -s, --sums-file <PATH>   Path to local SHA256SUMS.txt file (for testing/dry-run).
                           If omitted, downloads from GitHub Releases for TAG.
  -r, --repo-root <PATH>   Path to repository root (defaults to auto-detected root).
  -h, --help               Show this help message and exit.

Manifests Updated:
  1. macOS & Linux Brew:   contrib/packaging/homebrew/Formula/frameassembly.rb
  2. Windows Scoop:        contrib/packaging/scoop/frameassembly.json
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
fi

if [[ -z "$VERSION" ]]; then
    echo "Error: Version could not be determined. Please specify VERSION (e.g. 3.0.0 or v3.0.0)." >&2
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
    line="$(grep -Ei "^[0-9a-f]{64}[[:space:]]+(\*|\./)?[^[:space:]]*${pattern}([[:space:]]|\$)" "$SUMS_FILE" | head -n1 || true)"
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

extract_hash_with_fallback() {
    local primary_pattern="$1"
    local legacy_pattern="$2"
    local h
    h="$(extract_hash "$primary_pattern")"
    if [[ -z "$h" ]]; then
        h="$(extract_hash "$legacy_pattern")"
    fi
    echo "$h"
}

echo "==> Extracting SHA-256 hashes from checksums file..."

HASH_LINUX_X86_64="$(extract_hash_with_fallback "frameassembly-linux-x64\.tar\.gz" "x86_64-unknown-linux-musl\.tar\.gz")"
HASH_LINUX_AARCH64="$(extract_hash_with_fallback "frameassembly-linux-arm64\.tar\.gz" "aarch64-unknown-linux-musl\.tar\.gz")"
HASH_DARWIN_X86_64="$(extract_hash_with_fallback "frameassembly-macos-x64\.tar\.gz" "x86_64-apple-darwin\.tar\.gz")"
HASH_DARWIN_AARCH64="$(extract_hash_with_fallback "frameassembly-macos-arm64\.tar\.gz" "aarch64-apple-darwin\.tar\.gz")"
HASH_WINDOWS_X86_64="$(extract_hash_with_fallback "frameassembly-windows-x64\.zip" "x86_64-pc-windows-msvc\.zip")"
HASH_WINDOWS_AARCH64="$(extract_hash_with_fallback "frameassembly-windows-arm64\.zip" "aarch64-pc-windows-msvc\.zip")"

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

check_hash "Linux x64 (tar.gz)    " "$HASH_LINUX_X86_64"
check_hash "Linux arm64 (tar.gz)  " "$HASH_LINUX_AARCH64"
check_hash "macOS x64 (tar.gz)    " "$HASH_DARWIN_X86_64"
check_hash "macOS arm64 (tar.gz)  " "$HASH_DARWIN_AARCH64"
check_hash "Windows x64 (zip)     " "$HASH_WINDOWS_X86_64"
check_hash "Windows arm64 (zip)   " "$HASH_WINDOWS_AARCH64"

if [[ $MISSING_HASHES -ne 0 ]]; then
    echo "Error: One or more target archive hashes could not be found in '${SUMS_FILE}'." >&2
    exit 1
fi

echo "==> Updating package manifests in '${REPO_ROOT}'..."

# ------------------------------------------------------------------------------
# 1. macOS & Linux Homebrew Tap (Formula/frameassembly.rb)
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
        /\/v[0-9.]+\/frameassembly-v[0-9.]+-/ {
            gsub(/\/v[0-9.]+\/frameassembly-v[0-9.]+-/, "/v" ver "/frameassembly-v" ver "-")
        }
        /\/v[0-9.]+\/frameassembly-(linux|macos)-/ {
            gsub(/\/v[0-9.]+\/frameassembly-/, "/v" ver "/frameassembly-")
        }
        /assert_match[[:space:]]+"frameassembly[[:space:]][0-9.]+"/ {
            sub(/frameassembly[[:space:]][0-9.]+/, "frameassembly " ver)
        }
        /frameassembly-macos-arm64\.tar\.gz|aarch64-apple-darwin/ { target="mac_arm" }
        /frameassembly-macos-x64\.tar\.gz|x86_64-apple-darwin/ { target="mac_x86" }
        /frameassembly-linux-arm64\.tar\.gz|aarch64-unknown-linux-musl/ { target="lin_arm" }
        /frameassembly-linux-x64\.tar\.gz|x86_64-unknown-linux-musl/ { target="lin_x86" }
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
# 2. Windows Scoop (frameassembly.json)
# ------------------------------------------------------------------------------
SCOOP_JSON="${REPO_ROOT}/contrib/packaging/scoop/frameassembly.json"

if [[ -f "$SCOOP_JSON" ]]; then
    awk -v h_64="$HASH_WINDOWS_X86_64" -v h_arm="$HASH_WINDOWS_AARCH64" -v ver="$VERSION" '
        /"version":[[:space:]]*"[^"]*"/ {
            sub(/"version":[[:space:]]*"[^"]*"/, "\"version\": \"" ver "\"")
        }
        /\/v[0-9.]+\/frameassembly-v[0-9.]+-/ {
            gsub(/\/v[0-9.]+\/frameassembly-v[0-9.]+-/, "/v" ver "/frameassembly-v" ver "-")
        }
        /\/v[0-9.]+\/frameassembly-windows-/ {
            gsub(/\/v[0-9.]+\/frameassembly-windows-/, "/v" ver "/frameassembly-windows-")
        }
        /"extract_dir":[[:space:]]*"frameassembly-v[0-9.]+-/ {
            sub(/frameassembly-v[0-9.]+-/, "frameassembly-v" ver "-")
        }
        /"autoupdate":[[:space:]]*\{/ { in_auto=1 }
        !in_auto && /"64bit":[[:space:]]*\{/ { in_64=1; in_arm=0 }
        !in_auto && /"arm64":[[:space:]]*\{/ { in_arm=1; in_64=0 }
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
echo "  2. Sync Homebrew Formula/frameassembly.rb and Scoop bucket/frameassembly.json to:"
echo "     https://github.com/SteveWinschel/homebrew-tap-FrameAssembly"
echo "======================================================================"
