#!/usr/bin/env bash
# ==============================================================================
# FrameAssembly (frameassembly) — Standalone Debian (.deb) Package Builder
# https://github.com/SteveWinschel/FrameAssembly
#
# Builds a production-ready Debian/Ubuntu .deb package from a pre-compiled
# FrameAssembly binary using dpkg-deb.
#
# Usage:
#   contrib/packaging/apt/build-deb.sh [VERSION] [BINARY_PATH] [ARCH] [OUTPUT_DIR]
#
# Examples:
#   contrib/packaging/apt/build-deb.sh 1.3.0 target/release/frameassembly amd64 dist
#   contrib/packaging/apt/build-deb.sh 1.3.0 target/aarch64-unknown-linux-musl/release/frameassembly arm64 dist
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

VERSION="${1:-1.4.1}"
VERSION="${VERSION#v}" # strip leading 'v' if provided

BINARY_PATH="${2:-}"
if [[ -z "${BINARY_PATH}" ]]; then
    if [[ -f "${REPO_ROOT}/target/release/frameassembly" ]]; then
        BINARY_PATH="${REPO_ROOT}/target/release/frameassembly"
    elif [[ -f "${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/frameassembly" ]]; then
        BINARY_PATH="${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/frameassembly"
    elif [[ -f "${REPO_ROOT}/target/debug/frameassembly" ]]; then
        BINARY_PATH="${REPO_ROOT}/target/debug/frameassembly"
    else
        BINARY_PATH="${REPO_ROOT}/target/release/frameassembly"
    fi
fi

TARGET_ARCH="${3:-}"
if [[ -z "${TARGET_ARCH}" ]]; then
    HOST_ARCH="$(uname -m)"
    case "${HOST_ARCH}" in
        x86_64|amd64)
            TARGET_ARCH="amd64"
            ;;
        aarch64|arm64)
            TARGET_ARCH="arm64"
            ;;
        *)
            TARGET_ARCH="amd64"
            ;;
    esac
fi

OUTPUT_DIR="${4:-${REPO_ROOT}/dist}"

if [[ ! -f "${BINARY_PATH}" ]]; then
    echo "ERROR: FrameAssembly binary not found at: ${BINARY_PATH}" >&2
    echo "Please build the binary first (e.g. 'cargo build --release') or supply the exact path." >&2
    exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "ERROR: 'dpkg-deb' command not found. Please install dpkg (e.g. 'apt-get install dpkg')." >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

STAGE_DIR="$(mktemp -d -t fasm-deb-XXXXXX)"
trap 'rm -rf -- "${STAGE_DIR}"' EXIT

mkdir -p "${STAGE_DIR}/DEBIAN"
mkdir -p "${STAGE_DIR}/usr/bin"
mkdir -p "${STAGE_DIR}/usr/share/doc/frameassembly"

# 1. Install executable binary (mode 755)
cp "${BINARY_PATH}" "${STAGE_DIR}/usr/bin/frameassembly"
chmod 755 "${STAGE_DIR}/usr/bin/frameassembly"

# 2. Install documentation and copyright files (mode 644)
if [[ -f "${REPO_ROOT}/README.md" ]]; then
    cp "${REPO_ROOT}/README.md" "${STAGE_DIR}/usr/share/doc/frameassembly/README.md"
    chmod 644 "${STAGE_DIR}/usr/share/doc/frameassembly/README.md"
fi

if [[ -f "${SCRIPT_DIR}/debian/copyright" ]]; then
    cp "${SCRIPT_DIR}/debian/copyright" "${STAGE_DIR}/usr/share/doc/frameassembly/copyright"
    chmod 644 "${STAGE_DIR}/usr/share/doc/frameassembly/copyright"
elif [[ -f "${REPO_ROOT}/LICENSE" ]]; then
    cp "${REPO_ROOT}/LICENSE" "${STAGE_DIR}/usr/share/doc/frameassembly/copyright"
    chmod 644 "${STAGE_DIR}/usr/share/doc/frameassembly/copyright"
fi

# 3. Install MIME and magic definitions (mode 644)
if [[ -f "${REPO_ROOT}/contrib/mime/text-vnd.frameassembly.xml" ]]; then
    mkdir -p "${STAGE_DIR}/usr/share/mime/packages"
    cp "${REPO_ROOT}/contrib/mime/text-vnd.frameassembly.xml" "${STAGE_DIR}/usr/share/mime/packages/text-vnd.frameassembly.xml"
    chmod 644 "${STAGE_DIR}/usr/share/mime/packages/text-vnd.frameassembly.xml"
fi

if [[ -f "${REPO_ROOT}/contrib/magic/frameassembly.magic" ]]; then
    mkdir -p "${STAGE_DIR}/usr/share/file/magic"
    cp "${REPO_ROOT}/contrib/magic/frameassembly.magic" "${STAGE_DIR}/usr/share/file/magic/frameassembly"
    chmod 644 "${STAGE_DIR}/usr/share/file/magic/frameassembly"
fi

# 4. Generate DEBIAN/control file for specific architecture and version
cat > "${STAGE_DIR}/DEBIAN/control" <<EOF
Package: frameassembly
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${TARGET_ARCH}
Maintainer: Steve Winschel <https://github.com/SteveWinschel/FrameAssembly>
Description: Rootless Packets-as-Code DSL and compiler
 FrameAssembly compiles declarative .fasm specifications into deterministic,
 nanosecond-precision .pcap and .pcapng packet captures across 81 native
 Layer 2 through Layer 7 protocols for Wireshark, tcpreplay, Suricata, and Zeek.
Homepage: https://github.com/SteveWinschel/FrameAssembly
EOF

chmod 644 "${STAGE_DIR}/DEBIAN/control"

DEB_FILENAME="frameassembly_${VERSION}_${TARGET_ARCH}.deb"
OUTPUT_FILE="${OUTPUT_DIR}/${DEB_FILENAME}"

echo "Building Debian package: ${OUTPUT_FILE}..."
if dpkg-deb --help | grep -q -- '--root-owner-group'; then
    dpkg-deb --build --root-owner-group "${STAGE_DIR}" "${OUTPUT_FILE}"
else
    dpkg-deb --build "${STAGE_DIR}" "${OUTPUT_FILE}"
fi

echo "Successfully built Debian package: ${OUTPUT_FILE}"

# Emit unversioned deb alias alongside versioned package (e.g. frameassembly_amd64.deb)
UNVERSIONED_DEB="frameassembly_${TARGET_ARCH}.deb"
cp -f "${OUTPUT_FILE}" "${OUTPUT_DIR}/${UNVERSIONED_DEB}"
echo "Emitted unversioned Debian package alias: ${OUTPUT_DIR}/${UNVERSIONED_DEB}"

dpkg-deb --info "${OUTPUT_FILE}"
echo "--- Package contents ---"
dpkg-deb --contents "${OUTPUT_FILE}"
