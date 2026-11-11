#!/usr/bin/env sh
# ==============================================================================
# FrameAssembly (frameassembly) — Cross-Platform Bootstrap Installer
# https://github.com/SteveWinschel/FrameAssembly
# https://crates.io/crates/frameassembly
#
# Installs the prebuilt FrameAssembly release binary to ~/.cargo/bin (when Rust
# is present) or ~/.local/bin (on systems without Rust), falls back to building
# from crates.io via rustup (>= 1.85) + cargo install if no prebuilt archive is
# available, installs Bash/Zsh/Fish Tab completion scripts, optionally installs
# the VS Code / Cursor / Windsurf / VSCodium / Antigravity extension (.vsix),
# and self-deletes if downloaded as a standalone script file.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
#
# Options (via `sh -s -- [OPTIONS]`):
#   --locked          Pass --locked to cargo install
#   --force           Pass --force to cargo install
#   --vscode          Install the editor extension (.vsix) [default: auto]
#   --no-vscode       Skip automatic editor .vsix extension install
#   --no-completions  Skip installing shell Tab completion scripts
#   --dry-run         Print planned commands without executing system modifications
#   -h, --help        Display this help message and exit
# ==============================================================================

set -eu

CALLER_PATH="${PATH:-}"
REQUIRED_RUST_MAJOR=1
REQUIRED_RUST_MINOR=85
CRATE_NAME="frameassembly"
VSIX_VERSION="2.0.0"
RELEASE_VERSION="2.0.0"
VSIX_RAW_URL="https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/frameassembly-vscode/frameassembly-vscode-${VSIX_VERSION}.vsix"
COMPLETIONS_RAW_BASE="https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/contrib/completions"
GITHUB_RELEASE_BASE="https://github.com/SteveWinschel/FrameAssembly/releases/download/v${RELEASE_VERSION}"
RUSTUP_INIT_URL="https://sh.rustup.rs"

CARGO_LOCKED=0
CARGO_FORCE=0
INSTALL_VSCODE=1
INSTALL_COMPLETIONS=1
DRY_RUN=0
INSTALLED_BIN_DIR=""

log_info() {
    printf '\033[1;34m[FrameAssembly]\033[0m %s\n' "$*"
}

log_ok() {
    printf '\033[1;32m[FrameAssembly]\033[0m %s\n' "$*"
}

log_warn() {
    printf '\033[1;33m[FrameAssembly WARN]\033[0m %s\n' "$*" >&2
}

log_err() {
    printf '\033[1;31m[FrameAssembly ERROR]\033[0m %s\n' "$*" >&2
}

usage() {
    cat <<'EOF'
FrameAssembly (frameassembly) Cross-Platform Bootstrap Installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh -s -- [OPTIONS]

Options:
  --locked          Use locked Cargo.lock dependencies (cargo install --locked)
  --force           Force overwrite an existing frameassembly binary (cargo install --force)
  --vscode          Install the VS Code / Cursor / Windsurf / VSCodium / Antigravity extension (.vsix) [default: auto]
  --no-vscode       Skip installing the editor extension
  --no-completions  Skip installing Bash, Zsh, and Fish Tab completion scripts
  --dry-run         Show detected platform and planned actions without modifying the system
  -h, --help        Show this help message and exit
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --locked)
            CARGO_LOCKED=1
            ;;
        --force)
            CARGO_FORCE=1
            ;;
        --vscode)
            INSTALL_VSCODE=1
            ;;
        --no-vscode)
            INSTALL_VSCODE=0
            ;;
        --no-completions)
            INSTALL_COMPLETIONS=0
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_err "Unknown option: $1"
            usage >&2
            exit 1
            ;;
    esac
    shift
done

run_cmd() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run] $*"
        return 0
    fi
    "$@"
}

run_priv() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run (privileged)] $*"
        return 0
    fi
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    elif command -v doas >/dev/null 2>&1; then
        doas "$@"
    else
        log_err "Root privileges are required to install missing system packages ($*), and neither 'sudo' nor 'doas' was found."
        log_err "Please re-run this script as root or install 'curl' and a C compiler ('cc'/'gcc'/'clang') manually."
        exit 1
    fi
}

has_c_linker() {
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1
}

install_system_prerequisites() {
    need_curl=0
    need_cc=0

    if ! command -v curl >/dev/null 2>&1; then
        need_curl=1
    fi
    if ! has_c_linker; then
        need_cc=1
    fi

    if [ "$need_curl" -eq 0 ] && [ "$need_cc" -eq 0 ]; then
        log_ok "System prerequisites satisfied (curl and C linker found)."
        return 0
    fi

    log_info "Missing system prerequisites detected (need_curl=$need_curl, need_cc=$need_cc). Detecting package manager..."

    if command -v apt-get >/dev/null 2>&1; then
        log_info "Installing prerequisites via apt-get (Debian/Ubuntu)..."
        run_priv apt-get update -y
        run_priv apt-get install -y curl ca-certificates build-essential
    elif command -v dnf >/dev/null 2>&1; then
        log_info "Installing prerequisites via dnf (Fedora/RHEL/Rocky/AlmaLinux)..."
        run_priv dnf install -y curl ca-certificates gcc make
    elif command -v yum >/dev/null 2>&1; then
        log_info "Installing prerequisites via yum (RHEL/CentOS)..."
        run_priv yum install -y curl ca-certificates gcc make
    elif command -v pacman >/dev/null 2>&1; then
        log_info "Installing prerequisites via pacman (Arch Linux/Manjaro)..."
        run_priv pacman -Sy --noconfirm --needed curl ca-certificates base-devel
    elif command -v apk >/dev/null 2>&1; then
        log_info "Installing prerequisites via apk (Alpine Linux)..."
        run_priv apk update
        run_priv apk add --no-cache curl ca-certificates build-base
    elif command -v zypper >/dev/null 2>&1; then
        log_info "Installing prerequisites via zypper (openSUSE/SLES)..."
        run_priv zypper --non-interactive install curl ca-certificates gcc make
    elif command -v brew >/dev/null 2>&1; then
        log_info "Installing prerequisites via Homebrew (macOS/Linuxbrew)..."
        if [ "$need_curl" -eq 1 ]; then
            run_cmd brew install curl ca-certificates
        fi
        if [ "$need_cc" -eq 1 ]; then
            if [ "$(uname -s)" = "Darwin" ] && command -v xcode-select >/dev/null 2>&1; then
                log_info "Requesting Xcode Command Line Tools for C linker on macOS..."
                run_cmd xcode-select --install || run_cmd brew install gcc
            else
                run_cmd brew install gcc
            fi
        fi
    elif command -v pkg >/dev/null 2>&1 && [ "$(uname -s)" = "FreeBSD" ]; then
        log_info "Installing prerequisites via pkg (FreeBSD)..."
        run_priv pkg update -f
        run_priv pkg install -y curl ca_root_nss gcc
    elif command -v xbps-install >/dev/null 2>&1; then
        log_info "Installing prerequisites via xbps-install (Void Linux)..."
        run_priv xbps-install -Sy curl ca-certificates base-devel
    elif command -v emerge >/dev/null 2>&1; then
        log_info "Installing prerequisites via emerge (Gentoo)..."
        run_priv emerge --ask=n net-misc/curl app-misc/ca-certificates sys-devel/gcc
    elif command -v nix-env >/dev/null 2>&1; then
        log_info "Installing prerequisites via nix-env (NixOS/Nix)..."
        run_cmd nix-env -iA nixpkgs.curl nixpkgs.cacert nixpkgs.gcc
    elif command -v opkg >/dev/null 2>&1; then
        log_info "Installing prerequisites via opkg (OpenWrt)..."
        run_priv opkg update
        run_priv opkg install curl ca-bundle gcc make
    elif command -v pkgin >/dev/null 2>&1; then
        log_info "Installing prerequisites via pkgin (NetBSD/SmartOS)..."
        run_priv pkgin -y install curl mozilla-rootcerts gcc
    elif command -v pkg_add >/dev/null 2>&1; then
        log_info "Installing prerequisites via pkg_add (OpenBSD)..."
        run_priv pkg_add curl gcc
    elif command -v swupd >/dev/null 2>&1; then
        log_info "Installing prerequisites via swupd (Clear Linux)..."
        run_priv swupd bundle-add curl c-basic
    elif command -v eopkg >/dev/null 2>&1; then
        log_info "Installing prerequisites via eopkg (Solus)..."
        run_priv eopkg install -y curl ca-certs -c system.devel
    else
        log_err "Could not detect a supported system package manager to install missing prerequisites."
        log_err "Please install 'curl', 'ca-certificates', and a C compiler ('gcc' or 'clang') manually and re-run."
        exit 1
    fi
}

prepend_to_path_if_dir() {
    dir_to_add="$1"
    case ":$PATH:" in
        *":$dir_to_add:"*) ;;
        *)
            if [ -d "$dir_to_add" ]; then
                PATH="$dir_to_add:$PATH"
                export PATH
            fi
            ;;
    esac
}

source_cargo_env() {
    CARGO_ENV_FILE="${CARGO_HOME:-$HOME/.cargo}/env"
    if [ -f "$CARGO_ENV_FILE" ]; then
        # shellcheck disable=SC1090
        . "$CARGO_ENV_FILE"
    fi
    prepend_to_path_if_dir "${CARGO_HOME:-$HOME/.cargo}/bin"
}

resolve_prebuilt_bin_dir() {
    cargo_bin_candidate="${CARGO_HOME:-$HOME/.cargo}/bin"
    cargo_env_candidate="${CARGO_HOME:-$HOME/.cargo}/env"
    if [ -d "$cargo_bin_candidate" ] || [ -f "$cargo_env_candidate" ]; then
        printf '%s' "$cargo_bin_candidate"
    else
        printf '%s' "$HOME/.local/bin"
    fi
}

detect_prebuilt_target() {
    os_name="$(uname -s 2>/dev/null || echo unknown)"
    arch_name="$(uname -m 2>/dev/null || echo unknown)"
    case "${os_name}:${arch_name}" in
        Linux:x86_64|Linux:amd64)
            printf 'x86_64-unknown-linux-musl'
            ;;
        Linux:aarch64|Linux:arm64)
            printf 'aarch64-unknown-linux-musl'
            ;;
        Darwin:x86_64)
            printf 'x86_64-apple-darwin'
            ;;
        Darwin:arm64|Darwin:aarch64)
            printf 'aarch64-apple-darwin'
            ;;
        *)
            return 1
            ;;
    esac
}

try_install_prebuilt_binary() {
    if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
        return 1
    fi
    target_triple="$(detect_prebuilt_target)" || return 1
    archive_url="${GITHUB_RELEASE_BASE}/${CRATE_NAME}-v${RELEASE_VERSION}-${target_triple}.tar.gz"
    bin_dir="$(resolve_prebuilt_bin_dir)"
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run] Checking prebuilt release binary at ${archive_url} -> ${bin_dir}/${CRATE_NAME} (falling back to cargo install if unavailable)"
        return 1
    fi
    tmp_archive="${TMPDIR:-/tmp}/${CRATE_NAME}-${RELEASE_VERSION}-$$.tar.gz"
    tmp_extract="${TMPDIR:-/tmp}/${CRATE_NAME}-extract-$$"
    if curl -fsSL "$archive_url" -o "$tmp_archive" 2>/dev/null; then
        mkdir -p "$tmp_extract" "$bin_dir"
        if tar -xzf "$tmp_archive" -C "$tmp_extract" 2>/dev/null; then
            extracted_bin=""
            if [ -f "${tmp_extract}/${CRATE_NAME}" ]; then
                extracted_bin="${tmp_extract}/${CRATE_NAME}"
            elif command -v find >/dev/null 2>&1; then
                extracted_bin="$(find "$tmp_extract" -type f -name "$CRATE_NAME" 2>/dev/null | head -n 1)"
            fi
            if [ -n "$extracted_bin" ] && [ -f "$extracted_bin" ]; then
                mv -f "$extracted_bin" "${bin_dir}/${CRATE_NAME}"
                chmod +x "${bin_dir}/${CRATE_NAME}"
                rm -rf -- "$tmp_archive" "$tmp_extract"
                INSTALLED_BIN_DIR="$bin_dir"
                prepend_to_path_if_dir "$bin_dir"
                log_ok "Installed prebuilt ${CRATE_NAME} v${RELEASE_VERSION} (${target_triple}) to ${bin_dir}/${CRATE_NAME}."
                return 0
            fi
        fi
    fi
    rm -rf -- "$tmp_archive" "$tmp_extract"
    return 1
}

rust_version_meets_msrv() {
    if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
        return 1
    fi
    ver_str="$(rustc --version 2>/dev/null | awk '{print $2}')"
    major="$(printf '%s' "$ver_str" | cut -d. -f1)"
    minor="$(printf '%s' "$ver_str" | cut -d. -f2)"
    case "$major" in
        ''|*[!0-9]*) return 1 ;;
    esac
    case "$minor" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$major" -gt "$REQUIRED_RUST_MAJOR" ]; then
        return 0
    fi
    if [ "$major" -eq "$REQUIRED_RUST_MAJOR" ] && [ "$minor" -ge "$REQUIRED_RUST_MINOR" ]; then
        return 0
    fi
    return 1
}

ensure_rust_toolchain() {
    source_cargo_env

    if rust_version_meets_msrv; then
        log_ok "Rust toolchain satisfied ($(rustc --version), $(cargo --version))."
        return 0
    fi

    if command -v rustup >/dev/null 2>&1; then
        log_info "Updating existing Rust toolchain via rustup to meet MSRV >= ${REQUIRED_RUST_MAJOR}.${REQUIRED_RUST_MINOR}..."
        run_cmd rustup update stable
        run_cmd rustup default stable
    else
        log_info "Installing Rust toolchain via rustup (${RUSTUP_INIT_URL})..."
        if [ "$DRY_RUN" -eq 1 ]; then
            log_info "[dry-run] curl --proto '=https' --tlsv1.2 -sSf ${RUSTUP_INIT_URL} | sh -s -- -y --default-toolchain stable"
        else
            curl --proto '=https' --tlsv1.2 -sSf "$RUSTUP_INIT_URL" | sh -s -- -y --default-toolchain stable
        fi
    fi

    source_cargo_env

    if [ "$DRY_RUN" -eq 0 ] && ! rust_version_meets_msrv; then
        log_err "Rust >= ${REQUIRED_RUST_MAJOR}.${REQUIRED_RUST_MINOR} is required for FrameAssembly (Edition 2024), but found: $(rustc --version 2>/dev/null || echo 'none')."
        exit 1
    fi
}

install_frameassembly() {
    set -- install
    if [ "$CARGO_LOCKED" -eq 1 ]; then
        set -- "$@" --locked
    fi
    if [ "$CARGO_FORCE" -eq 1 ]; then
        set -- "$@" --force
    fi

    log_info "Installing ${CRATE_NAME} from crates.io (cargo $* ${CRATE_NAME})..."
    run_cmd cargo "$@" "$CRATE_NAME"
    INSTALLED_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
    prepend_to_path_if_dir "$INSTALLED_BIN_DIR"
}

install_single_completion() {
    comp_src_name="$1"
    comp_dest_path="$2"

    local_comp_path=""
    if [ -f "contrib/completions/${comp_src_name}" ]; then
        local_comp_path="contrib/completions/${comp_src_name}"
    else
        case "$0" in
            */*)
                script_dir="$(dirname "$0")"
                if [ -f "${script_dir}/contrib/completions/${comp_src_name}" ]; then
                    local_comp_path="${script_dir}/contrib/completions/${comp_src_name}"
                fi
                ;;
        esac
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[dry-run] Install shell completion ${comp_src_name} -> ${comp_dest_path}"
        return 0
    fi

    comp_dest_dir="$(dirname "$comp_dest_path")"
    mkdir -p "$comp_dest_dir" 2>/dev/null || return 0

    if [ -n "$local_comp_path" ]; then
        cp -f "$local_comp_path" "$comp_dest_path" 2>/dev/null || return 0
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL "${COMPLETIONS_RAW_BASE}/${comp_src_name}" -o "$comp_dest_path" 2>/dev/null || rm -f -- "$comp_dest_path"
    fi
}

install_shell_completions() {
    if [ "$INSTALL_COMPLETIONS" -eq 0 ] || [ -z "${HOME:-}" ]; then
        return 0
    fi

    bash_comp_dest="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/frameassembly"
    if [ -d "${ZDOTDIR:-$HOME}/.zfunc" ]; then
        zsh_comp_dest="${ZDOTDIR:-$HOME}/.zfunc/_frameassembly"
    else
        zsh_comp_dest="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_frameassembly"
    fi
    fish_comp_dest="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/frameassembly.fish"

    install_single_completion "frameassembly.bash" "$bash_comp_dest"
    install_single_completion "_frameassembly" "$zsh_comp_dest"
    install_single_completion "frameassembly.fish" "$fish_comp_dest"
    log_ok "Installed Bash, Zsh, and Fish Tab completions."
}

install_vscode_extension_if_requested() {
    if [ "$INSTALL_VSCODE" -eq 0 ]; then
        return 0
    fi

    detected_editors=""
    for candidate in code cursor windsurf codium agy; do
        if command -v "$candidate" >/dev/null 2>&1; then
            detected_editors="${detected_editors} ${candidate}"
        fi
    done

    if [ -z "$detected_editors" ]; then
        return 0
    fi

    tmp_vsix="${TMPDIR:-/tmp}/frameassembly-vscode-${VSIX_VERSION}-$$.vsix"
    log_info "Downloading FrameAssembly editor extension (v${VSIX_VERSION}) from GitHub..."
    if run_cmd curl -fsSL "$VSIX_RAW_URL" -o "$tmp_vsix"; then
        for editor_cli in $detected_editors; do
            log_info "Installing extension via ${editor_cli}..."
            run_cmd "$editor_cli" --install-extension "$tmp_vsix" || log_warn "${editor_cli} extension install returned non-zero status."
        done
        run_cmd rm -f -- "$tmp_vsix"
    else
        log_warn "Could not download ${VSIX_RAW_URL}; skipping editor extension install."
        run_cmd rm -f -- "$tmp_vsix"
    fi
}

cleanup_self() {
    case "$0" in
        *install.sh)
            if [ ! -d ".git" ] && [ -f "$0" ]; then
                log_info "Cleaning up one-time installer script ($0)..."
                run_cmd rm -f -- "$0"
            fi
            ;;
    esac
}

print_path_hint_if_needed() {
    target_dir="$1"
    [ -z "$target_dir" ] && return 0
    case ":${CALLER_PATH}:" in
        *":${target_dir}:"*)
            return 0
            ;;
    esac

    cargo_env_file="${CARGO_HOME:-$HOME/.cargo}/env"
    if [ "$target_dir" = "${CARGO_HOME:-$HOME/.cargo}/bin" ] && [ -f "$cargo_env_file" ]; then
        log_warn "${target_dir} is not yet in your current shell PATH."
        log_warn "Run: . \"${cargo_env_file}\"  (or restart your terminal)"
    else
        log_warn "${target_dir} is not yet in your current shell PATH."
        log_warn "Run: export PATH=\"${target_dir}:\$PATH\"  (and add that line to ~/.bashrc or ~/.zshrc)"
    fi
}

main() {
    log_info "Starting FrameAssembly (${CRATE_NAME}) bootstrap installer..."
    if ! try_install_prebuilt_binary; then
        install_system_prerequisites
        ensure_rust_toolchain
        install_frameassembly
    fi
    install_shell_completions
    install_vscode_extension_if_requested
    cleanup_self

    if [ "$DRY_RUN" -eq 1 ]; then
        log_ok "Dry run completed successfully."
        exit 0
    fi

    if command -v frameassembly >/dev/null 2>&1; then
        log_ok "Successfully installed $(frameassembly version)!"
        log_info "Quickstart: frameassembly demo.fasm output.pcap && frameassembly show demo.fasm"
        print_path_hint_if_needed "$INSTALLED_BIN_DIR"
    else
        fallback_dir="${INSTALLED_BIN_DIR:-$HOME/.local/bin}"
        print_path_hint_if_needed "$fallback_dir"
    fi
}

main
