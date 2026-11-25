//! End-to-end integration test suite for the `frameassembly update` self-update subcommand,
//! five-subcommand CLI contract, bootstrap installers (`install.sh` and `install.ps1`), and
//! four-shell Tab completion scripts (`bash`, `zsh`, `fish`, and `powershell`).
//!
//! This test harness exercises the compiled `frameassembly` binary via Cargo's
//! `CARGO_BIN_EXE_frameassembly` environment variable without hardcoding `target/` paths or
//! performing live network requests:
//! 1. **Root Help & Version Discovery**: Verifies `frameassembly help` lists all five subcommands
//!    (`show`, `reverse`, `update`, `version`, `help`) while hiding `--help`, `--version`, `-o`,
//!    and `--output`.
//! 2. **`update` Help Symmetry**: Verifies `frameassembly help update`, `frameassembly update -h`,
//!    and `frameassembly update --help` exit `0`, describe updating `frameassembly`, and hide
//!    `--help` and `--output`.
//! 3. **Zero-Flag & Legacy Flag Guards**: Verifies `clap` rejects unknown flags and positional
//!    arguments on `update` with exit code `2`, while `check_legacy_cli_args` rejects `-o` and
//!    `--output` with exit code `1` and migration guidance.
//! 4. **Bootstrap Installer Verification**: Verifies `install.sh` and `install.ps1` MSRV `1.89`,
//!    `v3.3.0` pins, atomic temp-file staging, `--help`, `--dry-run`, and fail-closed `--offline`
//!    `SHA256SUMS.txt` verification.
//! 5. **Shell Completion & Hermetic Self-Update Execution**: Verifies all four completion scripts
//!    complete `update` alongside `show`, `reverse`, `version`, and `help`, validates `bash -n`
//!    and live `COMPREPLY` behavior on Unix, and exercises hermetic mocked `frameassembly update`
//!    flows (up-to-date, Crates.io sparse-index fallback, Cargo-first de-shadowing, and fail-closed
//!    `sha2` prebuilt binary replacement).

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// Canonical five top-level subcommands exposed by FrameAssembly v3.3.0.
const EXPECTED_SUBCOMMANDS: [&str; 5] = ["show", "reverse", "update", "version", "help"];

/// Returns the compiled `frameassembly` binary path injected by Cargo (`CARGO_BIN_EXE_frameassembly`).
fn cli_bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_frameassembly"))
}

/// Returns the workspace root directory injected by Cargo (`CARGO_MANIFEST_DIR`).
fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Invokes the compiled `frameassembly` CLI with deterministic non-colored output settings.
fn run_frameassembly(args: &[&str]) -> Output {
    Command::new(cli_bin())
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("CARGO_TERM_COLOR")
        .output()
        .expect("failed to execute frameassembly CLI binary")
}

// ============================================================================
// 1. Root Help, Version & Five-Subcommand Discovery
// ============================================================================

/// Verifies that `frameassembly help` (plus `-h` and `--help` script compatibility flags) exits `0`,
/// lists all five subcommands (`show`, `reverse`, `update`, `version`, `help`), and hides `--help`,
/// `--version`, `-o`, and `--output`.
#[test]
fn test_root_help_lists_all_five_subcommands_and_hides_internal_flags() {
    let help_sub = run_frameassembly(&["help"]);
    assert_eq!(
        help_sub.status.code(),
        Some(0),
        "frameassembly help must exit 0, stderr:\n{}",
        String::from_utf8_lossy(&help_sub.stderr)
    );
    assert!(help_sub.stderr.is_empty());

    let stdout = String::from_utf8_lossy(&help_sub.stdout);
    assert!(stdout.contains("<INPUT.frasm>") && stdout.contains("[OUTPUT.pcap]"));
    for sub in EXPECTED_SUBCOMMANDS {
        assert!(
            stdout.contains(sub),
            "root help must list '{sub}':\n{stdout}"
        );
    }
    for hidden in [
        "--help",
        "-h",
        "--version",
        "-V",
        "-o",
        "--output",
        "DSL",
        ".fasm",
    ] {
        assert!(
            !stdout.contains(hidden),
            "root help must hide '{hidden}':\n{stdout}"
        );
    }

    for help_flag in ["-h", "--help"] {
        let out = run_frameassembly(&[help_flag]);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout), stdout);
    }

    let expected_ver = format!("frameassembly {}", env!("CARGO_PKG_VERSION"));
    for ver_args in [&["version"][..], &["-V"][..], &["--version"][..]] {
        let out = run_frameassembly(ver_args);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected_ver);
    }
}

// ============================================================================
// 2. `update` Subcommand Help Symmetry & Hidden-Flag Hygiene
// ============================================================================

/// Verifies that `frameassembly help update`, `frameassembly update -h`, and
/// `frameassembly update --help` all exit `0`, render identical help text describing updating
/// `frameassembly`, and omit `--help` and `--output`.
#[test]
fn test_update_help_subcommand_short_and_long_flags_match_and_hide_flags() {
    let variants: &[&[&str]] = &[
        &["help", "update"],
        &["update", "-h"],
        &["update", "--help"],
    ];

    let mut canonical_help: Option<String> = None;
    for args in variants {
        let out = run_frameassembly(args);
        assert_eq!(out.status.code(), Some(0), "{args:?} must exit 0");
        assert!(out.stderr.is_empty(), "{args:?} must emit empty stderr");

        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("update") && lower.contains("frameassembly"),
            "{args:?} must describe updating frameassembly:\n{text}"
        );
        assert!(text.contains("Usage: frameassembly update"));
        for hidden in ["--help", "-h", "--version", "-V", "-o", "--output"] {
            assert!(
                !text.contains(hidden),
                "{args:?} must omit '{hidden}':\n{text}"
            );
        }

        if let Some(prev) = &canonical_help {
            assert_eq!(&text, prev, "help mismatch on {args:?}");
        } else {
            canonical_help = Some(text);
        }
    }
}

// ============================================================================
// 3. Zero-Flag Enforcement & Legacy Flag Rejection on `update`
// ============================================================================

/// Verifies that `frameassembly update` accepts zero flags and zero positional arguments, exiting
/// with clap error code `2` on unknown flags or unexpected positional tokens.
#[test]
fn test_update_rejects_unknown_flags_and_extra_positional_args_via_clap() {
    for bad_flag in ["--unknown-flag", "--force", "--check", "--yes", "-y"] {
        let out = run_frameassembly(&["update", bad_flag]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "'update {bad_flag}' must exit 2"
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains(bad_flag));
    }

    for extra_arg in ["extra_positional_arg", "v3.3.0", "capture.pcap"] {
        let out = run_frameassembly(&["update", extra_arg]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "'update {extra_arg}' must exit 2"
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains(extra_arg));
    }
}

/// Verifies that legacy `-o` / `--output` (and `--show` / `--reverse`) flags passed alongside
/// `update` exit `1` via `check_legacy_cli_args` with actionable FrameAssembly migration hints.
#[test]
fn test_update_rejects_legacy_output_show_and_reverse_flags_with_migration_hints() {
    let output_cases: &[&[&str]] = &[
        &["update", "-o", "foo"],
        &["update", "--output", "foo"],
        &["update", "--output=foo"],
        &["update", "-ofoo"],
    ];

    for args in output_cases {
        let out = run_frameassembly(args);
        assert_eq!(out.status.code(), Some(1), "{args:?} must exit 1");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("-o") && stderr.contains("--output"));
        assert!(
            stderr.contains("Compile: frameassembly <in.frasm> [out.pcap]")
                && stderr.contains("Reverse: frameassembly reverse <in.pcap> [out.frasm]"),
            "{args:?} missing migration hints:\n{stderr}"
        );
    }

    let show_out = run_frameassembly(&["update", "--show"]);
    assert_eq!(show_out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&show_out.stderr).contains("frameassembly show <in.frasm>"));

    let rev_out = run_frameassembly(&["update", "--reverse"]);
    assert_eq!(rev_out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&rev_out.stderr)
            .contains("frameassembly reverse <in.pcap> [out.frasm]")
    );
}

// ============================================================================
// 4. Cross-Platform Installer Invariants (`install.sh` & `install.ps1`)
// ============================================================================

/// Verifies static version lockstep (`3.3.0`), MSRV `1.89`, fail-closed `SHA256SUMS.txt` checks,
/// and OS-safe atomic binary staging across both `install.sh` and `install.ps1`.
#[test]
fn test_installers_static_invariants_msrv_1_89_version_3_3_0_and_atomic_staging() {
    let pkg_ver = env!("CARGO_PKG_VERSION");

    let install_sh =
        fs::read_to_string(repo_root().join("install.sh")).expect("failed to read install.sh");
    assert!(
        install_sh.contains("REQUIRED_RUST_MAJOR=1")
            && install_sh.contains("REQUIRED_RUST_MINOR=89"),
        "install.sh must enforce MSRV 1.89"
    );
    assert!(
        install_sh.contains(&format!("RELEASE_VERSION=\"{pkg_ver}\""))
            && install_sh.contains(&format!("VSIX_VERSION=\"{pkg_ver}\"")),
        "install.sh must pin RELEASE_VERSION and VSIX_VERSION to {pkg_ver}"
    );
    assert!(
        install_sh.contains("staged_bin=\"${bin_dir}/.${CRATE_NAME}.install.$$.tmp\"")
            && install_sh.contains("cp -f \"$extracted_bin\" \"$staged_bin\"")
            && install_sh.contains("chmod 0755 \"$staged_bin\"")
            && install_sh.contains("mv -f \"$staged_bin\" \"${bin_dir}/${CRATE_NAME}\""),
        "install.sh must stage into a sibling temp file, chmod 0755, and atomically mv -f"
    );
    assert!(
        !install_sh.contains("cp -f \"$extracted_bin\" \"${bin_dir}/${CRATE_NAME}\""),
        "install.sh must never cp -f directly onto target binary"
    );

    let install_ps1 =
        fs::read_to_string(repo_root().join("install.ps1")).expect("failed to read install.ps1");
    assert!(
        install_ps1.contains(&format!("$ReleaseVersion = '{pkg_ver}'"))
            && install_ps1.contains(&format!("$VsixVersion = '{pkg_ver}'")),
        "install.ps1 must pin $ReleaseVersion and $VsixVersion to {pkg_ver}"
    );
    assert!(
        install_ps1.contains(".frameassembly.install.")
            && install_ps1.contains("frameassembly.exe.old")
            && install_ps1.contains("Move-Item -Path $exeStage -Destination $exeDest -Force"),
        "install.ps1 must stage to .tmp and swap locked Windows binaries via frameassembly.exe.old"
    );
}

// ============================================================================
// 5. Four-Shell Tab Completion Verification (`bash`, `zsh`, `fish`, `ps1`)
// ============================================================================

/// Verifies that all four shell completion scripts (`frameassembly.bash`, `_frameassembly`,
/// `frameassembly.fish`, and `frameassembly.ps1`) complete `update` alongside `show`, `reverse`,
/// `version`, and `help`, treat `update` as a zero-argument subcommand, and contain zero legacy
/// `.fasm` tokens.
#[test]
fn test_all_four_shell_completion_scripts_complete_five_subcommands_including_update() {
    let completions_dir = repo_root().join("contrib/completions");
    for name in [
        "frameassembly.bash",
        "_frameassembly",
        "frameassembly.fish",
        "frameassembly.ps1",
    ] {
        let bytes = fs::read(completions_dir.join(name)).expect("read completion script");
        assert!(!bytes.is_empty() && !bytes.contains(&0));
        let text = String::from_utf8(bytes).expect("valid UTF-8 completion script");
        for sub in EXPECTED_SUBCOMMANDS {
            assert!(text.contains(sub), "{name} must complete '{sub}'");
        }
        assert!(!text.contains(".fasm"), "{name} must not reference .fasm");
    }

    let bash_src = fs::read_to_string(completions_dir.join("frameassembly.bash")).unwrap();
    assert!(bash_src.contains("compgen -W \"show reverse update version help\""));
    assert!(bash_src.contains("update|version|-?*)"));

    let zsh_src = fs::read_to_string(completions_dir.join("_frameassembly")).unwrap();
    assert!(zsh_src.starts_with("#compdef frameassembly"));
    assert!(zsh_src.contains("'update:Update frameassembly to the newest release'"));
    assert!(zsh_src.contains("update|version|-?*)"));

    let fish_src = fs::read_to_string(completions_dir.join("frameassembly.fish")).unwrap();
    assert!(fish_src.contains("not contains -- \"$tokens[2]\" show reverse update version help"));
    assert!(fish_src.contains("-a update -d \"Update frameassembly to the newest release\""));
    assert!(fish_src.contains(
        "complete -c frameassembly -n \"__fish_frameassembly_subcmd_arg help 1\" -a \"show reverse update version help\""
    ));

    let ps1_src = fs::read_to_string(completions_dir.join("frameassembly.ps1")).unwrap();
    assert!(ps1_src.contains("Register-ArgumentCompleter -Native -CommandName frameassembly"));
    assert!(ps1_src.contains("Name = 'update'") && ps1_src.contains("'update' {"));
}

// ============================================================================
// 6. Unix Live Installer, Bash Completion & Hermetic Self-Update E2E Tests
// ============================================================================

/// Unix-specific execution tests for `install.sh`, `bash -n` / `COMPREPLY`, and hermetic
/// `frameassembly update` binary self-replacement.
#[cfg(unix)]
mod unix_installer_and_updater_tests {
    use super::{EXPECTED_SUBCOMMANDS, cli_bin, repo_root};
    use sha2::{Digest, Sha256};
    use std::ffi::OsString;
    use std::fmt::Write as _;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic counter isolating per-test temporary directories across parallel threads.
    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// RAII temporary directory guard under `std::env::temp_dir()` cleaned up automatically on drop.
    struct TempTestDir {
        /// Absolute path to the isolated temporary directory.
        path: PathBuf,
    }

    impl TempTestDir {
        /// Creates a new uniquely named directory under `std::env::temp_dir()`.
        fn new(prefix: &str) -> Self {
            let id = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir_name = format!(
                "frameassembly_update_test_{}_{}_{}",
                prefix,
                std::process::id(),
                id
            );
            let path = std::env::temp_dir().join(dir_name);
            fs::create_dir_all(&path).expect("failed to create isolated temporary test directory");
            Self { path }
        }

        /// Joins a relative child path onto this temporary directory.
        fn join(&self, rel: &str) -> PathBuf {
            self.path.join(rel)
        }

        /// Borrows the temporary directory root path.
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Writes an executable POSIX shell script with mode `0755`.
    fn write_executable_script(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create script parent");
        }
        fs::write(path, content).expect("write script");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
    }

    /// Computes the lowercase 64-character hex SHA-256 digest of `file_path`.
    fn compute_file_sha256_hex(file_path: &Path) -> String {
        let digest = Sha256::digest(fs::read(file_path).expect("read file for sha256"));
        let mut hex = String::with_capacity(64);
        for b in digest {
            let _ = write!(hex, "{b:02x}");
        }
        hex
    }

    /// Searches `PATH` (plus `/usr/bin` and `/bin`) for an executable host utility.
    fn find_host_tool(name: &str) -> Option<PathBuf> {
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        dirs.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
        dirs.into_iter()
            .map(|d| d.join(name))
            .find(|c| c.is_file() && c.metadata().is_ok_and(|m| m.mode() & 0o111 != 0))
    }

    /// Populates a minimal isolated `mock_bin` with symlinks to `cat`, `cp`, `chmod`, `tar`, and
    /// `gzip` plus an offline `curl` shim driven by `MOCK_*` environment variables.
    fn setup_hermetic_mock_bin(mock_bin: &Path) {
        fs::create_dir_all(mock_bin).expect("create mock_bin");
        for tool in ["cat", "cp", "chmod", "tar", "gzip"] {
            if let Some(src) = find_host_tool(tool) {
                let dst = mock_bin.join(tool);
                if !dst.exists() {
                    symlink(&src, &dst).expect("symlink tool");
                }
            }
        }
        let curl_shim = r#"#!/bin/sh
set -eu
out_file=""
write_out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out_file="$2"; shift 2 ;;
        -w) write_out="$2"; shift 2 ;;
        --proto) shift 2 ;;
        --tlsv1.2|-fsSL|-fsSLI) shift ;;
        http://*|https://*) url="$1"; shift ;;
        *) shift ;;
    esac
done
if [ -n "$write_out" ]; then
    [ -n "${MOCK_EFFECTIVE_URL:-}" ] && { printf '%s\n' "$MOCK_EFFECTIVE_URL"; exit 0; }
    exit 22
fi
case "$url" in
    *index.crates.io/fr/am/frameassembly)
        [ -n "${MOCK_CRATES_NDJSON_FILE:-}" ] && [ -f "$MOCK_CRATES_NDJSON_FILE" ] && { cat "$MOCK_CRATES_NDJSON_FILE"; exit 0; }
        exit 22 ;;
    */SHA256SUMS.txt)
        [ -n "$out_file" ] && [ -n "${MOCK_SUMS_FILE:-}" ] && [ -f "$MOCK_SUMS_FILE" ] && { cp "$MOCK_SUMS_FILE" "$out_file"; exit 0; }
        exit 22 ;;
    *.tar.gz)
        [ -n "$out_file" ] && [ -n "${MOCK_ARCHIVE_FILE:-}" ] && [ -f "$MOCK_ARCHIVE_FILE" ] && { cp "$MOCK_ARCHIVE_FILE" "$out_file"; exit 0; }
        exit 22 ;;
    *) exit 22 ;;
esac
"#;
        write_executable_script(&mock_bin.join("curl"), curl_shim);
    }

    /// Builds a `Command` invoking `exe update` inside a hermetic `HOME` / `CARGO_HOME` / `PATH`.
    fn hermetic_update_cmd(exe: &Path, mock_bin: &Path, home: &Path, cargo_home: &Path) -> Command {
        let mut cmd = Command::new(exe);
        cmd.arg("update")
            .env("PATH", mock_bin)
            .env("HOME", home)
            .env("CARGO_HOME", cargo_home)
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("ZDOTDIR", home)
            .env_remove("CC");
        cmd
    }

    /// Executes `sh <installer> --offline <archive> --no-vscode --no-completions` in isolated dirs.
    fn run_offline_installer(installer: &Path, archive: &Path, home: &Path, tmp: &Path) -> Output {
        Command::new("sh")
            .arg(installer)
            .arg("--offline")
            .arg(archive)
            .args(["--no-vscode", "--no-completions"])
            .env("HOME", home)
            .env("CARGO_HOME", home.join(".cargo_absent"))
            .env("TMPDIR", tmp)
            .output()
            .expect("run install.sh --offline")
    }

    /// Verifies `sh install.sh --help` and `sh install.sh --dry-run --no-vscode --no-completions`
    /// exit `0`, advertise supported flags, and perform zero filesystem writes.
    #[test]
    fn test_install_sh_help_and_dry_run_execution() {
        let install_sh = repo_root().join("install.sh");

        for help_flag in ["--help", "-h"] {
            let help_out = Command::new("sh")
                .arg(&install_sh)
                .arg(help_flag)
                .current_dir(repo_root())
                .output()
                .expect("run sh install.sh --help");
            assert_eq!(help_out.status.code(), Some(0));
            let stdout = String::from_utf8_lossy(&help_out.stdout);
            for required in [
                "cargo install frameassembly",
                "--offline",
                "--skip-checksum",
                "--no-vscode",
                "--no-completions",
                "--dry-run",
            ] {
                assert!(
                    stdout.contains(required),
                    "missing '{required}' in:\n{stdout}"
                );
            }
        }

        let temp = TempTestDir::new("install_dry_run");
        let isolated_home = temp.join("home");
        let fallback_bin = temp.join("fallback_bin");
        fs::create_dir_all(&isolated_home).unwrap();
        write_executable_script(&fallback_bin.join("curl"), "#!/bin/sh\nexit 0\n");

        let mut path_entries: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        path_entries.push(fallback_bin);
        let joined_path = std::env::join_paths(path_entries).unwrap_or_else(|_| OsString::new());

        let dry_out = Command::new("sh")
            .arg(&install_sh)
            .args(["--dry-run", "--no-vscode", "--no-completions"])
            .current_dir(repo_root())
            .env("HOME", &isolated_home)
            .env("CARGO_HOME", isolated_home.join(".cargo_absent"))
            .env("PATH", &joined_path)
            .output()
            .expect("run sh install.sh --dry-run");
        assert_eq!(dry_out.status.code(), Some(0));

        let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
        assert!(dry_stdout.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))));
        assert!(dry_stdout.contains("Dry run completed successfully."));
        assert!(!isolated_home.join(".local/bin/frameassembly").exists());
    }

    /// Verifies `sh install.sh --offline` fails closed on missing or tampered `SHA256SUMS.txt`
    /// and atomically replaces an existing binary inode via `mv -f` when the SHA-256 digest matches.
    #[test]
    fn test_install_sh_offline_sha256_fail_closed_and_atomic_inode_swap() {
        let Some(tar_exe) = find_host_tool("tar") else {
            return;
        };
        if !["sha256sum", "shasum", "openssl"]
            .into_iter()
            .any(|t| find_host_tool(t).is_some())
        {
            return;
        }

        let temp = TempTestDir::new("install_offline");
        let (home, bundle_src, dist_dir, tmp_dir) = (
            temp.join("home"),
            temp.join("bundle_src"),
            temp.join("dist"),
            temp.join("tmp"),
        );
        for d in [&home, &bundle_src, &dist_dir, &tmp_dir] {
            fs::create_dir_all(d).unwrap();
        }

        let temp_installer = temp.join("install.sh");
        fs::copy(repo_root().join("install.sh"), &temp_installer).unwrap();
        write_executable_script(
            &bundle_src.join("frameassembly"),
            "#!/bin/sh\necho \"frameassembly 3.3.0\"\n",
        );

        let archive_name = "frameassembly-linux-x64.tar.gz";
        let archive_path = dist_dir.join(archive_name);
        let tar_st = Command::new(tar_exe)
            .arg("-czf")
            .arg(&archive_path)
            .arg("-C")
            .arg(&bundle_src)
            .arg("frameassembly")
            .status()
            .unwrap();
        assert!(tar_st.success());

        let dest_bin = home.join(".local/bin/frameassembly");

        // 1. Missing SHA256SUMS.txt -> exit 1
        let missing = run_offline_installer(&temp_installer, &archive_path, &home, &tmp_dir);
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("SHA256SUMS.txt"));
        assert!(!dest_bin.exists());

        // 2. Tampered SHA256SUMS.txt -> exit 1
        let sums_path = dist_dir.join("SHA256SUMS.txt");
        fs::write(&sums_path, format!("{}  {archive_name}\n", "0".repeat(64))).unwrap();
        let bad = run_offline_installer(&temp_installer, &archive_path, &home, &tmp_dir);
        assert_eq!(bad.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&bad.stderr).contains("SHA-256 checksum mismatch"));
        assert!(!dest_bin.exists());

        // 3. Valid SHA256SUMS.txt -> atomic inode replacement via mv -f
        write_executable_script(&dest_bin, "old-inode-payload");
        let old_ino = fs::metadata(&dest_bin).unwrap().ino();
        let mut pinned_old_fd = File::open(&dest_bin).unwrap();

        let real_hash = compute_file_sha256_hex(&archive_path);
        fs::write(&sums_path, format!("{real_hash}  {archive_name}\n")).unwrap();
        let ok = run_offline_installer(&temp_installer, &archive_path, &home, &tmp_dir);
        assert_eq!(ok.status.code(), Some(0));

        let new_meta = fs::metadata(&dest_bin).unwrap();
        assert_ne!(
            new_meta.ino(),
            old_ino,
            "install.sh must replace via new inode"
        );
        assert!(new_meta.permissions().mode() & 0o111 != 0);

        let mut old_contents = String::new();
        pinned_old_fd.read_to_string(&mut old_contents).unwrap();
        assert_eq!(old_contents, "old-inode-payload");

        for entry in fs::read_dir(dest_bin.parent().unwrap()).unwrap().flatten() {
            assert!(!entry.file_name().to_string_lossy().contains(".tmp"));
        }
    }

    /// Verifies `bash -n` syntax validity and live `_frameassembly` Tab-completion `COMPREPLY`
    /// output for position 1, prefix `up`, `update` (zero args), and `help` (all 5 subcommands).
    #[test]
    fn test_bash_completion_syntax_and_live_tab_completion_for_update() {
        let Some(bash_exe) = find_host_tool("bash") else {
            return;
        };

        let bash_comp = repo_root().join("contrib/completions/frameassembly.bash");
        let install_sh = repo_root().join("install.sh");
        for script in [&bash_comp, &install_sh] {
            let syntax = Command::new(&bash_exe)
                .arg("-n")
                .arg(script)
                .output()
                .unwrap();
            assert!(
                syntax.status.success(),
                "bash -n failed on {}:\n{}",
                script.display(),
                String::from_utf8_lossy(&syntax.stderr)
            );
        }

        let temp = TempTestDir::new("bash_comp_live");
        fs::write(
            temp.join("demo.frasm"),
            "host a { ip 10.0.0.1 }\ncompile {}\n",
        )
        .unwrap();
        fs::write(temp.join("capture.pcap"), b"pcap").unwrap();
        fs::write(temp.join("notes.txt"), "ignore").unwrap();

        let probe_script = r#"
            set -eu
            source "$1"
            COMP_WORDS=(frameassembly ""); COMP_CWORD=1; _frameassembly
            printf 'POS1:%s\n' "${COMPREPLY[*]}"
            COMP_WORDS=(frameassembly "up"); COMP_CWORD=1; _frameassembly
            printf 'PREFIX_UP:%s\n' "${COMPREPLY[*]}"
            COMP_WORDS=(frameassembly update ""); COMP_CWORD=2; _frameassembly
            printf 'AFTER_UPDATE:%s\n' "${COMPREPLY[*]}"
            COMP_WORDS=(frameassembly help ""); COMP_CWORD=2; _frameassembly
            printf 'AFTER_HELP:%s\n' "${COMPREPLY[*]}"
        "#;

        let out = Command::new(&bash_exe)
            .args(["-c", probe_script, "bash"])
            .arg(&bash_comp)
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(out.status.success());

        let stdout = String::from_utf8_lossy(&out.stdout);
        let (mut pos1, mut prefix_up, mut after_update, mut after_help) = ("", "", "", "");
        for line in stdout.lines() {
            if let Some(v) = line.strip_prefix("POS1:") {
                pos1 = v;
            } else if let Some(v) = line.strip_prefix("PREFIX_UP:") {
                prefix_up = v;
            } else if let Some(v) = line.strip_prefix("AFTER_UPDATE:") {
                after_update = v;
            } else if let Some(v) = line.strip_prefix("AFTER_HELP:") {
                after_help = v;
            }
        }

        let pos1_items: Vec<&str> = pos1.split_whitespace().collect();
        assert!(pos1_items.contains(&"demo.frasm"));
        assert!(!pos1_items.contains(&"capture.pcap") && !pos1_items.contains(&"notes.txt"));
        for sub in EXPECTED_SUBCOMMANDS {
            assert!(pos1_items.contains(&sub), "missing '{sub}' in POS1");
        }
        assert_eq!(prefix_up.trim(), "update");
        assert_eq!(after_update.trim(), "");

        let help_items: Vec<&str> = after_help.split_whitespace().collect();
        for sub in EXPECTED_SUBCOMMANDS {
            assert!(help_items.contains(&sub), "missing '{sub}' in AFTER_HELP");
        }
    }

    /// Verifies hermetic `frameassembly update` execution when already up to date via GitHub
    /// `/releases/latest` redirect and via Crates.io sparse-index NDJSON fallback (ignoring yanked versions).
    #[test]
    fn test_update_e2e_up_to_date_and_crates_sparse_index_fallback() {
        let temp = TempTestDir::new("e2e_up_to_date");
        let (bin_dir, mock_bin, home_dir) =
            (temp.join("bin"), temp.join("mock_bin"), temp.join("home"));
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&home_dir).unwrap();
        setup_hermetic_mock_bin(&mock_bin);

        let temp_exe = bin_dir.join("frameassembly");
        fs::copy(cli_bin(), &temp_exe).unwrap();
        fs::set_permissions(&temp_exe, fs::Permissions::from_mode(0o755)).unwrap();
        let cur_ver = env!("CARGO_PKG_VERSION");
        let absent_cargo = home_dir.join(".cargo_absent");

        let gh_out = hermetic_update_cmd(&temp_exe, &mock_bin, &home_dir, &absent_cargo)
            .env(
                "MOCK_EFFECTIVE_URL",
                format!("https://github.com/SteveWinschel/FrameAssembly/releases/tag/v{cur_ver}"),
            )
            .output()
            .unwrap();
        assert_eq!(gh_out.status.code(), Some(0));
        let gh_stdout = String::from_utf8_lossy(&gh_out.stdout);
        assert!(gh_stdout.contains(&format!("FrameAssembly {cur_ver} is already up to date.")));

        let ndjson_path = temp.join("sparse_index.ndjson");
        fs::write(
            &ndjson_path,
            format!(
                "{{\"name\":\"frameassembly\",\"vers\":\"3.1.2\",\"yanked\":false}}\n\
                 {{\"name\":\"frameassembly\",\"vers\":\"{cur_ver}\",\"yanked\":false}}\n\
                 {{\"name\":\"frameassembly\",\"vers\":\"99.0.0\",\"yanked\":true}}\n"
            ),
        )
        .unwrap();

        let crates_out = hermetic_update_cmd(&temp_exe, &mock_bin, &home_dir, &absent_cargo)
            .env_remove("MOCK_EFFECTIVE_URL")
            .env("MOCK_CRATES_NDJSON_FILE", &ndjson_path)
            .output()
            .unwrap();
        assert_eq!(crates_out.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&crates_out.stdout)
                .contains(&format!("FrameAssembly {cur_ver} is already up to date."))
        );
    }

    /// Verifies Cargo-first update selection (`cargo install --force frameassembly`) when
    /// `cargo`, `rustc >= 1.89.0`, and `cc` are ready, plus atomic de-shadowing when the active
    /// executable resides outside `${CARGO_HOME}/bin`.
    #[test]
    fn test_update_e2e_cargo_first_and_standalone_binary_deshadowing() {
        let temp = TempTestDir::new("e2e_cargo_first");
        let (local_bin, cargo_home, mock_bin, home_dir) = (
            temp.join("local_bin"),
            temp.join("cargo_home"),
            temp.join("mock_bin"),
            temp.join("home"),
        );
        let cargo_bin = cargo_home.join("bin");
        for d in [&local_bin, &cargo_bin, &home_dir] {
            fs::create_dir_all(d).unwrap();
        }
        setup_hermetic_mock_bin(&mock_bin);

        write_executable_script(
            &mock_bin.join("rustc"),
            "#!/bin/sh\necho \"rustc 1.89.0 (29483883e 2025-08-04)\"\n",
        );
        write_executable_script(&mock_bin.join("cc"), "#!/bin/sh\nexit 0\n");

        let args_log = temp.join("cargo_args.txt");
        let built_template = temp.join("built_template");
        write_executable_script(
            &built_template,
            "#!/bin/sh\necho \"frameassembly 99.0.0\"\n",
        );
        let cargo_built = cargo_bin.join("frameassembly");
        write_executable_script(
            &cargo_bin.join("cargo"),
            &format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" > '{}'\ncp '{}' '{}'\nchmod 0755 '{}'\n",
                args_log.display(),
                built_template.display(),
                cargo_built.display(),
                cargo_built.display()
            ),
        );

        let standalone_exe = local_bin.join("frameassembly");
        fs::copy(cli_bin(), &standalone_exe).unwrap();
        fs::set_permissions(&standalone_exe, fs::Permissions::from_mode(0o755)).unwrap();
        let old_ino = fs::metadata(&standalone_exe).unwrap().ino();

        let out = hermetic_update_cmd(&standalone_exe, &mock_bin, &home_dir, &cargo_home)
            .env(
                "MOCK_EFFECTIVE_URL",
                "https://github.com/SteveWinschel/FrameAssembly/releases/tag/v99.0.0",
            )
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            fs::read_to_string(&args_log).unwrap().trim(),
            "install --force frameassembly"
        );

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("Synchronized active binary"));
        assert!(stdout.contains("Successfully updated frameassembly to v99.0.0 via Cargo."));
        assert_ne!(fs::metadata(&standalone_exe).unwrap().ino(), old_ino);

        let ver_out = Command::new(&standalone_exe)
            .arg("version")
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&ver_out.stdout).trim(),
            "frameassembly 99.0.0"
        );
    }

    /// Verifies headless prebuilt-release fallback in `frameassembly update`, asserting fail-closed
    /// `sha2::Sha256` rejection on tampered checksums and atomic self-replacement of the running
    /// binary plus refresh of existing shell completions when checksums match.
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn test_update_e2e_prebuilt_sha256_fail_closed_and_running_self_replacement() {
        let Some(tar_exe) = find_host_tool("tar") else {
            return;
        };
        let archive_name = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "frameassembly-linux-x64.tar.gz",
            ("linux", "aarch64") => "frameassembly-linux-arm64.tar.gz",
            ("macos", "x86_64") => "frameassembly-macos-x64.tar.gz",
            ("macos", "aarch64") => "frameassembly-macos-arm64.tar.gz",
            _ => unreachable!("guarded by cfg"),
        };

        let temp = TempTestDir::new("e2e_prebuilt_swap");
        let (bin_dir, mock_bin, home_dir, bundle_src) = (
            temp.join("bin"),
            temp.join("mock_bin"),
            temp.join("home"),
            temp.join("bundle_src"),
        );
        for d in [&bin_dir, &home_dir, &bundle_src] {
            fs::create_dir_all(d).unwrap();
        }
        setup_hermetic_mock_bin(&mock_bin);

        write_executable_script(
            &bundle_src.join("frameassembly"),
            "#!/bin/sh\necho \"frameassembly 99.0.0\"\n",
        );
        let refreshed_bash_comp = "# refreshed frameassembly bash completion v99.0.0\n";
        fs::write(bundle_src.join("frameassembly.bash"), refreshed_bash_comp).unwrap();

        let archive_path = temp.join(archive_name);
        let tar_st = Command::new(tar_exe)
            .arg("-czf")
            .arg(&archive_path)
            .arg("-C")
            .arg(&bundle_src)
            .args(["frameassembly", "frameassembly.bash"])
            .status()
            .unwrap();
        assert!(tar_st.success());

        let existing_bash_dest =
            home_dir.join(".local/share/bash-completion/completions/frameassembly");
        fs::create_dir_all(existing_bash_dest.parent().unwrap()).unwrap();
        fs::write(&existing_bash_dest, "# stale bash completion\n").unwrap();
        let absent_fish_dest = home_dir.join(".config/fish/completions/frameassembly.fish");

        let running_exe = bin_dir.join("frameassembly");
        fs::copy(cli_bin(), &running_exe).unwrap();
        fs::set_permissions(&running_exe, fs::Permissions::from_mode(0o755)).unwrap();
        let orig_ino = fs::metadata(&running_exe).unwrap().ino();
        let absent_cargo = home_dir.join(".cargo_absent");
        let sums_path = temp.join("SHA256SUMS.txt");

        // 1. Tampered SHA256SUMS.txt -> fail closed before extraction
        fs::write(&sums_path, format!("{}  {archive_name}\n", "f".repeat(64))).unwrap();
        let bad_out = hermetic_update_cmd(&running_exe, &mock_bin, &home_dir, &absent_cargo)
            .env(
                "MOCK_EFFECTIVE_URL",
                "https://github.com/SteveWinschel/FrameAssembly/releases/tag/v99.0.0",
            )
            .env("MOCK_SUMS_FILE", &sums_path)
            .env("MOCK_ARCHIVE_FILE", &archive_path)
            .output()
            .unwrap();
        assert_eq!(bad_out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&bad_out.stderr).contains("SHA-256 verification failed"));
        assert_eq!(fs::metadata(&running_exe).unwrap().ino(), orig_ino);
        assert_eq!(
            fs::read_to_string(&existing_bash_dest).unwrap(),
            "# stale bash completion\n"
        );

        // 2. Valid SHA256SUMS.txt -> atomic running self-replace + refresh existing Bash completion
        let valid_hash = compute_file_sha256_hex(&archive_path);
        fs::write(&sums_path, format!("{valid_hash}  *{archive_name}\n")).unwrap();
        let ok_out = hermetic_update_cmd(&running_exe, &mock_bin, &home_dir, &absent_cargo)
            .env(
                "MOCK_EFFECTIVE_URL",
                "https://github.com/SteveWinschel/FrameAssembly/releases/tag/v99.0.0",
            )
            .env("MOCK_SUMS_FILE", &sums_path)
            .env("MOCK_ARCHIVE_FILE", &archive_path)
            .output()
            .unwrap();
        assert_eq!(ok_out.status.code(), Some(0));

        let ok_stdout = String::from_utf8_lossy(&ok_out.stdout);
        assert!(ok_stdout.contains("Verified SHA-256 checksum"));
        assert!(ok_stdout.contains("Successfully updated frameassembly to v99.0.0"));
        assert_ne!(fs::metadata(&running_exe).unwrap().ino(), orig_ino);
        assert_eq!(
            fs::read_to_string(&existing_bash_dest).unwrap(),
            refreshed_bash_comp
        );
        assert!(!absent_fish_dest.exists());

        let ver_after = Command::new(&running_exe).arg("version").output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&ver_after.stdout).trim(),
            "frameassembly 99.0.0"
        );
    }
}
