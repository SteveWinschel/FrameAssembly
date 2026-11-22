//! Self-update command (`frameassembly update`) for the FrameAssembly CLI binary.
//!
//! This module resolves the latest stable release via GitHub `/releases/latest` redirects with a
//! Crates.io sparse-index fallback, prefers `cargo install` when `rustc >= 1.89.0` and a C/MSVC
//! linker are ready, prompts on interactive terminals (or falls back automatically in headless
//! runs) to install `rustup` or a SHA-256-verified prebuilt GitHub Release binary, atomically
//! swaps the binary across Linux, macOS, and Windows, and refreshes existing shell completions.

use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io::{self, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Current compiled crate version.
const CURRENT_VERSION_STR: &str = env!("CARGO_PKG_VERSION");
/// Platform-native executable filename for FrameAssembly.
const BIN_NAME: &str = if cfg!(windows) {
    "frameassembly.exe"
} else {
    "frameassembly"
};
/// Minimum Rust compiler version (`1.89.0`).
const MIN_RUST_VERSION: SemVer = SemVer {
    major: 1,
    minor: 89,
    patch: 0,
};
/// GitHub latest-release redirect endpoint (avoids REST API rate limits).
const RELEASES_LATEST_URL: &str = "https://github.com/SteveWinschel/FrameAssembly/releases/latest";
/// Base URL for pinned GitHub Release downloads.
const RELEASES_DOWNLOAD_BASE: &str =
    "https://github.com/SteveWinschel/FrameAssembly/releases/download";
/// Crates.io sparse index URL for `frameassembly`.
const CRATES_SPARSE_INDEX_URL: &str = "https://index.crates.io/fr/am/frameassembly";
/// Raw GitHub content base URL for shell completion files.
const RAW_GITHUB_BASE: &str = "https://raw.githubusercontent.com/SteveWinschel/FrameAssembly";
/// Monotonic counter isolating temporary working directories.
static TEMP_WORK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Strict `(major, minor, patch)` semantic version tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer {
    /// Major version component.
    major: u64,
    /// Minor version component.
    minor: u64,
    /// Patch version component.
    patch: u64,
}

impl SemVer {
    /// Parses strict `X.Y.Z` syntax (rejecting pre-release/build suffixes).
    fn parse(raw: &str) -> Option<Self> {
        let mut p = raw.trim().split('.');
        let (maj, min, pat) = (p.next()?, p.next()?, p.next()?);
        if p.next().is_some() {
            return None;
        }
        let num = |s: &str| {
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())?
        };
        Some(Self {
            major: num(maj)?,
            minor: num(min)?,
            patch: num(pat)?,
        })
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// RAII temporary working directory deleted automatically on drop.
struct TempWorkDir(
    /// Temporary working directory path removed on drop.
    PathBuf,
);

impl TempWorkDir {
    /// Creates an isolated directory under `std::env::temp_dir()`.
    fn new(prefix: &str) -> Result<Self> {
        let id = TEMP_WORK_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frameassembly_{prefix}_{}_{}",
            std::process::id(),
            id
        ));
        fs::create_dir_all(&dir).into_diagnostic()?;
        Ok(Self(dir))
    }
}

impl Drop for TempWorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Discovered Rust toolchain and linker availability.
struct ToolchainProbe {
    /// Resolved `<CARGO_HOME>/bin` directory.
    cargo_bin: Option<PathBuf>,
    /// Child `PATH` with `<CARGO_HOME>/bin` prepended.
    child_path: OsString,
    /// Discovered `cargo` executable.
    cargo_exe: Option<PathBuf>,
    /// Discovered `rustup` executable.
    rustup_exe: Option<PathBuf>,
    /// Parsed `rustc` version.
    rustc_version: Option<SemVer>,
    /// Whether a C or MSVC linker is usable.
    has_linker: bool,
}

impl ToolchainProbe {
    /// Returns `true` when `cargo`, `rustc >= 1.89.0`, and a linker are ready.
    fn is_ready(&self) -> bool {
        self.cargo_exe.is_some()
            && self.rustc_version.is_some_and(|v| v >= MIN_RUST_VERSION)
            && self.has_linker
    }

    /// Returns human-readable descriptions of missing prerequisites.
    fn missing_descriptions(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.cargo_exe.is_none() {
            out.push("cargo (Rust package manager)".into());
        }
        match self.rustc_version {
            None => out.push(format!("rustc >= {MIN_RUST_VERSION}")),
            Some(v) if v < MIN_RUST_VERSION => {
                out.push(format!("rustc >= {MIN_RUST_VERSION} (found {v})"))
            }
            _ => {}
        }
        if !self.has_linker {
            let lbl = if cfg!(windows) {
                "MSVC C++ linker (link.exe / Visual Studio Build Tools)"
            } else if cfg!(target_os = "macos") {
                "C linker (Xcode Command Line Tools: cc/clang)"
            } else {
                "C linker (cc/gcc/clang)"
            };
            out.push(lbl.into());
        }
        out
    }
}

/// Removes leftover `<exe_dir>/frameassembly.exe.old` from a prior Windows update.
#[cfg(windows)]
pub(crate) fn cleanup_stale_windows_old_exe() {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let _ = fs::remove_file(dir.join("frameassembly.exe.old"));
    }
}

/// No-op on non-Windows targets.
#[cfg(not(windows))]
pub(crate) fn cleanup_stale_windows_old_exe() {}

/// Runs `frameassembly update` to check for and install newer stable releases.
pub(crate) fn run_update() -> Result<()> {
    let current = SemVer::parse(CURRENT_VERSION_STR)
        .ok_or_else(|| miette::miette!("Invalid package version '{CURRENT_VERSION_STR}'"))?;

    println!("Checking for FrameAssembly updates (current: v{current})...");
    let latest = check_latest_version()?;
    if current >= latest {
        println!("frameassembly {current} is already up to date.");
        return Ok(());
    }

    println!("New release available: v{current} -> v{latest}");
    let mut probe = probe_toolchain();

    if !probe.is_ready()
        && probe.rustc_version.is_none_or(|v| v < MIN_RUST_VERSION)
        && let Some(rustup) = &probe.rustup_exe
    {
        println!("Updating Rust toolchain via rustup (need rustc >= {MIN_RUST_VERSION})...");
        if Command::new(rustup)
            .args(["update", "stable"])
            .env("PATH", &probe.child_path)
            .status()
            .is_ok_and(|s| s.success())
        {
            probe = probe_toolchain();
        } else {
            eprintln!("Warning: 'rustup update stable' did not complete cleanly.");
        }
    }

    if probe.is_ready() {
        return update_via_cargo(&probe, latest);
    }

    let missing = probe.missing_descriptions();
    if !is_interactive_tty() {
        println!(
            "Non-interactive environment missing {}; falling back to verified prebuilt binary.",
            missing.join(", ")
        );
        return update_via_prebuilt_release(latest);
    }

    println!("\nCannot build from source because prerequisites are missing:");
    for item in &missing {
        println!("  - {item}");
    }
    println!("\n  [1] Install/update Rust toolchain via rustup (recommended)");
    println!("  [2] Install verified prebuilt GitHub Release binary");

    if prompt_choice("Select an option [1/2] (default: 1): ", &["1", "2", ""])? == "2" {
        return update_via_prebuilt_release(latest);
    }

    ensure_rustup_and_cargo(&mut probe)?;
    if !probe.has_linker {
        eprintln!("\nA C/MSVC linker is still required to compile FrameAssembly from source:");
        if cfg!(windows) {
            eprintln!(
                "  winget install Microsoft.VisualStudio.2022.BuildTools --override \"--wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended\""
            );
        } else if cfg!(target_os = "macos") {
            eprintln!("  xcode-select --install");
        } else {
            eprintln!(
                "  Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y build-essential\n  Fedora/RHEL:   sudo dnf install -y gcc\n  Arch/Alpine:   sudo pacman -S base-devel / apk add build-base"
            );
        }
        let confirm = prompt_choice(
            "Install verified prebuilt GitHub Release binary instead? [Y/n]: ",
            &["y", "yes", "n", "no", ""],
        )?;
        if matches!(confirm.as_str(), "" | "y" | "yes") {
            return update_via_prebuilt_release(latest);
        }
        return Err(miette::miette!(
            "Update aborted: install the C/MSVC linker and re-run 'frameassembly update'."
        ));
    }

    update_via_cargo(&probe, latest)
}

/// Checks GitHub `/releases/latest` redirect first, falling back to Crates.io sparse index.
fn check_latest_version() -> Result<SemVer> {
    let gh_err = match resolve_effective_url(RELEASES_LATEST_URL) {
        Ok(url) => match parse_version_from_release_url(&url) {
            Some(ver) => return Ok(ver),
            None => format!("unexpected redirect target '{url}'"),
        },
        Err(e) => e,
    };
    let body = fetch_text(CRATES_SPARSE_INDEX_URL).map_err(|e| {
        miette::miette!("Unable to check for updates (GitHub: {gh_err}; Crates.io index: {e})")
    })?;
    parse_highest_crates_index_version(&body)
        .ok_or_else(|| miette::miette!("Unable to determine latest version (GitHub: {gh_err}; Crates.io index had no non-yanked stable release)"))
}

/// Extracts `SemVer` from a resolved `/releases/tag/vX.Y.Z` URL.
fn parse_version_from_release_url(url: &str) -> Option<SemVer> {
    let (_, after) = url
        .trim()
        .trim_end_matches('/')
        .split_once("/releases/tag/")?;
    let seg = after.split(['/', '?', '#']).next().unwrap_or(after);
    SemVer::parse(seg.strip_prefix(['v', 'V']).unwrap_or(seg))
}

/// Parses the highest non-yanked stable `"vers"` entry from Crates.io sparse-index NDJSON.
fn parse_highest_crates_index_version(ndjson: &str) -> Option<SemVer> {
    ndjson
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(parse_crates_index_line)
        .filter_map(|(v, y)| (!y).then_some(v))
        .max()
}

/// Extracts top-level `"vers"` and `"yanked"` fields from one Crates.io index JSON line.
fn parse_crates_index_line(line: &str) -> Option<(SemVer, bool)> {
    let b = line.as_bytes();
    let mut i = 0usize;
    let skip_ws = |i: &mut usize| {
        while b.get(*i).is_some_and(u8::is_ascii_whitespace) {
            *i += 1;
        }
    };
    let scan_str = |i: &mut usize| -> Option<&str> {
        (b.get(*i) == Some(&b'"')).then_some(())?;
        *i += 1;
        let start = *i;
        while let Some(&c) = b.get(*i) {
            if c == b'\\' {
                *i += 2;
            } else if c == b'"' {
                let s = std::str::from_utf8(&b[start..*i]).ok()?;
                *i += 1;
                return Some(s);
            } else {
                *i += 1;
            }
        }
        None
    };
    skip_ws(&mut i);
    (b.get(i) == Some(&b'{')).then_some(())?;
    i += 1;
    let (mut vers, mut yanked) = (None, false);
    loop {
        skip_ws(&mut i);
        match b.get(i)? {
            b'}' => break,
            b',' => i += 1,
            b'"' => {
                let key = scan_str(&mut i)?;
                skip_ws(&mut i);
                (b.get(i) == Some(&b':')).then_some(())?;
                i += 1;
                skip_ws(&mut i);
                let delim = |k: usize| {
                    b.get(k)
                        .is_none_or(|c| matches!(c, b',' | b'}' | b']') || c.is_ascii_whitespace())
                };
                if key == "vers" && b.get(i) == Some(&b'"') {
                    vers = SemVer::parse(scan_str(&mut i)?);
                } else if key == "yanked" && b.get(i..i + 4) == Some(b"true") && delim(i + 4) {
                    (yanked, i) = (true, i + 4);
                } else if key == "yanked" && b.get(i..i + 5) == Some(b"false") && delim(i + 5) {
                    (yanked, i) = (false, i + 5);
                } else {
                    let mut depth = 0usize;
                    while let Some(&c) = b.get(i) {
                        if c == b'"' {
                            scan_str(&mut i)?;
                        } else if matches!(c, b'{' | b'[') {
                            (depth, i) = (depth + 1, i + 1);
                        } else if matches!(c, b'}' | b']') && depth > 0 {
                            (depth, i) = (depth - 1, i + 1);
                            if depth == 0 {
                                break;
                            }
                        } else if depth == 0
                            && (matches!(c, b',' | b'}' | b']') || c.is_ascii_whitespace())
                        {
                            break;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
            _ => return None,
        }
    }
    vers.map(|v| (v, yanked))
}

/// Resolves `CARGO_HOME` from `CARGO_HOME` env or `<home>/.cargo`.
fn resolve_cargo_home_from(cargo_home: Option<&OsStr>, home: Option<&Path>) -> Option<PathBuf> {
    cargo_home
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|h| h.join(".cargo")))
}

/// Returns the user's home directory from OS environment variables.
fn user_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    if let Some(p) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    #[cfg(windows)]
    if let (Some(d), Some(p)) = (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
        let mut full = d;
        full.push(p);
        if !full.is_empty() {
            return Some(PathBuf::from(full));
        }
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Builds a child `PATH` with `cargo_bin` prepended so `rustup` shims shadow older `rustc`.
fn build_prepended_path(cargo_bin: Option<&Path>, current_path: Option<&OsStr>) -> OsString {
    let mut dirs: Vec<PathBuf> = cargo_bin.map(Path::to_path_buf).into_iter().collect();
    if let Some(existing) = current_path {
        dirs.extend(
            std::env::split_paths(existing)
                .filter(|e| !cargo_bin.is_some_and(|b| paths_equivalent(e, b))),
        );
    }
    std::env::join_paths(dirs)
        .unwrap_or_else(|_| current_path.map(OsStr::to_os_string).unwrap_or_default())
}

/// Compares two directory paths (case-insensitively on Windows).
fn paths_equivalent(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a == b
            || a.to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches(['\\', '/']))
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// Searches `search_path` for an executable named `stem`.
fn find_executable(stem: &str, search_path: &OsStr) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    };
    std::env::split_paths(search_path)
        .map(|d| d.join(&name))
        .find(|p| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(p).is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
            }
            #[cfg(not(unix))]
            p.is_file()
        })
}

/// Probes `cargo`, `rustc`, `rustup`, and C/MSVC linker readiness.
fn probe_toolchain() -> ToolchainProbe {
    let cargo_env = std::env::var_os("CARGO_HOME");
    let home = user_home_dir();
    let cargo_bin =
        resolve_cargo_home_from(cargo_env.as_deref(), home.as_deref()).map(|h| h.join("bin"));
    let child_path =
        build_prepended_path(cargo_bin.as_deref(), std::env::var_os("PATH").as_deref());
    let rustc_version = find_executable("rustc", &child_path).and_then(|exe| {
        let out = Command::new(exe)
            .arg("--version")
            .env("PATH", &child_path)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| parse_rustc_version_output(&String::from_utf8_lossy(&out.stdout)))
            .flatten()
    });
    ToolchainProbe {
        cargo_exe: find_executable("cargo", &child_path),
        rustup_exe: find_executable("rustup", &child_path),
        has_linker: has_c_or_msvc_linker(&child_path),
        cargo_bin,
        child_path,
        rustc_version,
    }
}

/// Parses `rustc X.Y.Z` output (stripping pre-release/commit suffixes).
fn parse_rustc_version_output(stdout: &str) -> Option<SemVer> {
    SemVer::parse(stdout.split_whitespace().nth(1)?.split(['-', '+']).next()?)
}

/// Checks for `CC`, `cc`, `gcc`, or `clang` on Unix (verifying macOS Xcode CLT).
#[cfg(not(windows))]
fn has_c_or_msvc_linker(search_path: &OsStr) -> bool {
    let usable = |p: &Path| -> bool {
        #[cfg(target_os = "macos")]
        if p.starts_with("/usr/bin") {
            return Command::new("xcode-select")
                .arg("-p")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
        }
        let _ = p;
        true
    };
    if let Some(cc) = std::env::var_os("CC").filter(|v| !v.is_empty()) {
        let p = Path::new(&cc);
        let found = if p.components().count() > 1 {
            p.is_file().then(|| p.to_path_buf())
        } else {
            find_executable(&cc.to_string_lossy(), search_path)
        };
        if found.as_deref().is_some_and(usable) {
            return true;
        }
    }
    ["cc", "gcc", "clang"]
        .into_iter()
        .filter_map(|t| find_executable(t, search_path))
        .any(|p| usable(&p))
}

/// Checks for MSVC `link.exe` on `PATH` (ignoring MSYS/Git shims) or via `vswhere.exe`.
#[cfg(windows)]
fn has_c_or_msvc_linker(search_path: &OsStr) -> bool {
    for dir in std::env::split_paths(search_path) {
        let cand = dir.join("link.exe");
        if cand.is_file() {
            let lower = cand.to_string_lossy().to_ascii_lowercase();
            if !lower.ends_with("\\usr\\bin\\link.exe") && !lower.ends_with("/usr/bin/link.exe") {
                return true;
            }
        }
    }
    let pf86 = std::env::var_os("ProgramFiles(x86)")
        .unwrap_or_else(|| OsString::from("C:\\Program Files (x86)"));
    let vswhere = PathBuf::from(pf86).join("Microsoft Visual Studio\\Installer\\vswhere.exe");
    vswhere.is_file()
        && Command::new(vswhere)
            .args([
                "-latest",
                "-products",
                "*",
                "-requiresAny",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
                "-property",
                "installationPath",
            ])
            .output()
            .is_ok_and(|o| {
                o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
            })
}

/// Bootstraps or updates `rustup` + `cargo` + `rustc >= 1.89.0` for Option `[1]`.
fn ensure_rustup_and_cargo(probe: &mut ToolchainProbe) -> Result<()> {
    if probe.cargo_exe.is_some() && probe.rustc_version.is_some_and(|v| v >= MIN_RUST_VERSION) {
        return Ok(());
    }
    if let Some(rustup) = &probe.rustup_exe {
        println!("Ensuring stable Rust toolchain via rustup...");
        let st = Command::new(rustup)
            .args(["toolchain", "install", "stable"])
            .env("PATH", &probe.child_path)
            .status()
            .into_diagnostic()?;
        if !st.success() {
            return Err(miette::miette!("'rustup toolchain install stable' failed"));
        }
        let _ = Command::new(rustup)
            .args(["default", "stable"])
            .env("PATH", &probe.child_path)
            .status();
    } else {
        let work = TempWorkDir::new("rustup")?;
        #[cfg(not(windows))]
        let (url, target) = ("https://sh.rustup.rs", work.0.join("rustup-init.sh"));
        #[cfg(windows)]
        let (url, target) = (
            if cfg!(target_arch = "aarch64") {
                "https://win.rustup.rs/aarch64"
            } else {
                "https://win.rustup.rs/x86_64"
            },
            work.0.join("rustup-init.exe"),
        );
        println!("Downloading and running rustup installer ({url})...");
        download_file(url, &target).map_err(|e| miette::miette!("{e}"))?;
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = Command::new("sh");
            c.arg(&target);
            c
        };
        #[cfg(windows)]
        let mut cmd = Command::new(&target);
        let st = cmd
            .args(["-y", "--default-toolchain", "stable"])
            .env("PATH", &probe.child_path)
            .status()
            .into_diagnostic()?;
        if !st.success() {
            return Err(miette::miette!("rustup installer exited with status {st}"));
        }
    }
    *probe = probe_toolchain();
    if probe.cargo_exe.is_none() || probe.rustc_version.is_none_or(|v| v < MIN_RUST_VERSION) {
        return Err(miette::miette!(
            "Rust >= {MIN_RUST_VERSION} and cargo not found after rustup (found {:?}).",
            probe.rustc_version
        ));
    }
    Ok(())
}

/// Detects whether an interactive terminal (or `/dev/tty` on Unix) is attached.
fn is_interactive_tty() -> bool {
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        return true;
    }
    #[cfg(unix)]
    if io::stdout().is_terminal()
        && fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    {
        return true;
    }
    false
}

/// Prompts for one of `valid_choices` (case-insensitive) up to three attempts.
fn prompt_choice(prompt: &str, valid_choices: &[&str]) -> Result<String> {
    for _ in 0..3 {
        print!("{prompt}");
        io::stdout().flush().into_diagnostic()?;
        let mut line = String::new();
        if io::stdin().is_terminal() {
            io::stdin().read_line(&mut line).into_diagnostic()?;
        } else {
            #[cfg(unix)]
            {
                use std::io::BufRead as _;
                BufReader::new(File::open("/dev/tty").into_diagnostic()?)
                    .read_line(&mut line)
                    .into_diagnostic()?;
            }
            #[cfg(not(unix))]
            io::stdin().read_line(&mut line).into_diagnostic()?;
        }
        let norm = line.trim().to_ascii_lowercase();
        if valid_choices.iter().any(|c| *c == norm) {
            return Ok(norm);
        }
        println!("Please enter a valid choice.");
    }
    Err(miette::miette!(
        "Too many invalid responses; aborting update."
    ))
}

/// Installs the update via `cargo install`, handles Windows `.exe.old` swap + rollback, and
/// de-shadows any user-writable binary outside `${CARGO_HOME}/bin`.
fn update_via_cargo(probe: &ToolchainProbe, latest: SemVer) -> Result<()> {
    let cargo = probe
        .cargo_exe
        .as_deref()
        .ok_or_else(|| miette::miette!("cargo not found"))?;
    let cargo_bin = probe
        .cargo_bin
        .as_deref()
        .ok_or_else(|| miette::miette!("CARGO_HOME/bin not found"))?;
    let current_exe = std::env::current_exe().ok();
    let in_cargo_bin = current_exe.as_deref().and_then(Path::parent).is_some_and(|p| {
        paths_equivalent(p, cargo_bin)
            || matches!((fs::canonicalize(p), fs::canonicalize(cargo_bin)), (Ok(a), Ok(b)) if paths_equivalent(&a, &b))
    });

    #[cfg(windows)]
    let moved_old: Option<(PathBuf, PathBuf)> = if in_cargo_bin && let Some(exe) = &current_exe {
        let old = cargo_bin.join("frameassembly.exe.old");
        let _ = fs::remove_file(&old);
        fs::rename(exe, &old).into_diagnostic()?;
        Some((exe.clone(), old))
    } else {
        None
    };

    println!(
        "Updating via Cargo ({} install --force frameassembly)...",
        cargo.display()
    );
    let status = Command::new(cargo)
        .args(["install", "--force", "frameassembly"])
        .env("PATH", &probe.child_path)
        .status();
    if !status.as_ref().is_ok_and(|s| s.success()) {
        #[cfg(windows)]
        if let Some((orig, old)) = &moved_old {
            let _ = fs::rename(old, orig);
        }
        return match status {
            Ok(s) => Err(miette::miette!(
                "'cargo install --force frameassembly' exited with {s}"
            )),
            Err(e) => Err(miette::miette!("Failed to launch cargo: {e}")),
        };
    }

    let built = cargo_bin.join(BIN_NAME);
    if !in_cargo_bin
        && let Some(exe) = &current_exe
        && built.is_file()
    {
        match atomic_replace_binary(&built, exe) {
            Ok(()) => println!(
                "Synchronized active binary {} from {}.",
                exe.display(),
                built.display()
            ),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => eprintln!(
                "Note: updated binary installed to {}, but {} is not user-writable and may shadow it.",
                built.display(),
                exe.display()
            ),
            Err(e) => eprintln!(
                "Warning: updated {} but could not de-shadow {}: {e}",
                built.display(),
                exe.display()
            ),
        }
    }
    refresh_existing_completions(None, latest);
    println!("Successfully updated frameassembly to v{latest} via Cargo.");
    Ok(())
}

/// Maps `(os, arch)` to the published GitHub Release archive name.
fn release_archive_name_for(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("frameassembly-linux-x64.tar.gz"),
        ("linux", "aarch64") => Some("frameassembly-linux-arm64.tar.gz"),
        ("macos", "x86_64") => Some("frameassembly-macos-x64.tar.gz"),
        ("macos", "aarch64") => Some("frameassembly-macos-arm64.tar.gz"),
        ("windows", "x86_64") => Some("frameassembly-windows-x64.zip"),
        ("windows", "aarch64") => Some("frameassembly-windows-arm64.zip"),
        _ => None,
    }
}

/// Downloads, SHA-256-verifies fail-closed, extracts, and atomically installs a GitHub Release.
fn update_via_prebuilt_release(latest: SemVer) -> Result<()> {
    let archive_name = release_archive_name_for(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or_else(|| {
            miette::miette!(
                "No prebuilt release for {}/{}; update via 'cargo install frameassembly'.",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
    let target_exe = std::env::current_exe().into_diagnostic()?;
    let base = format!("{RELEASES_DOWNLOAD_BASE}/v{latest}");
    let work = TempWorkDir::new("update")?;
    let (sums_path, archive_path, extract_dir) = (
        work.0.join("SHA256SUMS.txt"),
        work.0.join(archive_name),
        work.0.join("extract"),
    );
    fs::create_dir_all(&extract_dir).into_diagnostic()?;

    println!("Downloading SHA256SUMS.txt for v{latest}...");
    download_file(&format!("{base}/SHA256SUMS.txt"), &sums_path)
        .map_err(|e| miette::miette!("{e}"))?;
    let sums_text = fs::read_to_string(&sums_path).into_diagnostic()?;

    println!("Downloading {archive_name}...");
    download_file(&format!("{base}/{archive_name}"), &archive_path)
        .map_err(|e| miette::miette!("{e}"))?;
    verify_file_sha256(&archive_path, archive_name, &sums_text)?;
    println!("Verified SHA-256 checksum for {archive_name}.");

    extract_archive(&archive_path, &extract_dir)?;
    let extracted_bin = find_file_recursive(&extract_dir, BIN_NAME)
        .ok_or_else(|| miette::miette!("Archive {archive_name} did not contain '{BIN_NAME}'"))?;

    #[cfg(target_os = "macos")]
    let _ = Command::new("xattr")
        .args(["-d", "com.apple.quarantine"])
        .arg(&extracted_bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    atomic_replace_binary(&extracted_bin, &target_exe).map_err(|err| {
        if err.kind() == io::ErrorKind::PermissionDenied && target_exe == Path::new("/usr/bin/frameassembly") {
            let deb = if cfg!(target_arch = "aarch64") { "frameassembly_arm64.deb" } else { "frameassembly_amd64.deb" };
            miette::miette!("Permission denied updating /usr/bin/frameassembly ({err}). If installed via .deb, run:\n  curl -fsSLo ./{deb} {RELEASES_DOWNLOAD_BASE}/v{latest}/{deb} && sudo apt install -y ./{deb} && rm -f ./{deb}")
        } else if err.kind() == io::ErrorKind::PermissionDenied {
            miette::miette!("Permission denied replacing {} ({err}). Re-run with write permissions or use your package manager.", target_exe.display())
        } else {
            miette::miette!("Failed to replace {}: {err}", target_exe.display())
        }
    })?;

    refresh_existing_completions(Some(&extract_dir), latest);
    println!(
        "Successfully updated frameassembly to v{latest} at {}.",
        target_exe.display()
    );
    Ok(())
}

/// Parses the lowercase hex SHA-256 digest for `filename` from `SHA256SUMS.txt`.
fn parse_sha256_sums(sums_text: &str, filename: &str) -> Option<String> {
    sums_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|line| {
            let mut p = line.split_whitespace();
            let (hash, raw) = (p.next()?, p.next()?);
            let valid = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
            let base = raw
                .trim_start_matches('*')
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(raw);
            (valid && base == filename).then(|| hash.to_ascii_lowercase())
        })
}

/// Verifies `file_path` fail-closed against `archive_name` in `sums_text` via `sha2::Sha256`.
fn verify_file_sha256(file_path: &Path, archive_name: &str, sums_text: &str) -> Result<()> {
    let expected = parse_sha256_sums(sums_text, archive_name).ok_or_else(|| {
        miette::miette!("No SHA-256 entry found for '{archive_name}' in SHA256SUMS.txt")
    })?;
    let mut reader = BufReader::new(File::open(file_path).into_diagnostic()?);
    let (mut hasher, mut buf) = (Sha256::new(), [0u8; 65536]);
    loop {
        let n = reader.read(&mut buf).into_diagnostic()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut actual = String::with_capacity(64);
    for b in hasher.finalize() {
        let _ = write!(actual, "{b:02x}");
    }
    if actual != expected {
        return Err(miette::miette!(
            "SHA-256 verification failed for {archive_name}: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

/// Stages `src_bin` into a sibling temp file and atomically replaces `target_exe`.
fn atomic_replace_binary(src_bin: &Path, target_exe: &Path) -> io::Result<()> {
    let dir = target_exe
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "executable has no parent"))?;
    let staged = dir.join(format!(".frameassembly.update.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&staged);
    if let Err(err) = fs::copy(src_bin, &staged) {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    #[cfg(unix)]
    let res = {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
            .and_then(|()| fs::rename(&staged, target_exe))
    };
    #[cfg(windows)]
    let res = {
        let old = dir.join("frameassembly.exe.old");
        let _ = fs::remove_file(&old);
        let moved_old = if target_exe.exists() {
            fs::rename(target_exe, &old)?;
            true
        } else {
            false
        };
        match fs::rename(&staged, target_exe) {
            Ok(()) => {
                if moved_old {
                    let _ = fs::remove_file(&old);
                }
                Ok(())
            }
            Err(err) => {
                if moved_old {
                    let _ = fs::rename(&old, target_exe);
                }
                Err(err)
            }
        }
    };
    if res.is_err() {
        let _ = fs::remove_file(&staged);
    }
    res
}

/// Recursively locates `target_name` inside `root`.
fn find_file_recursive(root: &Path, target_name: &str) -> Option<PathBuf> {
    let direct = root.join(target_name);
    if direct.is_file() {
        return Some(direct);
    }
    for entry in fs::read_dir(root).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir()
            && let Some(found) = find_file_recursive(&p, target_name)
        {
            return Some(found);
        }
    }
    None
}

/// Refreshes existing Bash/Zsh/Fish/PowerShell completion scripts without creating new ones.
fn refresh_existing_completions(extract_dir: Option<&Path>, latest: SemVer) {
    let (mut updated, mut seen) = (0usize, HashSet::new());
    for (src_name, dest) in existing_completion_targets() {
        if !seen.insert(fs::canonicalize(&dest).unwrap_or_else(|_| dest.clone())) {
            continue;
        }
        let bytes = extract_dir
            .and_then(|dir| find_file_recursive(dir, src_name))
            .and_then(|p| fs::read(p).ok())
            .or_else(|| {
                fetch_text(&format!(
                    "{RAW_GITHUB_BASE}/v{latest}/contrib/completions/{src_name}"
                ))
                .ok()
                .map(String::into_bytes)
            });
        if let Some(content) = bytes
            && let Some(parent) = dest.parent()
        {
            let tmp = parent.join(format!(".frameassembly.comp.{}.tmp", std::process::id()));
            let ok = File::create(&tmp)
                .and_then(|mut f| {
                    f.write_all(&content)?;
                    f.sync_all()
                })
                .and_then(|()| fs::rename(&tmp, &dest));
            if ok.is_ok() {
                updated += 1;
            } else {
                let _ = fs::remove_file(&tmp);
            }
        }
    }
    if updated > 0 {
        println!("Refreshed {updated} shell completion file(s).");
    }
}

/// Collects existing completion file paths on disk eligible for refresh.
fn existing_completion_targets() -> Vec<(&'static str, PathBuf)> {
    let ps1 = "frameassembly.ps1";
    let mut out = Vec::new();
    let home = user_home_dir();
    #[cfg(not(windows))]
    {
        let (bash, zsh, fish) = ("frameassembly.bash", "_frameassembly", "frameassembly.fish");
        if let Some(h) = &home {
            let env_or = |k, fb: &str| {
                std::env::var_os(k)
                    .filter(|v| !v.is_empty())
                    .map_or_else(|| h.join(fb), PathBuf::from)
            };
            let (xd, xc, zd) = (
                env_or("XDG_DATA_HOME", ".local/share"),
                env_or("XDG_CONFIG_HOME", ".config"),
                env_or("ZDOTDIR", ""),
            );
            out.push((bash, xd.join("bash-completion/completions/frameassembly")));
            out.push((zsh, zd.join(".zfunc/_frameassembly")));
            out.push((zsh, xd.join("zsh/site-functions/_frameassembly")));
            out.push((fish, xc.join("fish/completions/frameassembly.fish")));
            out.push((ps1, xc.join("powershell/frameassembly.ps1")));
        }
        out.push((
            bash,
            PathBuf::from("/usr/local/share/bash-completion/completions/frameassembly"),
        ));
        out.push((
            zsh,
            PathBuf::from("/opt/homebrew/share/zsh/site-functions/_frameassembly"),
        ));
        out.push((
            zsh,
            PathBuf::from("/usr/local/share/zsh/site-functions/_frameassembly"),
        ));
    }
    #[cfg(windows)]
    {
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            out.push((ps1, dir.join("completions\\frameassembly.ps1")));
        }
        if let Some(lad) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            out.push((
                ps1,
                PathBuf::from(lad).join("Programs\\FrameAssembly\\completions\\frameassembly.ps1"),
            ));
        }
        if let Some(h) = &home {
            out.push((ps1, h.join("Documents\\PowerShell\\frameassembly.ps1")));
            out.push((
                ps1,
                h.join("Documents\\WindowsPowerShell\\frameassembly.ps1"),
            ));
        }
    }
    out.into_iter().filter(|(_, p)| p.is_file()).collect()
}

/// Returns a `System32` tool path on Windows (`SystemRoot\System32\<name>`).
#[cfg(windows)]
fn windows_sys32_tool(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from("C:\\Windows"));
    PathBuf::from(root).join("System32").join(name)
}

/// Executes `curl` with `args`, falling back to PowerShell on Windows when `curl` fails.
fn curl_or_powershell(
    args: &[&OsStr],
    ps_fallback: impl FnOnce() -> String,
) -> std::result::Result<String, String> {
    #[cfg(not(windows))]
    let curl = std::env::var_os("PATH")
        .and_then(|p| find_executable("curl", &p))
        .unwrap_or_else(|| PathBuf::from("curl"));
    #[cfg(windows)]
    let curl = std::env::var_os("PATH")
        .and_then(|v| find_executable("curl", &v))
        .unwrap_or_else(|| windows_sys32_tool("curl.exe"));

    let err = match Command::new(curl).args(args).output() {
        Ok(out) if out.status.success() => {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        Ok(out) => format!(
            "curl exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("failed to run curl: {e}"),
    };
    #[cfg(windows)]
    return run_powershell(&ps_fallback()).map_err(|ps_err| format!("{err}; {ps_err}"));
    #[cfg(not(windows))]
    {
        let _ = ps_fallback;
        Err(err)
    }
}

/// Runs a PowerShell TLS 1.2+ fallback snippet on Windows.
#[cfg(windows)]
fn run_powershell(body: &str) -> std::result::Result<String, String> {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; {body}"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("failed to run powershell: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolves the final effective redirect URL for `url`.
fn resolve_effective_url(url: &str) -> std::result::Result<String, String> {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let args = ["-fsSLI", "-o", null, "-w", "%{url_effective}", url].map(OsStr::new);
    let out = curl_or_powershell(&args, || {
        let u = url.replace('\'', "''");
        format!(
            "try{{$r=Invoke-WebRequest -Uri '{u}' -MaximumRedirection 0 -UseBasicParsing -ErrorAction Stop;if($r.Headers['Location']){{Write-Output $r.Headers['Location']}}}}catch{{$h=$_.Exception.Response.Headers;if($h){{$l=$h['Location'];if(-not $l -and $h.Location){{$l=$h.Location.ToString()}};if($l){{Write-Output $l}}}}}}"
        )
    })?;
    let t = out.trim();
    if t.is_empty() {
        Err("empty redirect URL".into())
    } else {
        Ok(t.to_string())
    }
}

/// Fetches UTF-8 text from `url` via `curl` (with Windows PowerShell fallback).
fn fetch_text(url: &str) -> std::result::Result<String, String> {
    curl_or_powershell(&["-fsSL", url].map(OsStr::new), || {
        format!(
            "(Invoke-WebRequest -Uri '{}' -UseBasicParsing -ErrorAction Stop).Content",
            url.replace('\'', "''")
        )
    })
}

/// Downloads `url` over HTTPS to `dest` via `curl` (with Windows PowerShell fallback).
fn download_file(url: &str, dest: &Path) -> std::result::Result<(), String> {
    let args = [
        OsStr::new("--proto"),
        OsStr::new("=https"),
        OsStr::new("--tlsv1.2"),
        OsStr::new("-fsSL"),
        OsStr::new(url),
        OsStr::new("-o"),
        dest.as_os_str(),
    ];
    curl_or_powershell(&args, || {
        format!(
            "Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing -ErrorAction Stop",
            url.replace('\'', "''"),
            dest.to_string_lossy().replace('\'', "''")
        )
    })?;
    Ok(())
}

/// Extracts `.tar.gz` on Unix or `.zip` via `System32\tar.exe` / PowerShell on Windows.
fn extract_archive(archive: &Path, dest_dir: &Path) -> Result<()> {
    #[cfg(not(windows))]
    let out = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(dest_dir)
        .output()
        .into_diagnostic()?;
    #[cfg(windows)]
    let out = {
        let tar = windows_sys32_tool("tar.exe");
        if tar.is_file()
            && let Ok(o) = Command::new(tar)
                .arg("-xf")
                .arg(archive)
                .arg("-C")
                .arg(dest_dir)
                .output()
            && o.status.success()
        {
            return Ok(());
        }
        let (a, d) = (
            archive.to_string_lossy().replace('\'', "''"),
            dest_dir.to_string_lossy().replace('\'', "''"),
        );
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("Expand-Archive -Path '{a}' -DestinationPath '{d}' -Force"),
            ])
            .output()
            .into_diagnostic()?
    };
    if !out.status.success() {
        return Err(miette::miette!(
            "Failed to extract {}: {}",
            archive.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Unit tests for `SemVer`, release URLs, Crates.io index, SHA-256 verification, and `CARGO_HOME`.
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies strict `SemVer` parsing, ordering, and pre-release rejection.
    #[test]
    fn test_semver_parse_and_ordering() {
        assert!(SemVer::parse("3.1.2") < SemVer::parse("3.2.0"));
        assert!(SemVer::parse("3.2.0") < SemVer::parse("3.10.0"));
        assert_eq!(SemVer::parse("3.2.0").unwrap().to_string(), "3.2.0");
        for bad in ["v3.2.0", "3.2.0-rc.1", "3.2", "3.2.0.1", ""] {
            assert!(SemVer::parse(bad).is_none());
        }
    }

    /// Verifies `/releases/tag/vX.Y.Z` URL extraction.
    #[test]
    fn test_parse_version_from_release_url() {
        let b = "https://github.com/SteveWinschel/FrameAssembly/releases";
        assert_eq!(
            parse_version_from_release_url(&format!("{b}/tag/v3.2.0")),
            SemVer::parse("3.2.0")
        );
        assert_eq!(
            parse_version_from_release_url(&format!("{b}/tag/3.2.1/\n")),
            SemVer::parse("3.2.1")
        );
        assert_eq!(parse_version_from_release_url(&format!("{b}/latest")), None);
        assert_eq!(
            parse_version_from_release_url(&format!("{b}/tag/v3.3.0-beta.1")),
            None
        );
    }

    /// Verifies Crates.io sparse-index NDJSON parsing ignores yanked and pre-release entries.
    #[test]
    fn test_parse_highest_crates_index_version() {
        let ndjson = concat!(
            r#"{"name":"frameassembly","vers":"3.1.0","deps":[],"yanked":false}"#,
            "\n",
            r#"{"name":"frameassembly","vers":"3.2.0","deps":[{"name":"sha2","req":"^0.11.0","yanked":true}],"yanked":false}"#,
            "\n",
            r#"{"name":"frameassembly","vers":"3.3.0","deps":[],"yanked":true}"#,
            "\n",
            r#"{"name":"frameassembly","vers":"3.4.0-rc.1","deps":[],"yanked":false}"#,
            "\n"
        );
        assert_eq!(
            parse_highest_crates_index_version(ndjson),
            SemVer::parse("3.2.0")
        );
        assert_eq!(
            parse_highest_crates_index_version(
                r#"{"name":"frameassembly","vers":"3.2.0","deps":[],"yanked":true}"#
            ),
            None
        );
    }

    /// Verifies `SHA256SUMS.txt` matching and fail-closed verification via `sha2::Digest`.
    #[test]
    fn test_sha256_sums_parsing_and_verification_pass_fail() {
        let work = TempWorkDir::new("sha_test").expect("temp dir");
        let arc = "frameassembly-linux-x64.tar.gz";
        let path = work.0.join(arc);
        let data = b"frameassembly deterministic release payload";
        fs::write(&path, data).expect("write");
        let mut dig = String::with_capacity(64);
        for b in Sha256::digest(data) {
            let _ = write!(dig, "{b:02x}");
        }
        let sums = format!(
            "{}  other.tar.gz\n{}  ./dist/{arc}\n",
            "0".repeat(64),
            dig.to_ascii_uppercase()
        );
        assert_eq!(parse_sha256_sums(&sums, arc), Some(dig));
        assert!(verify_file_sha256(&path, arc, &sums).is_ok());
        assert!(
            verify_file_sha256(&path, arc, &format!("{}  {arc}\n", "f".repeat(64)))
                .unwrap_err()
                .to_string()
                .contains("SHA-256 verification failed")
        );
        assert!(
            verify_file_sha256(&path, "missing.tar.gz", &sums)
                .unwrap_err()
                .to_string()
                .contains("No SHA-256 entry found")
        );
    }

    /// Verifies `CARGO_HOME` detection, `PATH` prepending, archive mapping, and `rustc` parsing.
    #[test]
    fn test_cargo_home_path_and_platform_helpers() {
        let u = Path::new("/home/alice");
        assert_eq!(
            resolve_cargo_home_from(Some(OsStr::new("/opt/cargo")), Some(u)),
            Some(PathBuf::from("/opt/cargo"))
        );
        assert_eq!(
            resolve_cargo_home_from(Some(OsStr::new("")), Some(u)),
            Some(PathBuf::from("/home/alice/.cargo"))
        );
        assert_eq!(
            resolve_cargo_home_from(None, Some(u)),
            Some(PathBuf::from("/home/alice/.cargo"))
        );
        assert_eq!(resolve_cargo_home_from(None, None), None);
        let bin = Path::new("/home/alice/.cargo/bin");
        let joined = std::env::join_paths(["/usr/bin", "/home/alice/.cargo/bin"]).expect("join");
        let dirs: Vec<PathBuf> =
            std::env::split_paths(&build_prepended_path(Some(bin), Some(&joined))).collect();
        assert_eq!(dirs.first().map(PathBuf::as_path), Some(bin));
        assert_eq!(dirs.iter().filter(|p| p.as_path() == bin).count(), 1);
        for (os, arch, want) in [
            ("linux", "x86_64", "frameassembly-linux-x64.tar.gz"),
            ("linux", "aarch64", "frameassembly-linux-arm64.tar.gz"),
            ("macos", "x86_64", "frameassembly-macos-x64.tar.gz"),
            ("macos", "aarch64", "frameassembly-macos-arm64.tar.gz"),
            ("windows", "x86_64", "frameassembly-windows-x64.zip"),
            ("windows", "aarch64", "frameassembly-windows-arm64.zip"),
        ] {
            assert_eq!(release_archive_name_for(os, arch), Some(want));
        }
        assert_eq!(release_archive_name_for("freebsd", "x86_64"), None);
        assert_eq!(
            parse_rustc_version_output("rustc 1.89.0 (29483883e 2025-08-04)"),
            Some(MIN_RUST_VERSION)
        );
        assert_eq!(
            parse_rustc_version_output("rustc 1.100.0-nightly (0ef1bc386 2026-11-09)"),
            SemVer::parse("1.100.0")
        );
    }
}
