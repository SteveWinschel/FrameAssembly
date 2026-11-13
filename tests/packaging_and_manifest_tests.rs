//! Automated E2E verification test suite for FrameAssembly v3.0.0 multi-platform packaging,
//! shell completions, registry authority assets, installer harmonization, and release workflows.
//!
//! This test harness verifies compliance across four quality tiers:
//! - **Tier 1 (Manifest, Completion & Recipe Structure)**: Structural and semantic validity for
//!   Debian/APT, Homebrew Tap (`SteveWinschel/homebrew-tap-FrameAssembly`), Scoop, shell
//!   completions (`bash`, `zsh`, `fish`, `powershell`), GitHub Issue forms, and verified removal
//!   of discontinued third-party registry channels.
//! - **Tier 2 (Syntax & Linter Integration)**: Shell syntax linting (`bash -n`) for build scripts,
//!   completion scripts, and `install.sh` (`v3.0.0`, `$HOME/.local/bin`, musl targets).
//! - **Tier 3 (Registry & Disambiguation Invariants)**: GitHub Linguist definitions and heuristics,
//!   Freedesktop `shared-mime-info` XML magic (`host`/`flow`/`compile`, `ip` + MAC-only `mac`),
//!   libmagic rules, IANA RFC 6838 vendor tree registration, and 3-way format disambiguation.
//! - **Tier 4 (Maintainer Workflows & Store Readiness)**: Master packaging maintainer guide,
//!   in-process WASM VS Code Packet Studio (`frameassembly-vscode-3.0.0.vsix`), `frameassembly-wasm`
//!   v3.0.0 metadata, and `< 50,000`-byte test harness hygiene.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Executes `bash -n` on the target script path to verify shell syntax validity.
fn verify_bash_syntax(script_path: &Path) {
    if !cfg!(unix) {
        return;
    }
    assert!(
        script_path.exists(),
        "Expected shell script '{}' to exist",
        script_path.display()
    );

    let output = Command::new("bash")
        .arg("-n")
        .arg(script_path)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "Failed to execute bash -n on '{}': {}",
                script_path.display(),
                err
            )
        });

    assert!(
        output.status.success(),
        "Shell script '{}' failed syntax validation via 'bash -n':\n{}",
        script_path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ==============================================================================
// TIER 1: MANIFEST, COMPLETION & RECIPE STRUCTURE TESTS
// ==============================================================================

/// Verifies that discontinued third-party distribution directories and CI workflow secrets have
/// been completely removed from `contrib/packaging/` and `.github/workflows/release.yml`.
#[test]
fn test_tier1_discontinued_registry_channels_absent() {
    let legacy_arch_dir = concat!("contrib/packaging/", "au", "r");
    let legacy_win_dir = concat!("contrib/packaging/win", "get");
    assert!(
        !Path::new(legacy_arch_dir).exists(),
        "Discontinued packaging directory '{}' must not exist in v3.0.0",
        legacy_arch_dir
    );
    assert!(
        !Path::new(legacy_win_dir).exists(),
        "Discontinued packaging directory '{}' must not exist in v3.0.0",
        legacy_win_dir
    );

    let release_yml =
        fs::read_to_string(".github/workflows/release.yml").expect("Missing release.yml");
    for banned in [
        concat!("OVSX_", "PAT"),
        concat!("AU", "R_SSH_PRIVATE_KEY"),
        concat!("WIN", "GET_TOKEN"),
        concat!("npx ", "ovsx"),
        concat!("au", "r.archlinux.org"),
        concat!("win", "get-pkgs"),
    ] {
        assert!(
            !release_yml.contains(banned),
            "release.yml must not reference discontinued secret/channel '{}'",
            banned
        );
    }
}

/// Verifies that the APT Debian package control file exists and contains all mandatory v3.0.0 fields.
#[test]
fn test_tier1_apt_control_structure() {
    let content = fs::read_to_string("contrib/packaging/apt/debian/control")
        .expect("Missing contrib/packaging/apt/debian/control");

    assert!(
        content.contains("Package: frameassembly"),
        "APT control must declare 'Package: frameassembly'"
    );
    assert!(
        content.contains("Version: 3.0.0"),
        "APT control must declare Version: 3.0.0*"
    );
    assert!(
        content.contains("Section: net") && content.contains("Priority: optional"),
        "APT control must declare Section: net and Priority: optional"
    );
    assert!(
        content.contains("Architecture:") && content.contains("Maintainer: Steve Winschel"),
        "APT control must declare Architecture and Maintainer Steve Winschel"
    );
    assert!(
        content.contains("Description: Compile .frasm") && !content.contains("DSL"),
        "APT control must use natural description without compiler 'DSL' jargon"
    );
    assert!(
        content.contains("Homepage: https://github.com/SteveWinschel/FrameAssembly"),
        "APT control must link to canonical repository Homepage"
    );
}

/// Verifies that the APT Debian copyright file exists and adheres to DEP-5 machine-readable format.
#[test]
fn test_tier1_apt_copyright_structure() {
    let content = fs::read_to_string("contrib/packaging/apt/debian/copyright")
        .expect("Missing contrib/packaging/apt/debian/copyright");

    assert!(
        content.contains("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"),
        "APT copyright must follow DEP-5 Format specification URL"
    );
    assert!(
        content.contains("Upstream-Name: frameassembly")
            && content.contains("Files: *")
            && content.contains("Copyright: 2026 Steve Winschel")
            && content.contains("License: MIT"),
        "APT copyright must declare Upstream-Name, Files: *, Copyright, and MIT license"
    );
}

/// Verifies that the Homebrew formula declares version 3.0.0 and multi-architecture macOS/Linux URLs.
#[test]
fn test_tier1_homebrew_formula_structure() {
    let content = fs::read_to_string("contrib/packaging/homebrew/Formula/frameassembly.rb")
        .expect("Missing Homebrew formula");

    assert!(content.contains("class Frameassembly < Formula"));
    assert!(
        content.contains("version \"3.0.0\""),
        "Homebrew formula must declare version \"3.0.0\""
    );
    assert!(content.contains("homepage \"https://github.com/SteveWinschel/FrameAssembly\""));
    assert!(content.contains("license \"MIT\""));
    assert!(content.contains("on_macos do") && content.contains("on_linux do"));
    assert!(content.contains("bin.install \"frameassembly\""));
    assert!(content.contains("test do"));
}

/// Verifies that the Scoop JSON manifest declares version 3.0.0 and multi-arch zip downloads.
#[test]
fn test_tier1_scoop_manifest_structure() {
    let content = fs::read_to_string("contrib/packaging/scoop/frameassembly.json")
        .expect("Missing Scoop manifest");

    assert!(
        content.contains("\"version\": \"3.0.0\""),
        "Scoop manifest must declare version 3.0.0"
    );
    assert!(content.contains("\"license\": \"MIT\""));
    assert!(content.contains("\"bin\": \"frameassembly.exe\""));
    assert!(content.contains("\"64bit\":") && content.contains("\"arm64\":"));
    assert!(content.contains("\"extract_dir\":"));
    assert!(content.contains("\"checkver\": \"github\"") && content.contains("\"autoupdate\":"));
}

/// Verifies that `build-deb.sh` bundles `text-vnd.frameassembly.xml`, `frameassembly.magic`, and
/// Bash/Zsh/Fish shell completion scripts into the `.deb` package.
#[test]
fn test_tier1_apt_mime_magic_and_completions_bundling() {
    let content = fs::read_to_string("contrib/packaging/apt/build-deb.sh")
        .expect("Missing contrib/packaging/apt/build-deb.sh");
    assert!(
        content.contains("usr/share/mime/packages")
            && content.contains("text-vnd.frameassembly.xml"),
        "APT build-deb.sh must bundle text-vnd.frameassembly.xml into /usr/share/mime/packages"
    );
    assert!(
        content.contains("usr/share/file/magic") && content.contains("frameassembly.magic"),
        "APT build-deb.sh must bundle frameassembly.magic into /usr/share/file/magic"
    );
    assert!(
        content.contains("bash-completion/completions")
            && content.contains("zsh/vendor-completions")
            && content.contains("fish/vendor_completions.d"),
        "APT build-deb.sh must bundle Bash, Zsh, and Fish completions"
    );
    assert!(
        content.contains("frameassembly_${TARGET_ARCH}.deb") || content.contains("UNVERSIONED_DEB"),
        "APT build-deb.sh must emit unversioned deb alias"
    );
}

/// Verifies context-aware shell completions (`contrib/completions/`) and structured GitHub Issue
/// forms (`.github/ISSUE_TEMPLATE/`) for FrameAssembly v3.0.0.
#[test]
fn test_tier1_shell_completions_and_issue_templates() {
    for file in [
        "contrib/completions/frameassembly.bash",
        "contrib/completions/_frameassembly",
        "contrib/completions/frameassembly.fish",
        "contrib/completions/frameassembly.ps1",
        "contrib/completions/README.md",
    ] {
        let p = Path::new(file);
        assert!(p.exists(), "Missing completion file: {}", file);
        let text = fs::read_to_string(p).expect("Failed to read completion file");
        for token in ["show", "reverse", "version", "help", ".frasm", ".pcap"] {
            assert!(
                text.contains(token),
                "{} must reference '{}' for v3.0.0 Tab completion",
                file,
                token
            );
        }
    }

    for tmpl in [
        ".github/ISSUE_TEMPLATE/protocol_request.yml",
        ".github/ISSUE_TEMPLATE/decompile_issue.yml",
        ".github/ISSUE_TEMPLATE/ux_and_ai_feedback.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
    ] {
        assert!(Path::new(tmpl).exists(), "Missing GitHub Issue template: {}", tmpl);
    }
}

/// Verifies that `contrib/packaging/update-checksums.sh` exists, is executable, supports `--help`,
/// and accurately updates Homebrew and Scoop v3.0.0 manifests using `--sums-file`.
#[test]
fn test_tier1_update_checksums_script() {
    let script_path = Path::new("contrib/packaging/update-checksums.sh");
    assert!(script_path.exists(), "contrib/packaging/update-checksums.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(script_path).expect("metadata").permissions();
        assert!(perms.mode() & 0o111 != 0, "update-checksums.sh must be executable");
    }

    if !cfg!(unix) {
        return;
    }

    let help_output = Command::new("bash")
        .arg(script_path)
        .arg("--help")
        .output()
        .expect("Failed to run update-checksums.sh --help");
    assert!(help_output.status.success(), "--help must exit with status 0");
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_str.contains("--sums-file"), "--help must document --sums-file");

    let temp_root = std::env::temp_dir().join(format!(
        "fa_test_checksums_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let temp_pkg_dir = temp_root.join("contrib/packaging");
    fs::create_dir_all(&temp_pkg_dir).expect("Failed to create temp packaging dir");

    struct TempGuard<'a>(&'a Path);
    impl<'a> Drop for TempGuard<'a> {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0);
        }
    }
    let _guard = TempGuard(&temp_root);

    fn copy_dir_all(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).expect("Failed to create destination directory");
        for entry in fs::read_dir(src).expect("Failed to read source directory") {
            let entry = entry.expect("Failed to read directory entry");
            let file_type = entry.file_type().expect("Failed to get file type");
            let target = dst.join(entry.file_name());
            if file_type.is_dir() {
                copy_dir_all(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("Failed to copy file");
            }
        }
    }
    copy_dir_all(Path::new("contrib/packaging"), &temp_pkg_dir);

    let (h1, h2, h3, h4, h5, h6) = (
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64),
        "5".repeat(64),
        "6".repeat(64),
    );
    let target_ver = "3.0.0";
    let synthetic_sums = temp_root.join("SHA256SUMS.txt");
    let test_sums_content = format!(
        "{h1}  frameassembly-v{target_ver}-x86_64-unknown-linux-musl.tar.gz\n\
{h2}  frameassembly-v{target_ver}-aarch64-unknown-linux-musl.tar.gz\n\
{h3}  frameassembly-v{target_ver}-x86_64-apple-darwin.tar.gz\n\
{h4}  frameassembly-v{target_ver}-aarch64-apple-darwin.tar.gz\n\
{h5}  frameassembly-v{target_ver}-x86_64-pc-windows-msvc.zip\n\
{h6}  frameassembly-v{target_ver}-aarch64-pc-windows-msvc.zip\n"
    );
    fs::write(&synthetic_sums, test_sums_content).expect("Failed to write synthetic SHA256SUMS.txt");

    let run_output = Command::new("bash")
        .arg(script_path)
        .arg("--sums-file")
        .arg(&synthetic_sums)
        .arg("--repo-root")
        .arg(&temp_root)
        .arg(target_ver)
        .output()
        .expect("Failed to execute update-checksums.sh");

    assert!(
        run_output.status.success(),
        "update-checksums.sh execution failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&run_output.stdout),
        String::from_utf8_lossy(&run_output.stderr)
    );

    let brew_formula = fs::read_to_string(temp_pkg_dir.join("homebrew/Formula/frameassembly.rb"))
        .expect("Read Homebrew formula");
    assert!(
        brew_formula.contains(&h3)
            && brew_formula.contains(&h4)
            && brew_formula.contains(&h1)
            && brew_formula.contains(&h2),
        "Homebrew formula must contain updated macOS and Linux SHA256 hashes"
    );

    let scoop_json = fs::read_to_string(temp_pkg_dir.join("scoop/frameassembly.json"))
        .expect("Read Scoop manifest");
    assert!(
        scoop_json.contains(&h5) && scoop_json.contains(&h6),
        "Scoop manifest must contain updated Windows 64bit and arm64 SHA256 hashes"
    );
}

// ==============================================================================
// TIER 2: SYNTAX & LINTER INTEGRATION TESTS
// ==============================================================================

/// Verifies that all shell scripts in the packaging, completion, and install pipeline pass `bash -n`.
#[test]
fn test_tier2_shell_syntax_validation() {
    for script in [
        "contrib/packaging/apt/build-deb.sh",
        "contrib/packaging/update-checksums.sh",
        "contrib/completions/frameassembly.bash",
        "install.sh",
    ] {
        verify_bash_syntax(Path::new(script));
    }
}

/// Verifies that `install.sh` targets `v3.0.0`, `$HOME/.local/bin` fallback, musl binaries,
/// shell completions, and the default root CLI command (`frameassembly demo.frasm output.pcap`).
#[test]
fn test_tier2_install_sh_harmonization() {
    let install_sh = Path::new("install.sh");
    let content = fs::read_to_string(install_sh).expect("Failed to read install.sh");
    verify_bash_syntax(install_sh);

    assert!(content.contains("detect_prebuilt_target"));
    assert!(content.contains("try_install_prebuilt_binary"));
    assert!(
        content.contains("VSIX_VERSION=\"3.0.0\"") && content.contains("RELEASE_VERSION=\"3.0.0\""),
        "install.sh must declare VSIX_VERSION=\"3.0.0\" and RELEASE_VERSION=\"3.0.0\""
    );
    assert!(
        content.contains(".local/bin"),
        "install.sh must support $HOME/.local/bin when ~/.cargo/bin is absent"
    );
    assert!(
        content.contains("x86_64-unknown-linux-musl")
            && content.contains("aarch64-unknown-linux-musl"),
        "install.sh must map both x86_64 and aarch64 Linux targets to musl"
    );
    assert!(
        content.contains("frameassembly show quickstart.frasm")
            && content.contains("frameassembly quickstart.frasm quickstart.pcap"),
        "install.sh quickstart must write quickstart.frasm and run 'frameassembly quickstart.frasm quickstart.pcap'"
    );
    assert!(
        !content.contains("demo.frasm") && !content.contains("demo.fasm"),
        "install.sh quickstart must be self-contained and not reference a non-existent demo file"
    );
    let legacy_cli = concat!("frameassembly", " ", "compile");
    assert!(
        !content.contains(legacy_cli),
        "install.sh must not reference removed compile subcommand"
    );
}

// ==============================================================================
// TIER 3: REGISTRY & DISAMBIGUATION INVARIANTS TESTS
// ==============================================================================

/// Verifies GitHub Linguist registration assets, v3.0.0 strict-lowercase heuristics, samples,
/// and `.gitattributes`.
#[test]
fn test_tier3_linguist_registry_assets() {
    let lang_content =
        fs::read_to_string("contrib/linguist/languages.yml").expect("Failed to read languages.yml");
    assert!(lang_content.contains("FrameAssembly:"));
    assert!(lang_content.contains("type: programming"));
    assert!(lang_content.contains("- \".frasm\"") || lang_content.contains("-\".frasm\""));
    assert!(lang_content.contains("tm_scope: source.frameassembly"));
    assert!(!lang_content.contains("language_id:"));

    let heur_content = fs::read_to_string("contrib/linguist/heuristics.yml")
        .expect("Failed to read heuristics.yml");
    assert!(heur_content.contains("language: FrameAssembly"));
    assert!(heur_content.contains("language: Assembly"));
    assert!(
        heur_content.contains("host") && heur_content.contains("flow") && heur_content.contains("compile"),
        "heuristics.yml must match v3.0.0 lowercase FrameAssembly anchors host, flow, compile"
    );

    for sample_path in [
        "contrib/linguist/samples/enterprise_snmpv3_and_tls.frasm",
        "contrib/linguist/samples/industrial_ot_modbus_dnp3.frasm",
    ] {
        let code = fs::read_to_string(sample_path).expect("Failed to read Linguist sample");
        let prog = frameassembly::parser::parse_program(&code)
            .expect("Linguist sample must parse cleanly");
        frameassembly::parser::validate_semantics(&prog, &code)
            .expect("Linguist sample must pass semantic validation");
        let packets = frameassembly::backend::compile_program(&prog)
            .expect("Linguist sample must compile to packets");
        assert!(!packets.is_empty());
    }

    let gitattrs = fs::read_to_string(".gitattributes").expect("Failed to read .gitattributes");
    assert!(gitattrs.contains("*.frasm linguist-language=FrameAssembly"));
}

/// Verifies that the Freedesktop shared-mime-info XML definition matches v3.0.0 strict-lowercase
/// `host`, `flow`, `compile`, `ip`, and MAC-only `mac` clauses.
#[test]
fn test_tier3_freedesktop_mime_xml_structure() {
    let content = fs::read_to_string("contrib/mime/text-vnd.frameassembly.xml")
        .expect("Failed to read MIME XML");

    assert!(content.contains("<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">"));
    assert!(content.contains("<mime-type type=\"text/vnd.frameassembly\">"));
    assert!(content.contains("<sub-class-of type=\"text/plain\"/>"));
    assert!(content.contains("<glob pattern=\"*.frasm\" weight=\"60\"/>"));
    assert!(content.contains("<magic priority=\"60\">"));
    assert!(
        content.contains("value=\"host ") && content.contains("value=\"compile\"") && content.contains("value=\"mac "),
        "MIME XML magic must match lowercase host, mac (for L2 MAC-only hosts), and compile tokens"
    );
}

/// Verifies IANA RFC 6838 vendor tree application and Wikidata QuickStatements batch in
/// `contrib/iana/text-vnd.frameassembly.md`.
#[test]
fn test_tier3_iana_and_wikidata_assets() {
    let content =
        fs::read_to_string("contrib/iana/text-vnd.frameassembly.md").expect("Failed to read IANA file");
    assert!(content.contains("**Type name:**") && content.contains("text"));
    assert!(content.contains("**Subtype name:**") && content.contains("vnd.frameassembly"));
    assert!(content.contains("Encoding considerations:"));
    assert!(content.contains("Security considerations:"));
    assert!(content.contains("Interoperability considerations:"));
    assert!(content.contains("`P31`") && content.contains("`P1195`") && content.contains("`P1163`"));
    assert!(content.contains("`P973`") && content.contains("`P856`") && content.contains("`P1324`"));
    assert!(content.contains("LAST|P1195|\"frasm\""));
    assert!(content.contains("LAST|P1163|\"text/vnd.frameassembly\""));
    assert!(content.contains("LAST|P856|\"https://frameassembly.ai.studio/\""));
    assert!(content.contains("file-extensions.org") || content.contains("File-Extensions.org"));
    assert!(content.contains("Wikidata") && (content.contains("PRONOM") || content.contains("National Archives")));
}

/// Verifies that `docs/12_frasm_specification.md` documents authoritative 3-way format disambiguation.
#[test]
fn test_tier3_format_disambiguation_integrity() {
    let content =
        fs::read_to_string("docs/12_frasm_specification.md").expect("Failed to read 12_frasm_specification.md");
    assert!(
        content.contains("FrameAssembly (`.frasm`)")
            || content.contains("FrameAssembly (`.frasm`, `text/vnd.frameassembly`)")
    );
    assert!(content.contains("Flat Assembler"));
    assert!(content.contains("FPGA") || content.contains("SymbiFlow"));
    assert!(content.contains("//") && content.contains(";") && content.contains("#"));
}

/// Verifies that `contrib/magic/frameassembly.magic` defines valid v3.0.0 strict-lowercase libmagic
/// patterns (`host`, `flow`, `compile`, `ip`, `mac`) and upstream submission instructions.
#[test]
fn test_tier3_libmagic_rules_and_upstream_guide() {
    let content =
        fs::read_to_string("contrib/magic/frameassembly.magic").expect("Failed to read frameassembly.magic");
    assert!(content.contains("github.com/file/file"));
    assert!(content.contains("~/.magic") || content.contains("/etc/magic"));
    assert!(
        content.contains("host")
            && content.contains("flow")
            && content.contains("compile")
            && content.contains("mac"),
        "libmagic file must define rules matching lowercase host, flow, compile, and mac tokens"
    );
    assert!(content.contains("search/2048"));
    assert!(content.contains("text/vnd.frameassembly"));
    assert!(content.contains("!:ext") && content.contains("frasm"));
    assert!(!content.contains('\0'));
}

// ==============================================================================
// TIER 4: MAINTAINER WORKFLOWS & STORE READINESS TESTS
// ==============================================================================

/// Verifies that `contrib/packaging/README.md` covers supported channels (`APT`, `Homebrew`,
/// `Scoop`, `SteveWinschel/homebrew-tap-FrameAssembly`) and omits discontinued channels.
#[test]
fn test_tier4_packaging_maintainer_guide() {
    let content = fs::read_to_string("contrib/packaging/README.md")
        .expect("Missing contrib/packaging/README.md");

    assert!(content.contains("APT") || content.contains("Debian"));
    assert!(content.contains("Homebrew") && content.contains("homebrew-tap-FrameAssembly"));
    assert!(content.contains("Scoop"));
    let banned_arch = concat!("au", "r.archlinux.org");
    let banned_win = concat!("win", "get install");
    assert!(
        !content.contains(banned_arch) && !content.contains(banned_win),
        "contrib/packaging/README.md must not advertise discontinued channels"
    );

    let apt_install_cmd = "curl -fsSLo /tmp/frameassembly.deb https://github.com/SteveWinschel/FrameAssembly/releases/latest/download/frameassembly_amd64.deb && sudo apt install -y /tmp/frameassembly.deb && rm -f /tmp/frameassembly.deb";
    assert!(
        content.contains(apt_install_cmd),
        "contrib/packaging/README.md must showcase clean one-line apt install command"
    );
}

/// Verifies that this test file adheres to `< 50,000` bytes, `//! >= 50` words, and zero NUL bytes.
#[test]
fn test_tier4_test_suite_hygiene() {
    let test_file = Path::new("tests/packaging_and_manifest_tests.rs");
    let meta = fs::metadata(test_file).expect("Failed to get test file metadata");
    assert!(
        meta.len() < 50_000,
        "tests/packaging_and_manifest_tests.rs must be < 50,000 bytes, was {} bytes",
        meta.len()
    );
    let content = fs::read_to_string(test_file).expect("Failed to read test file");
    assert!(!content.contains('\0'));
    let docstring_words = content
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .flat_map(|line| line[3..].split_whitespace())
        .count();
    assert!(docstring_words >= 50, "Inner //! module docstring must have >= 50 words");
}

/// Verifies that `frameassembly-vscode` v3.0.0 is configured for the VS Code Marketplace with
/// 256x256 icon, 30 keywords, WASM Packet Studio commands, and `frameassembly-vscode-3.0.0.vsix`.
#[test]
fn test_tier4_vscode_extension_store_readiness() {
    let base_dir = Path::new("frameassembly-vscode");
    let icon_bytes = fs::read(base_dir.join("icon.png")).expect("Failed to read icon.png");
    assert_eq!(&icon_bytes[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    let w = u32::from_be_bytes([icon_bytes[16], icon_bytes[17], icon_bytes[18], icon_bytes[19]]);
    let h = u32::from_be_bytes([icon_bytes[20], icon_bytes[21], icon_bytes[22], icon_bytes[23]]);
    assert_eq!((w, h), (256, 256), "icon.png must be 256x256 pixels");

    let pkg_json =
        fs::read_to_string(base_dir.join("package.json")).expect("Failed to read package.json");
    assert!(pkg_json.contains("\"icon\": \"icon.png\""));
    assert!(pkg_json.contains("\"galleryBanner\":"));
    assert!(pkg_json.contains("\"scopeName\": \"source.frameassembly\""));
    assert!(pkg_json.contains("text/vnd.frameassembly"));
    assert!(pkg_json.contains("\"firstLine\":"));
    assert!(pkg_json.contains("\"publisher\": \"SteveWinschel\""));
    assert!(pkg_json.contains("\"version\": \"3.0.0\""));
    assert!(pkg_json.contains("\"homepage\": \"https://frameassembly.ai.studio/\""));
    assert!(pkg_json.contains("\"main\": \"./extension.js\""));
    assert!(pkg_json.contains("frameassembly.compileToPcap"));
    assert!(pkg_json.contains("frameassembly.showPacketLadder"));
    assert!(pkg_json.contains("frameassembly.reversePcap"));

    let tml = fs::read_to_string(base_dir.join("syntaxes/frameassembly.tmLanguage.json"))
        .expect("Failed to read frameassembly.tmLanguage.json");
    assert!(tml.contains("\"scopeName\": \"source.frameassembly\""));

    let readme = fs::read_to_string(base_dir.join("README.md")).expect("Failed to read README.md");
    assert!(readme.contains("Example `.frasm` Workflows") && !readme.contains("Problem -> Solution"));
    assert!(readme.contains("source.frameassembly"));

    let vsix_path = base_dir.join("frameassembly-vscode-3.0.0.vsix");
    assert!(vsix_path.exists(), "frameassembly-vscode-3.0.0.vsix must exist");
    if cfg!(unix) {
        let unzip_output = Command::new("unzip")
            .arg("-l")
            .arg(&vsix_path)
            .output()
            .expect("Failed to run unzip -l on vsix");
        assert!(unzip_output.status.success());
        let out_str = String::from_utf8_lossy(&unzip_output.stdout);
        for entry in [
            "extension/icon.png",
            "extension/extension.js",
            "extension/protocol_schema.json",
            "extension/wasm/frameassembly_wasm_bg.wasm",
        ] {
            assert!(
                out_str.contains(entry),
                "frameassembly-vscode-3.0.0.vsix must bundle {}",
                entry
            );
        }
    }
}

/// Verifies `.github/workflows/release.yml` triggers, `needs: [prepare, wasm]` VS Code bundling,
/// the 4 supported optional secrets (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, `VSCE_PAT`,
/// `HOMEBREW_TAP_TOKEN`), and `homebrew-tap-FrameAssembly`.
#[test]
fn test_tier1_release_workflow_full_matrix_and_secrets() {
    let content = fs::read_to_string(".github/workflows/release.yml")
        .expect("Failed to read release.yml")
        .replace("\r\n", "\n");

    assert!(content.contains("paths:\n      - 'Cargo.toml'"));
    assert!(!content.contains("tags:\n      - 'v[0-9]+"));
    assert!(content.contains("workflow_dispatch:"));
    assert!(content.contains("wasm:"));
    assert!(content.contains("vscode-extension:"));
    assert!(content.contains("publish:"));

    let required_secrets = [
        "NPM_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "VSCE_PAT",
        "HOMEBREW_TAP_TOKEN",
    ];
    for sec in required_secrets {
        assert!(
            content.contains(&format!("secrets.{}", sec)),
            "release.yml must reference secret {}",
            sec
        );
        assert!(
            content.contains(&format!("if: ${{{{ env.{} != '' }}}}", sec)),
            "Step must be guarded by env.{}",
            sec
        );
    }

    assert!(content.contains("homebrew-tap-FrameAssembly"));
    assert!(content.contains("wasm-pack build --release --target web"));
    assert!(content.contains("cargo publish"));
    assert!(content.contains("update-checksums.sh"));
    assert!(content.contains("frameassembly_${ARCH}.deb"));
}

/// Verifies `frameassembly-wasm` v3.0.0 manifest, dependencies, and README SEO formatting.
#[test]
fn test_tier1_wasm_packaging_and_readme_seo() {
    let wasm_manifest =
        fs::read_to_string("frameassembly-wasm/Cargo.toml").expect("Read frameassembly-wasm/Cargo.toml");
    assert!(wasm_manifest.contains("version = \"3.0.0\""));
    assert!(wasm_manifest.contains("frameassembly = { path = \"..\", version = \"3.0.0\" }"));
    assert!(wasm_manifest.contains("homepage = \"https://frameassembly.ai.studio/\""));

    let wasm_pkg_json = fs::read_to_string("frameassembly-wasm/package.json")
        .expect("Read frameassembly-wasm/package.json");
    assert!(wasm_pkg_json.contains("\"version\": \"3.0.0\""));
    assert!(wasm_pkg_json.contains("\"homepage\": \"https://frameassembly.ai.studio/\""));

    let wasm_readme =
        fs::read_to_string("frameassembly-wasm/README.md").expect("Read frameassembly-wasm/README.md");
    assert!(wasm_readme.contains("frameassembly-wasm` v3.0.0"));
    assert!(
        wasm_readme.contains("Client-Side `.frasm` to `.pcapng` Compilation")
            && !wasm_readme.contains("Problem -> Solution")
    );
    assert!(wasm_readme.contains("compile_fasm_to_pcapng"));
    assert!(wasm_readme.contains("validate_fasm"));
    assert!(wasm_readme.contains("inspect_fasm"));
    assert!(wasm_readme.contains("reverse_pcap"));

    for doc_path in [
        "README.md",
        "src/lib.rs",
        "docs/01_getting_started.md",
        "frameassembly-vscode/README.md",
        "frameassembly-wasm/README.md",
    ] {
        let doc = fs::read_to_string(doc_path).unwrap_or_else(|_| panic!("Read {}", doc_path));
        for banned in ["Problem -> Solution", "Why It Hurts Today", "The FrameAssembly Solution"] {
            assert!(!doc.contains(banned), "{} must not contain '{}'", doc_path, banned);
        }
    }
}

/// Verifies the v3.0.0 release surface: the Windows `install.ps1` bootstrapper, clean per-OS
/// archive names in `release.yml`, the single `SHA256SUMS.txt` manifest, the community health
/// files, and the Linux/macOS `update-checksums.sh` syntax.
#[test]
fn test_tier2_v3_release_assets_installer_and_community_files() {
    let install_ps1 = fs::read_to_string("install.ps1").expect("Missing install.ps1");
    for needle in [
        "LOCALAPPDATA",
        "SHA256SUMS.txt",
        "frameassembly-windows-x64.zip",
        "frameassembly-windows-arm64.zip",
        "-DryRun",
        "-NoVsCode",
        "-NoCompletions",
        ".frasm",
    ] {
        assert!(
            install_ps1.contains(needle),
            "install.ps1 must reference '{}'",
            needle
        );
    }
    assert!(!install_ps1.contains("demo.fasm"), "install.ps1 must not reference demo.fasm");

    let release_yml =
        fs::read_to_string(".github/workflows/release.yml").expect("Missing release.yml");
    for asset in [
        "frameassembly-windows-x64",
        "frameassembly-windows-arm64",
        "frameassembly-macos-arm64",
        "frameassembly-macos-x64",
        "frameassembly-linux-x64",
        "frameassembly-linux-arm64",
        "frameassembly_${ARCH}.deb",
        "frameassembly-vscode.vsix",
        "SHA256SUMS.txt",
        "quickstart.frasm",
        "Download by Operating System",
    ] {
        assert!(
            release_yml.contains(asset),
            "release.yml must publish or document '{}'",
            asset
        );
    }
    assert!(
        !release_yml.contains(".fasm"),
        "release.yml must not reference legacy .fasm files"
    );

    for community in [".github/SECURITY.md", ".github/CONTRIBUTING.md"] {
        let text = fs::read_to_string(community).unwrap_or_else(|_| panic!("Missing {}", community));
        assert!(
            text.split_whitespace().count() >= 50,
            "{} must contain at least 50 words",
            community
        );
    }

    verify_bash_syntax(Path::new("contrib/packaging/update-checksums.sh"));
}
