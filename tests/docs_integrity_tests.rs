//! Documentation integrity gate for FrameAssembly's human-facing and agent-facing Markdown.
//!
//! Network engineers read `README.md` and the guides in `docs/`, while AI agents read `AGENTS.md`,
//! `CLAUDE.md`, `.github/copilot-instructions.md`, and `llms.txt`. This suite keeps both audiences
//! safe from stale documentation by enforcing three core invariants:
//! 1. **No training metadata in human docs**: the corpus-only `// PROMPT:`, `// TOKENS:`, and
//!    `// INSTRUCTION:` header comments never appear in `README.md` or `docs/*.md`, except in
//!    `docs/13_for_nerds.md`, which documents the `examples/` corpus format for AI engineers.
//! 2. **MIME, Linguist & SEO hygiene**: the `.frasm` MIME XML, GitHub Linguist samples, and
//!    `Cargo.toml` metadata stay consistent with FrameAssembly v3.0.0 strict-lowercase syntax.
//! 3. **Four-Way Ecosystem Version Lockstep (`3.0.0`)**: `Cargo.toml`, `src/lib.rs`, `llms.txt`,
//!    `llms-full.txt`, `frameassembly-wasm`, `frameassembly-vscode`, `install.sh`, `CITATION.cff`,
//!    and `codemeta.json` remain synchronized on `3.0.0` and `https://frameassembly.ai.studio/`.

use std::fs;
use std::path::PathBuf;

/// Returns every `*.md` file directly inside `docs/`, sorted for deterministic reporting.
fn doc_guides() -> Vec<PathBuf> {
    let mut guides: Vec<PathBuf> = fs::read_dir("docs")
        .expect("Missing docs/ directory")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .collect();
    guides.sort();
    guides
}

/// Verifies that corpus-only training headers never leak into human-facing documentation.
#[test]
fn test_human_docs_have_no_training_metadata_comments() {
    let mut files = vec![PathBuf::from("README.md")];
    files.extend(
        doc_guides()
            .into_iter()
            .filter(|path| !path.ends_with("13_for_nerds.md")),
    );

    let mut leaks = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("Failed to read Markdown file");
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if ["// PROMPT:", "// TOKENS:", "// INSTRUCTION:"]
                .iter()
                .any(|marker| trimmed.starts_with(marker))
            {
                leaks.push(format!("{}:{}", file.display(), idx + 1));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "Training metadata comments found in human-facing docs:\n{}",
        leaks.join("\n")
    );
}

/// Verifies `contrib/mime/text-vnd.frameassembly.xml` XML schema (`<mime-info>` root), `<magic>`
/// lexer token validity, live `update-mime-database` + `gio info` classification (including
/// `> 600` byte comment headers, MAC-only L2 hosts, and zero false positives on ordinary text),
/// `languages.yml` schema, `heuristics.yml` disambiguation, and `contrib/linguist/samples/*.frasm`.
#[test]
fn test_fasm_mime_xml_and_linguist_samples() {
    let xml_path = "contrib/mime/text-vnd.frameassembly.xml";
    let xml_text = fs::read_to_string(xml_path).expect("Missing MIME XML file");
    assert!(
        xml_text.contains("<mime-info ")
            && xml_text.contains("type=\"text/vnd.frameassembly\"")
            && xml_text.contains("pattern=\"*.frasm\""),
        "MIME XML must wrap <mime-type type=\"text/vnd.frameassembly\"> inside <mime-info>"
    );

    let py_verify = r#"
import xml.etree.ElementTree as ET, subprocess, shutil, tempfile, os, re

tree = ET.parse("contrib/mime/text-vnd.frameassembly.xml")
root = tree.getroot()
assert root.tag.endswith("mime-info"), f"Root element must be mime-info, got {root.tag}"

if shutil.which("update-mime-database") and shutil.which("gio"):
    with tempfile.TemporaryDirectory() as tmp:
        pkg_dir = os.path.join(tmp, "mime", "packages")
        os.makedirs(pkg_dir)
        shutil.copy("contrib/mime/text-vnd.frameassembly.xml", pkg_dir)
        env = os.environ.copy()
        env["XDG_DATA_HOME"] = tmp
        env["XDG_DATA_DIRS"] = f"{tmp}:/usr/local/share:/usr/share"
        subprocess.run(["update-mime-database", os.path.join(tmp, "mime")], env=env, check=True)

        r_fasm = subprocess.check_output(
            ["gio", "info", "-a", "standard::content-type,standard::fast-content-type",
             "contrib/linguist/samples/enterprise_snmpv3_and_tls.frasm"],
            env=env, text=True
        )
        assert "standard::content-type: text/vnd.frameassembly" in r_fasm, r_fasm
        assert "standard::fast-content-type: text/vnd.frameassembly" in r_fasm, r_fasm

        long_hdr = os.path.join(tmp, "long_comment_spec")
        with open(long_hdr, "w") as f:
            f.write("// " + ("A" * 320) + "\n// " + ("B" * 320) + "\nhost\tgw { ip 10.0.0.1 }\nflow f(a, b) { a -> b icmp }\ncompile { f(gw, gw) }\n")
        r_long = subprocess.check_output(["gio", "info", "-a", "standard::content-type", long_hdr], env=env, text=True)
        assert "standard::content-type: text/vnd.frameassembly" in r_long, r_long

        mac_only = os.path.join(tmp, "mac_only_spec")
        with open(mac_only, "w") as f:
            f.write("host sw1 { mac 00:1c:73:aa:bb:01 }\nhost sw2 { mac 00:1c:73:aa:bb:02 }\nflow f(a, b) { a -> b lldp }\ncompile { f(sw1, sw2) }\n")
        r_mac = subprocess.check_output(["gio", "info", "-a", "standard::content-type", mac_only], env=env, text=True)
        assert "standard::content-type: text/vnd.frameassembly" in r_mac, r_mac

        for name, body in [
            ("NOTES", "How to compile this project on localhost:\nRun make all.\n"),
            ("DocFile", "This host script runs on localhost port 8080.\n"),
        ]:
            p = os.path.join(tmp, name)
            with open(p, "w") as f:
                f.write(body)
            r_txt = subprocess.check_output(["gio", "info", "-a", "standard::content-type", p], env=env, text=True)
            assert "text/vnd.frameassembly" not in r_txt, f"False positive on {name}: {r_txt}"

lang_yml = open("contrib/linguist/languages.yml").read()
assert "wrap: false" not in lang_yml, "languages.yml must not include wrap: false"

heur_text = open("contrib/linguist/heuristics.yml").read()
patterns = [line.strip().strip("- ").strip("'") for line in heur_text.splitlines() if line.strip().startswith("- '")]
fasm_pats = [re.compile(p, re.MULTILINE) for p in patterns[:4]]
asm_pats = [re.compile(p, re.MULTILINE) for p in patterns[4:]]

def classify(text):
    if any(p.search(text) for p in fasm_pats):
        return "FrameAssembly"
    if any(p.search(text) for p in asm_pats):
        return "Assembly"
    return "Unknown"

assert classify("host gw { mac 00:11:22:33:44:55 ip 10.0.0.1 }") == "FrameAssembly"
assert classify("host sw { mac 00:11:22:33:44:55 }") == "FrameAssembly"
assert classify("c -> s dscp 46 ttl 64 srcport 50000 tcp syn sackperm") == "FrameAssembly"
assert classify("; host ip comment in x86 fasm\nformat ELF64 executable\nmacro compile {\n  mov eax, 1\n}\n") == "Assembly"
"#;

    let status = std::process::Command::new("python3")
        .arg("-c")
        .arg(py_verify)
        .status()
        .expect("Failed to invoke python3 MIME/Linguist verification");
    assert!(
        status.success(),
        "MIME XML / Linguist heuristics verification failed"
    );

    let mut matched_tokens = 0usize;
    for line in xml_text.lines() {
        if let Some(pos) = line.find("value=\"") {
            let after = &line[pos + 7..];
            if let Some(end) = after.find('"') {
                let raw_val = after[..end].replace("&#x09;", "\t");
                let token_str = raw_val.trim();
                let lexed = frameassembly::lexer::lex(token_str).unwrap_or_else(|e| {
                    panic!("MIME magic token {token_str:?} failed to lex: {e:?}")
                });
                assert_eq!(
                    lexed.len(),
                    1,
                    "MIME magic value {token_str:?} must lex to a single keyword token"
                );
                assert!(
                    !matches!(lexed[0].0, frameassembly::lexer::Token::Ident(_)),
                    "MIME magic value {token_str:?} must be a built-in v3.0.0 keyword, not Ident"
                );
                matched_tokens += 1;
            }
        }
    }
    assert!(
        matched_tokens >= 12,
        "Expected at least 12 magic match token clauses in MIME XML, got {matched_tokens}"
    );

    for entry in fs::read_dir("contrib/linguist/samples").expect("Missing contrib/linguist/samples")
    {
        let path = entry.expect("Invalid directory entry").path();
        if path.extension().is_some_and(|ext| ext == "frasm") {
            let src = fs::read_to_string(&path).expect("Failed to read Linguist sample");
            assert!(
                !src.to_ascii_lowercase().contains("loop "),
                "Linguist sample {} must not use removed loop syntax",
                path.display()
            );
            let prog = frameassembly::parser::parse_program(&src)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {e:?}", path.display()));
            frameassembly::parser::validate_semantics(&prog, &src)
                .unwrap_or_else(|e| panic!("Failed semantics in {}: {e:?}", path.display()));
            let frames = frameassembly::backend::compile_program(&prog)
                .unwrap_or_else(|e| panic!("Failed compilation in {}: {e}", path.display()));
            assert!(
                frames.len() >= 4,
                "Linguist sample {} must emit at least 4 frames",
                path.display()
            );
        }
    }
}

/// Verifies `Cargo.toml` crates.io limits (`<= 5` keywords of `<= 20` ASCII chars, `<= 5`
/// categories, `120..=160` char `description`) and enforces one-word `FrameAssembly` branding and
/// accurate rootless terminology across documentation and configuration files.
#[test]
fn test_cargo_toml_seo_and_brand_terminology_invariants() {
    let cargo_toml = fs::read_to_string("Cargo.toml").expect("Missing Cargo.toml");
    let desc_line = cargo_toml
        .lines()
        .find(|l| l.starts_with("description = "))
        .expect("Missing description in Cargo.toml");
    let desc = desc_line
        .trim_start_matches("description = \"")
        .trim_end_matches('"');
    assert!(
        (120..=160).contains(&desc.len()) && desc.is_ascii(),
        "Cargo.toml description must be 120..=160 ASCII chars, got {} chars",
        desc.len()
    );

    let kw_line = cargo_toml
        .lines()
        .find(|l| l.starts_with("keywords = "))
        .expect("Missing keywords in Cargo.toml");
    let kws: Vec<&str> = kw_line
        .split('"')
        .skip(1)
        .step_by(2)
        .collect();
    assert!(
        (1..=5).contains(&kws.len()) && kws.iter().all(|k| k.len() <= 20 && k.is_ascii()),
        "Cargo.toml keywords must have <= 5 items of <= 20 ASCII chars each: {kws:?}"
    );

    let banned_two_word = concat!("frame", " ", "assembly");
    let banned_zero_dep = concat!("zero-", "dependency");
    let mut check_paths = vec![
        PathBuf::from("Cargo.toml"),
        PathBuf::from("README.md"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
        PathBuf::from(".github/copilot-instructions.md"),
        PathBuf::from("llms.txt"),
        PathBuf::from("src/lib.rs"),
        PathBuf::from("contrib/iana/text-vnd.frameassembly.md"),
        PathBuf::from("contrib/mime/text-vnd.frameassembly.xml"),
        PathBuf::from("contrib/linguist/README.md"),
        PathBuf::from("contrib/linguist/languages.yml"),
        PathBuf::from("contrib/linguist/heuristics.yml"),
    ];
    check_paths.extend(doc_guides());

    for path in &check_paths {
        let lower = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()))
            .to_ascii_lowercase();
        assert!(
            !lower.contains(banned_two_word),
            "Found banned two-word brand in {}",
            path.display()
        );
        assert!(
            !lower.contains(banned_zero_dep),
            "Found banned dependency claim in {}",
            path.display()
        );
    }
}

/// Verifies that all four ecosystem publishing and metadata surfaces (`Cargo.toml`, `src/lib.rs`,
/// `frameassembly-wasm`, `frameassembly-vscode`, `install.sh`, `CITATION.cff`, `codemeta.json`,
/// `llms.txt`, and `llms-full.txt`) are synchronized at version `3.0.0`, link the official
/// website (`https://frameassembly.ai.studio/`), and omit removed distribution channels.
#[test]
fn test_ecosystem_v2_0_0_version_and_metadata_lockstep() {
    let cargo_toml = fs::read_to_string("Cargo.toml").expect("Missing Cargo.toml");
    assert!(
        cargo_toml.contains("version = \"3.0.0\"")
            && cargo_toml.contains("homepage = \"https://frameassembly.ai.studio/\""),
        "Cargo.toml must declare version = \"3.0.0\" and homepage = \"https://frameassembly.ai.studio/\""
    );

    let lib_rs = fs::read_to_string("src/lib.rs").expect("Missing src/lib.rs");
    assert!(
        lib_rs.contains("3.0.0") && lib_rs.contains("https://frameassembly.ai.studio/"),
        "src/lib.rs must reference version 3.0.0 and https://frameassembly.ai.studio/"
    );

    let wasm_cargo = fs::read_to_string("frameassembly-wasm/Cargo.toml")
        .expect("Missing frameassembly-wasm/Cargo.toml");
    assert!(
        wasm_cargo.contains("version = \"3.0.0\"")
            && wasm_cargo.contains("frameassembly = { path = \"..\", version = \"3.0.0\" }")
            && wasm_cargo.contains("homepage = \"https://frameassembly.ai.studio/\""),
        "frameassembly-wasm/Cargo.toml must declare version 3.0.0, pin frameassembly 3.0.0, and set homepage"
    );

    let wasm_pkg = fs::read_to_string("frameassembly-wasm/package.json")
        .expect("Missing frameassembly-wasm/package.json");
    assert!(
        wasm_pkg.contains("\"version\": \"3.0.0\"")
            && wasm_pkg.contains("\"homepage\": \"https://frameassembly.ai.studio/\""),
        "frameassembly-wasm/package.json must declare version 3.0.0 and homepage"
    );

    let vscode_pkg = fs::read_to_string("frameassembly-vscode/package.json")
        .expect("Missing frameassembly-vscode/package.json");
    assert!(
        vscode_pkg.contains("\"version\": \"3.0.0\"")
            && vscode_pkg.contains("\"homepage\": \"https://frameassembly.ai.studio/\""),
        "frameassembly-vscode/package.json must declare version 3.0.0 and homepage"
    );

    let install_sh = fs::read_to_string("install.sh").expect("Missing install.sh");
    assert!(
        install_sh.contains("VSIX_VERSION=\"3.0.0\"")
            && install_sh.contains("RELEASE_VERSION=\"3.0.0\""),
        "install.sh must declare VSIX_VERSION=\"3.0.0\" and RELEASE_VERSION=\"3.0.0\""
    );

    let citation_cff = fs::read_to_string("CITATION.cff").expect("Missing CITATION.cff");
    assert!(
        (citation_cff.contains("version: 3.0.0") || citation_cff.contains("version: \"3.0.0\""))
            && citation_cff.contains("url: \"https://frameassembly.ai.studio/\""),
        "CITATION.cff must declare version 3.0.0 and url https://frameassembly.ai.studio/"
    );

    let codemeta_json = fs::read_to_string("codemeta.json").expect("Missing codemeta.json");
    assert!(
        codemeta_json.contains("\"version\": \"3.0.0\"")
            && codemeta_json.contains("\"url\": \"https://frameassembly.ai.studio/\""),
        "codemeta.json must declare version 3.0.0 and url https://frameassembly.ai.studio/"
    );

    let llms_txt = fs::read_to_string("llms.txt").expect("Missing llms.txt");
    assert!(
        llms_txt.contains("3.0.0")
            && llms_txt.contains("https://frameassembly.ai.studio/")
            && llms_txt.lines().count() < 512
            && llms_txt.len() < 25_000,
        "llms.txt must reference 3.0.0 and https://frameassembly.ai.studio/ and remain < 512 lines and < 25,000 bytes"
    );

    let llms_full = fs::read_to_string("llms-full.txt").expect("Missing llms-full.txt");
    assert!(
        llms_full.contains("3.0.0")
            && llms_full.contains("https://frameassembly.ai.studio/")
            && llms_full.len() < 1_500_000
            && !llms_full.as_bytes().contains(&0),
        "llms-full.txt must reference 3.0.0, remain < 1,500,000 bytes, and contain zero NUL bytes"
    );

    let context7 = fs::read_to_string("context7.json").expect("Missing context7.json");
    assert!(
        context7.contains("\"version\": \"3.0.0\"")
            && context7.contains("https://frameassembly.ai.studio/"),
        "context7.json must declare version 3.0.0 and https://frameassembly.ai.studio/"
    );

    for (doc_path, require_browser_link, check_removed_channels) in [
        ("README.md", true, true),
        ("docs/01_getting_started.md", true, true),
        ("frameassembly-vscode/README.md", true, true),
        ("frameassembly-wasm/README.md", false, false),
        ("contrib/linguist/README.md", false, false),
        ("contrib/packaging/README.md", false, true),
        ("AGENTS.md", false, false),
        ("CLAUDE.md", false, false),
        (".github/copilot-instructions.md", false, false),
    ] {
        let doc = fs::read_to_string(doc_path).unwrap_or_else(|_| panic!("Missing {}", doc_path));
        assert!(
            doc.contains("https://frameassembly.ai.studio/"),
            "{} must link https://frameassembly.ai.studio/",
            doc_path
        );
        if require_browser_link {
            assert!(
                doc.contains("Try in Browser") || doc.contains("frameassembly.ai.studio"),
                "{} must highlight browser playground access",
                doc_path
            );
        }
        if check_removed_channels {
            let doc_lower = doc.to_ascii_lowercase();
            for removed in [
                concat!("win", "get install"),
                concat!("au", "r.archlinux.org"),
                concat!("yay -s ", "frameassembly"),
                concat!("open-", "vsx.org"),
            ] {
                assert!(
                    !doc_lower.contains(removed),
                    "{} must not reference removed channel '{}'",
                    doc_path,
                    removed
                );
            }
        }
    }
}
