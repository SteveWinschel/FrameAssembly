//! Documentation integrity gate for FrameAssembly's human-facing and agent-facing Markdown.
//!
//! Network engineers who do not program read `README.md` and the guides in `docs/`, while AI
//! agents read `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, and `llms.txt`. This
//! suite keeps both audiences safe from stale documentation by enforcing these invariants:
//! 1. **No training metadata in human docs**: the corpus-only `// PROMPT:`, `// TOKENS:`, and
//!    `// INSTRUCTION:` header comments never appear in `README.md` or `docs/*.md`, except in
//!    `docs/for_nerds.md`, which documents the `examples/` corpus format for AI engineers.
//! 2. **MIME, Linguist & SEO hygiene**: the `.fasm` MIME XML, GitHub Linguist samples, and
//!    `Cargo.toml` metadata stay consistent with FrameAssembly branding and terminology.

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
            .filter(|path| !path.ends_with("for_nerds.md")),
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
/// `> 600` byte comment headers and zero false positives on ordinary plain text), `languages.yml`
/// schema, `heuristics.yml` disambiguation, and compilation of `contrib/linguist/samples/*.fasm`.
#[test]
fn test_fasm_mime_xml_and_linguist_samples() {
    let xml_path = "contrib/mime/text-vnd.frameassembly.xml";
    let xml_text = fs::read_to_string(xml_path).expect("Missing MIME XML file");
    assert!(
        xml_text.contains("<mime-info ")
            && xml_text.contains("type=\"text/vnd.frameassembly\"")
            && xml_text.contains("pattern=\"*.fasm\""),
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
             "contrib/linguist/samples/enterprise_snmpv3_and_tls.fasm"],
            env=env, text=True
        )
        assert "standard::content-type: text/vnd.frameassembly" in r_fasm, r_fasm
        assert "standard::fast-content-type: text/vnd.frameassembly" in r_fasm, r_fasm

        long_hdr = os.path.join(tmp, "long_comment_spec")
        with open(long_hdr, "w") as f:
            f.write("// " + ("A" * 320) + "\n// " + ("B" * 320) + "\nHOST\tgw { IP 10.0.0.1 }\nFLOW f(a, b) { a -> b ICMP }\nCOMPILE { f(gw, gw) }\n")
        r_long = subprocess.check_output(["gio", "info", "-a", "standard::content-type", long_hdr], env=env, text=True)
        assert "standard::content-type: text/vnd.frameassembly" in r_long, r_long

        for name, body in [
            ("NOTES", "How to compile this project on localhost:\nRun make all.\n"),
            ("DocFile", "This script runs on localhost port 8080.\n"),
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

assert classify("HOST gw { MAC 00:11:22:33:44:55 IP 10.0.0.1 }") == "FrameAssembly"
assert classify("c -> s DSCP 46 TTL 64 SRCPORT 50000 TCP SYN") == "FrameAssembly"
assert classify("; HOST IP comment in x86 fasm\nformat ELF64 executable\nmacro compile {\n  mov eax, 1\n}\n") == "Assembly"
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
        if path.extension().is_some_and(|ext| ext == "fasm") {
            let src = fs::read_to_string(&path).expect("Failed to read Linguist sample");
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


