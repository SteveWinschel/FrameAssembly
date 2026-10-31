//! Documentation integrity gate for FrameAssembly's human-facing and agent-facing Markdown.
//!
//! Network engineers who do not program read `README.md` and the guides in `docs/`, while AI
//! agents read `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, and `llms.txt`. This
//! suite keeps both audiences safe from stale documentation by enforcing three invariants:
//! 1. **Relative link integrity**: every relative Markdown link `[text](path#anchor)` outside fenced
//!    code blocks resolves to an existing file or directory on disk.
//! 2. **No orphan guides**: every `docs/*.md` guide is linked from `README.md`.
//! 3. **No training metadata in human docs**: the corpus-only `// PROMPT:`, `// TOKENS:`, and
//!    `// INSTRUCTION:` header comments never appear in `README.md` or `docs/*.md`, except in
//!    `docs/for_nerds.md`, which documents the `examples/` corpus format for AI engineers.

use std::fs;
use std::path::{Path, PathBuf};

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

/// Extracts relative link targets from Markdown `text`, skipping fenced code blocks, absolute
/// URLs (`http:`, `https:`, `mailto:`), and pure in-page `#anchor` links.
fn relative_links(text: &str) -> Vec<(usize, String)> {
    let mut links = Vec::new();
    let mut in_fence = false;
    for (idx, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut rest = line;
        while let Some(pos) = rest.find("](") {
            let after = &rest[pos + 2..];
            let Some(end) = after.find(')') else {
                break;
            };
            let target = after[..end].trim().trim_start_matches('<').trim_end_matches('>');
            let is_external = ["http://", "https://", "mailto:", "#"]
                .iter()
                .any(|prefix| target.starts_with(prefix));
            if !is_external && !target.is_empty() && !target.contains(' ') {
                links.push((idx + 1, target.to_string()));
            }
            rest = &after[end..];
        }
    }
    links
}

/// Verifies that every relative link in the human- and agent-facing Markdown files resolves.
#[test]
fn test_markdown_relative_links_resolve() {
    let mut files: Vec<PathBuf> = [
        "README.md",
        "AGENTS.md",
        "CLAUDE.md",
        ".github/copilot-instructions.md",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    files.extend(doc_guides());

    let mut broken = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", file.display(), e));
        let base = file.parent().unwrap_or(Path::new(""));
        for (line, target) in relative_links(&text) {
            let path_part = target.split('#').next().unwrap_or_default();
            if path_part.is_empty() {
                continue;
            }
            if !base.join(path_part).exists() {
                broken.push(format!("{}:{} -> {}", file.display(), line, target));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "Broken relative Markdown links:\n{}",
        broken.join("\n")
    );
}

/// Verifies that `README.md` links every guide in `docs/`, so no guide is orphaned.
#[test]
fn test_every_doc_guide_is_linked_from_readme() {
    let readme = fs::read_to_string("README.md").expect("Missing README.md");
    let orphans: Vec<String> = doc_guides()
        .iter()
        .filter_map(|guide| {
            let name = guide.file_name()?.to_str()?;
            let linked = readme.contains(&format!("(docs/{name}"))
                || readme.contains(&format!("(./docs/{name}"));
            (!linked).then(|| name.to_string())
        })
        .collect();
    assert!(
        orphans.is_empty(),
        "docs/ guides not linked from README.md: {:?}",
        orphans
    );
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

