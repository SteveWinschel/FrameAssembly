//! Seven-gate corpus, lexer-bijection, Markdown/Rustdoc block compilation, six-way grammar/parser
//! lockstep, AI pre-training chunk filter, AST-to-builder field wiring, and reverse PCAP
//! decompiler symmetry suite for FrameAssembly v3.0.0:
//! 1. **Gate 1**: All 2,611 `.frasm` files satisfy header/metric rules and compile to PCAPNG (`0x0A0D0D0A`).
//! 2. **Gate 2**: `// TOKENS:` matches `src/lexer/mod.rs` lowercase keywords in exact first-appearance order.
//! 3. **Gate 3**: All ````frameassembly` and ````frasm` blocks across docs, skills, and `src/**/*.rs` compile.
//! 4. **Gate 4**: Six-way lockstep (`src/lexer/mod.rs`, `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, TextMate).
//! 5. **Gate 5**: `< 50 KB` Rust/corpus ceiling, `//!` docstrings (`>= 50` words), zero NUL bytes, 13 docs.
//! 6. **Gate 6**: AST `*Spec` fields wired to builders and 1:1 reverse decompiler file symmetry.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use frameassembly::backend::{compile_program, generate_pcap};
use frameassembly::lexer::Token;
use frameassembly::parser::{parse_program, validate_semantics};
use logos::Logos;

/// Recursively collects all files matching `extension` under `dir`.
fn collect_files_with_ext(dir: &Path, extension: &str, results: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files_with_ext(&path, extension, results);
            } else if path.extension().and_then(|s| s.to_str()) == Some(extension) {
                results.push(path);
            }
        }
    }
}

/// Discovers all `.frasm` files in the `examples/` directory hierarchy sorted by path.
fn get_sorted_example_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_files_with_ext(Path::new("examples"), "frasm", &mut paths);
    paths.sort();
    paths
}

/// Extracts all built-in `#[token("...")]` keyword literals from `src/lexer/mod.rs`, asserting
/// FrameAssembly v3.0.0 strict-lowercase `[a-z0-9]+` invariants (zero uppercase, zero `_`, zero `-`,
/// zero `ignore(ascii_case)`, and zero `loop`).
fn extract_lexer_lowercase_keywords() -> HashSet<String> {
    let lexer_src = fs::read_to_string("src/lexer/mod.rs").expect("Failed to read src/lexer/mod.rs");
    assert!(
        !lexer_src.contains("ignore(ascii_case)"),
        "src/lexer/mod.rs must not use ignore(ascii_case) in FrameAssembly v3.0.0"
    );
    let punct: HashSet<&str> = ["{", "}", "(", ")", "->", "<-", ","].into_iter().collect();
    let mut keywords = HashSet::new();
    for line in lexer_src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#[token(\"")
            && let Some(end_idx) = rest.find('"')
        {
            let tok = &rest[..end_idx];
            if punct.contains(tok) {
                continue;
            }
            assert!(
                !tok.is_empty()
                    && tok.chars().next().unwrap().is_ascii_lowercase()
                    && tok.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "Every built-in keyword in src/lexer/mod.rs must be strict [a-z0-9]+ without '_' or '-', found: '{}'",
                tok
            );
            assert_ne!(
                tok, "loop",
                "Removed 'loop' token must not exist in src/lexer/mod.rs"
            );
            keywords.insert(tok.to_string());
        }
    }
    keywords
}

/// Extracts all `Token` enum variant identifiers from `src/lexer/mod.rs`.
fn extract_lexer_token_variants() -> HashSet<String> {
    let lexer_src = fs::read_to_string("src/lexer/mod.rs").expect("Failed to read src/lexer/mod.rs");
    let mut variants = HashSet::new();
    let mut in_enum = false;
    for line in lexer_src.lines() {
        let s = line.trim();
        if s.starts_with("pub enum Token") {
            in_enum = true;
            continue;
        }
        if in_enum && s == "}" {
            break;
        }
        if !in_enum || s.starts_with("//") {
            continue;
        }
        let after_attr = if let Some((_, rhs)) = s.rsplit_once(']') {
            rhs.trim()
        } else {
            s
        };
        let name = after_attr
            .split('(')
            .next()
            .unwrap_or("")
            .trim_end_matches(',')
            .trim();
        if !name.is_empty() && name.chars().next().unwrap().is_ascii_uppercase() {
            variants.insert(name.to_string());
        }
    }
    variants
}

/// Computes the expected `// TOKENS:` list from the ordered unique keyword slices emitted by `Token::lexer`,
/// respecting the 200-character line-length cap on multi-protocol omnibus files.
fn expected_tokens_for_file(ordered_keywords: &[String]) -> Vec<String> {
    let full = format!("// TOKENS: {}", ordered_keywords.join(", "));
    if full.len() <= 200 {
        return ordered_keywords.to_vec();
    }
    let tail = ordered_keywords
        .last()
        .cloned()
        .unwrap_or_else(|| "compile".to_string());
    let mut prefix = Vec::new();
    for tok in &ordered_keywords[..ordered_keywords.len().saturating_sub(1)] {
        let mut candidate = prefix.clone();
        candidate.push(tok.clone());
        candidate.push(tail.clone());
        if format!("// TOKENS: {}", candidate.join(", ")).len() <= 200 {
            prefix.push(tok.clone());
        } else {
            break;
        }
    }
    prefix.push(tail);
    prefix
}

/// Inspects and verifies a single `.frasm` example file for Gate 1 and Gate 2.
fn verify_example_file(path: &Path, valid_keywords: &HashSet<String>) -> Result<(), String> {
    let filename = path.file_name().and_then(|s| s.to_str()).ok_or("Invalid filename")?;
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    if content.len() >= 50_000 {
        return Err(format!("{}: File size {} bytes exceeds 50,000-byte limit", path.display(), content.len()));
    }

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 3 {
        return Err(format!("{}: File too short (must have at least 3 lines)", path.display()));
    }

    let word_count = content.split_whitespace().count();
    if word_count < 50 {
        return Err(format!("{}: Word count {} is below 50-word OpenCoder threshold", path.display(), word_count));
    }
    let total_chars: usize = lines.iter().map(|l| l.len()).sum();
    let avg_line_len = total_chars as f64 / (lines.len() as f64);
    let max_line_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    if avg_line_len > 85.0 {
        return Err(format!("{}: Average line length {:.1} exceeds 85 chars", path.display(), avg_line_len));
    }
    if max_line_len > 200 {
        return Err(format!("{}: Max line length {} exceeds 200 chars", path.display(), max_line_len));
    }

    // OpenCoder duplicate non-blank line ratio (< 0.25)
    let mut line_counts: HashMap<&str, usize> = HashMap::new();
    let mut non_blank_chars = 0usize;
    for &ln in &lines {
        if !ln.trim().is_empty() {
            *line_counts.entry(ln).or_insert(0) += 1;
            non_blank_chars += ln.len();
        }
    }
    let dupe_chars: usize = line_counts
        .iter()
        .filter(|(_, c)| **c > 1)
        .map(|(ln, c)| ln.len() * (*c - 1))
        .sum();
    let dupe_ratio = dupe_chars as f64 / (non_blank_chars.max(1) as f64);
    if dupe_ratio >= 0.25 {
        return Err(format!(
            "{}: Duplicate line character ratio {:.3} >= 0.25",
            path.display(),
            dupe_ratio
        ));
    }

    if !lines[0].starts_with("// PROMPT: ") {
        return Err(format!("{}: Line 1 must begin with '// PROMPT: ', got: '{}'", path.display(), lines[0]));
    }
    if lines[0].trim_start_matches("// PROMPT: ").trim().is_empty() {
        return Err(format!("{}: PROMPT comment body cannot be empty", path.display()));
    }

    if !lines[1].starts_with("// TOKENS: ") {
        return Err(format!("{}: Line 2 must begin with '// TOKENS: ', got: '{}'", path.display(), lines[1]));
    }
    let tokens_body = lines[1].trim_start_matches("// TOKENS: ").trim();
    if tokens_body.is_empty() {
        return Err(format!("{}: TOKENS comment body cannot be empty", path.display()));
    }

    let header_tokens: Vec<String> = tokens_body
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    for raw_tok in &header_tokens {
        if !valid_keywords.contains(raw_tok) {
            return Err(format!("{}: Non-canonical or unknown token '{}' in // TOKENS: header", path.display(), raw_tok));
        }
        let mut lex = Token::lexer(raw_tok);
        if let Some(Ok(Token::Ident(id))) = lex.next() {
            return Err(format!("{}: Hallucinated identifier '{}' in // TOKENS: header", path.display(), id));
        }
    }

    // Gate 2 exact ordered lexer bijection check on the code body
    let mut ordered_body_keywords = Vec::new();
    let mut seen_kw = HashSet::new();
    let mut body_lex = Token::lexer(&content);
    while let Some(res) = body_lex.next() {
        let tok = res.map_err(|_| format!("{}: Lexer error in code body", path.display()))?;
        let slice = body_lex.slice();
        if valid_keywords.contains(slice)
            && !matches!(
                tok,
                Token::Ident(_)
                    | Token::StringLit(_)
                    | Token::IpAddress(_)
                    | Token::MacAddress(_)
                    | Token::OidStr(_)
                    | Token::Number(_)
            )
            && seen_kw.insert(slice.to_string())
        {
            ordered_body_keywords.push(slice.to_string());
        }
    }
    let expected_header = expected_tokens_for_file(&ordered_body_keywords);
    if header_tokens != expected_header {
        return Err(format!(
            "{}: // TOKENS: bijection mismatch\n  header:   {:?}\n  expected: {:?}",
            path.display(),
            header_tokens,
            expected_header
        ));
    }

    if !content.contains("// INSTRUCTION:") {
        return Err(format!("{}: File must contain '// INSTRUCTION:' comments before blocks", path.display()));
    }

    let program = parse_program(&content).map_err(|e| format!("Parse error in {}: {:?}", path.display(), e))?;
    validate_semantics(&program, &content).map_err(|e| format!("Semantic error in {}: {:?}", path.display(), e))?;

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp_pcap = std::env::temp_dir().join(format!("verify_{}_{}_{}", std::process::id(), count, filename));
    let temp_pcap_str = temp_pcap.to_str().ok_or("Invalid temp path")?;

    if let Err(e) = generate_pcap(&program, temp_pcap_str) {
        let _ = fs::remove_file(&temp_pcap);
        return Err(format!("Compilation error in {}: {}", path.display(), e));
    }

    let bytes = fs::read(&temp_pcap).map_err(|e| format!("Failed to read output PCAP for {}: {}", path.display(), e))?;
    let _ = fs::remove_file(&temp_pcap);

    if bytes.len() < 28 {
        return Err(format!("{}: Generated PCAPNG is too small ({} bytes)", path.display(), bytes.len()));
    }
    if bytes[0..4] != [0x0A, 0x0D, 0x0D, 0x0A] {
        return Err(format!("{}: Output file does not begin with PCAPNG SHB magic 0x0A0D0D0A", path.display()));
    }

    Ok(())
}

/// Tests that no `.frasm` files remain directly in the root of `examples/`.
#[test]
fn test_corpus_no_root_examples() {
    let mut root_fasm = Vec::new();
    if let Ok(entries) = fs::read_dir("examples") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("frasm") {
                root_fasm.push(path);
            }
        }
    }
    assert!(
        root_fasm.is_empty(),
        "No flat .frasm files should remain in examples/ root, found: {:?}",
        root_fasm
    );
}

/// Canonical Layer 2 protocol identifiers across `src/`, `examples/`, and `src/reverse/`.
const EXPECTED_L2: [&str; 8] = ["arp", "vlan", "qinq", "lldp", "stp", "lacp", "eapol", "mpls"];

/// Canonical Layer 3 protocol identifiers across `src/`, `examples/`, and `src/reverse/`.
const EXPECTED_L3: [&str; 20] = [
    "icmp", "ndp", "igmp", "mld", "gre", "vxlan", "geneve", "ipsec", "esp", "ah", "ikev2",
    "wireguard", "ospf", "bgp", "rip", "vrrp", "hsrp", "pim", "bfd", "openflow",
];

/// Canonical Layer 4 protocol identifiers across `src/`, `examples/`, and `src/reverse/`.
const EXPECTED_L4: [&str; 3] = ["tcp", "udp", "sctp"];

/// Canonical Layer 7 non-SNMP protocol identifiers across `src/`, `examples/`, and `src/reverse/`.
const EXPECTED_L7_NON_SNMP: [&str; 47] = [
    "dns", "mdns", "dhcp", "ntp", "ptp", "radius", "tacacs", "syslog", "netflow", "ipfix",
    "sflow", "tftp", "ftp", "ssh", "telnet", "http", "http2", "grpc", "websocket", "tls",
    "quic", "stun", "sip", "rtp", "rtsp", "smtp", "imap", "pop3", "kerberos", "ldap",
    "smb", "nfs", "redis", "memcached", "mysql", "postgres", "mqtt", "coap", "amqp",
    "ssdp", "whois", "modbus", "bacnet", "dnp3", "s7comm", "ethernetip", "opcua",
];

/// Tests that all `.frasm` example files in the corpus avoid numeric prefixes and follow snake_case naming.
#[test]
fn test_corpus_non_numeric_naming_conventions() {
    let paths = get_sorted_example_paths();
    assert_eq!(
        paths.len(),
        2611,
        "Corpus must contain exactly 2,611 .frasm examples across all layers, found {}",
        paths.len()
    );

    for path in &paths {
        let filename = path.file_name().unwrap().to_str().unwrap();
        let first_char = filename.chars().next().expect("Non-empty filename");
        assert!(
            !first_char.is_ascii_digit(),
            "{}: Filenames must not start with a numeric prefix",
            path.display()
        );
        assert!(
            filename.ends_with(".frasm"),
            "{}: Must have .frasm extension",
            path.display()
        );
    }
}

/// Tests that all 81 protocol folders have at least 30 scenarios and `examples/topologies` has at least 100.
#[test]
fn test_corpus_protocol_folder_coverage() {
    let expected_snmp = ["snmpv1", "snmpv2c", "snmpv3"];
    for (base, protos) in [
        ("examples/l2", &EXPECTED_L2[..]),
        ("examples/l3", &EXPECTED_L3[..]),
        ("examples/l4", &EXPECTED_L4[..]),
        ("examples/l7", &EXPECTED_L7_NON_SNMP[..]),
        ("examples/l7/snmp", &expected_snmp[..]),
    ] {
        for proto in protos {
            let dir = Path::new(base).join(proto);
            assert!(dir.exists() && dir.is_dir(), "Missing folder: {}", dir.display());
            let mut files = Vec::new();
            collect_files_with_ext(&dir, "frasm", &mut files);
            assert!(
                files.len() >= 30,
                "Folder {} has fewer than 30 scenarios: {}",
                dir.display(),
                files.len()
            );
        }
    }

    let topologies_dir = Path::new("examples/topologies");
    assert!(topologies_dir.exists() && topologies_dir.is_dir(), "Missing examples/topologies");
    let mut topo_files = Vec::new();
    collect_files_with_ext(topologies_dir, "frasm", &mut topo_files);
    assert!(
        topo_files.len() >= 100,
        "examples/topologies has fewer than 100 scenarios: {}",
        topo_files.len()
    );
}

/// Gate 1 & Gate 2: Tests all `.frasm` example files in `examples/` for headers, lexer bijection,
/// pre-training metrics, syntax parsing, and PCAPNG compilation.
#[test]
fn test_corpus_all_examples_headers_and_compilation() {
    let paths = get_sorted_example_paths();
    let valid_keywords = extract_lexer_lowercase_keywords();
    assert_eq!(
        paths.len(),
        2611,
        "Corpus must have 2,611 .frasm examples, found {}",
        paths.len()
    );

    let mut failed = Vec::new();
    let demo_path = Path::new("demo.frasm");
    if demo_path.exists() {
        let demo_src = fs::read_to_string(demo_path).expect("Failed to read demo.frasm");
        for tag in ["// PROMPT:", "// TOKENS:", "// INSTRUCTION:"] {
            assert!(!demo_src.contains(tag), "demo.frasm must not contain {}", tag);
        }
        let prog = parse_program(&demo_src).expect("demo.frasm failed to parse");
        validate_semantics(&prog, &demo_src).expect("demo.frasm failed semantic validation");
        compile_program(&prog).expect("demo.frasm failed wire compilation");
    }
    for path in &paths {
        if let Err(e) = verify_example_file(path, &valid_keywords) {
            failed.push(e);
        }
    }

    if !failed.is_empty() {
        panic!(
            "Corpus verification failed for {} file(s):\n{}",
            failed.len(),
            failed.join("\n")
        );
    }
}

/// Helper to extract and compile all ````frameassembly` and ````frasm` blocks in a file.
fn verify_fasm_blocks_in_file(path: &Path) -> Result<usize, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let is_rs = path.extension().and_then(|s| s.to_str()) == Some("rs");
    let mut in_block = false;
    let mut current_block = String::new();
    let mut block_start_line = 0usize;
    let mut compiled = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let stripped = if is_rs {
            line.trim_start()
                .strip_prefix("//! ")
                .or_else(|| line.trim_start().strip_prefix("//!"))
                .or_else(|| line.trim_start().strip_prefix("/// "))
                .or_else(|| line.trim_start().strip_prefix("///"))
                .unwrap_or(line)
        } else {
            line
        };
        let trimmed = stripped.trim();

        if !in_block && (trimmed.starts_with("```frameassembly") || trimmed.starts_with("```frasm")) {
            in_block = true;
            current_block.clear();
            block_start_line = idx + 1;
        } else if in_block && trimmed.starts_with("```") {
            in_block = false;
            let snippet = current_block.trim();
            let snippet_lower = snippet.to_ascii_lowercase();
            if snippet_lower.contains("host ") && snippet_lower.contains("compile") {
                let prog = parse_program(snippet)
                    .map_err(|e| format!("{}:{}: Fenced .frasm block failed to parse: {:?}", path.display(), block_start_line, e))?;
                validate_semantics(&prog, snippet)
                    .map_err(|e| format!("{}:{}: Fenced .frasm block failed semantic validation: {:?}", path.display(), block_start_line, e))?;
                compile_program(&prog)
                    .map_err(|e| format!("{}:{}: Fenced .frasm block failed wire compilation: {}", path.display(), block_start_line, e))?;
                compiled += 1;
            }
        } else if in_block {
            current_block.push_str(stripped);
            current_block.push('\n');
        }
    }

    Ok(compiled)
}

/// Gate 3: Verifies that every ````frameassembly` and ````frasm` code block in Markdown docs,
/// READMEs, `llms.txt`, `llms-full.txt`, skills, and Rust docstrings compiles with zero errors.
#[test]
fn test_gate3_all_markdown_and_rustdoc_fasm_blocks_compile() {
    let mut files_to_check = vec![
        PathBuf::from("README.md"),
        PathBuf::from("frameassembly-wasm/README.md"),
        PathBuf::from("frameassembly-vscode/README.md"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
        PathBuf::from(".github/copilot-instructions.md"),
        PathBuf::from("llms.txt"),
        PathBuf::from("llms-full.txt"),
    ];
    collect_files_with_ext(Path::new("docs"), "md", &mut files_to_check);
    collect_files_with_ext(Path::new("contrib"), "md", &mut files_to_check);
    collect_files_with_ext(Path::new("src"), "rs", &mut files_to_check);
    collect_files_with_ext(Path::new("frameassembly-wasm/src"), "rs", &mut files_to_check);
    collect_files_with_ext(Path::new(".agents/skills"), "md", &mut files_to_check);

    let mut total_compiled_blocks = 0usize;
    let mut errors = Vec::new();
    for path in &files_to_check {
        match verify_fasm_blocks_in_file(path) {
            Ok(n) => total_compiled_blocks += n,
            Err(e) => errors.push(e),
        }
    }

    assert!(
        errors.is_empty(),
        "Fenced .frasm code block compilation errors:\n{}",
        errors.join("\n")
    );
    assert!(
        total_compiled_blocks >= 70,
        "Expected at least 70 compilable .frasm blocks across docs/skills/src, found {}",
        total_compiled_blocks
    );
}

/// Verifies that every RHS non-terminal referenced in `grammar.ebnf` is defined on the LHS.
fn verify_ebnf_non_terminal_resolution(ebnf: &str) {
    let chars: Vec<char> = ebnf.chars().collect();
    let mut no_comments = String::with_capacity(ebnf.len());
    let mut idx = 0;
    let mut in_comment = false;
    while idx < chars.len() {
        if !in_comment && idx + 1 < chars.len() && chars[idx] == '(' && chars[idx + 1] == '*' {
            in_comment = true;
            idx += 2;
        } else if in_comment && idx + 1 < chars.len() && chars[idx] == '*' && chars[idx + 1] == ')' {
            in_comment = false;
            idx += 2;
        } else if !in_comment {
            no_comments.push(chars[idx]);
            idx += 1;
        } else {
            idx += 1;
        }
    }

    let mut stmts = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    let mut in_q = false;
    for ch in no_comments.chars() {
        if ch == '"' && !in_sq && !in_q {
            in_dq = !in_dq;
            cur.push(ch);
        } else if ch == '\'' && !in_dq && !in_q {
            in_sq = !in_sq;
            cur.push(ch);
        } else if ch == '?' && !in_dq && !in_sq {
            in_q = !in_q;
            cur.push(ch);
        } else if ch == ';' && !in_dq && !in_sq && !in_q {
            stmts.push(cur.clone());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }

    let mut defined_lhs = HashSet::new();
    let mut rhs_non_terminals = Vec::new();
    for stmt in &stmts {
        if let Some((lhs, rhs)) = stmt.split_once('=') {
            let lhs_name = lhs.trim();
            if !lhs_name.is_empty() {
                defined_lhs.insert(lhs_name.to_string());
            }
            let mut r_dq = false;
            let mut r_sq = false;
            let mut r_q = false;
            let mut cleaned = String::new();
            for ch in rhs.chars() {
                if ch == '"' && !r_sq && !r_q {
                    r_dq = !r_dq;
                    cleaned.push(' ');
                } else if ch == '\'' && !r_dq && !r_q {
                    r_sq = !r_sq;
                    cleaned.push(' ');
                } else if ch == '?' && !r_dq && !r_sq {
                    r_q = !r_q;
                    cleaned.push(' ');
                } else if !r_dq && !r_sq && !r_q {
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        cleaned.push(ch);
                    } else {
                        cleaned.push(' ');
                    }
                }
            }
            for word in cleaned.split_whitespace() {
                if word.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                    rhs_non_terminals.push(word.to_string());
                }
            }
        }
    }

    assert!(defined_lhs.contains("program"), "grammar.ebnf must define 'program' entrypoint");
    for referenced in &rhs_non_terminals {
        assert!(defined_lhs.contains(referenced), "Undefined EBNF non-terminal '{referenced}' in grammar.ebnf");
    }
}

/// Verifies that every RHS non-terminal referenced in `frameassembly.gbnf` is defined on the LHS.
fn verify_gbnf_non_terminal_resolution(gbnf: &str) {
    let mut defined_lhs = HashSet::new();
    let mut rhs_non_terminals = Vec::new();
    for line in gbnf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let rhs = if let Some((lhs, rhs_part)) = trimmed.split_once("::=") {
            defined_lhs.insert(lhs.trim().to_string());
            rhs_part
        } else {
            trimmed
        };
        let (mut in_quotes, mut in_brackets, mut escaped) = (false, false, false);
        let mut cleaned = String::new();
        for ch in rhs.chars() {
            if escaped {
                escaped = false;
                cleaned.push(' ');
            } else if ch == '\\' && (in_quotes || in_brackets) {
                escaped = true;
                cleaned.push(' ');
            } else if ch == '"' && !in_brackets {
                in_quotes = !in_quotes;
                cleaned.push(' ');
            } else if !in_quotes && ch == '[' {
                in_brackets = true;
                cleaned.push(' ');
            } else if !in_quotes && ch == ']' {
                in_brackets = false;
                cleaned.push(' ');
            } else if !in_quotes && !in_brackets && (ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
                cleaned.push(ch);
            } else {
                cleaned.push(' ');
            }
        }
        for word in cleaned.split_whitespace() {
            if word.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                rhs_non_terminals.push(word.to_string());
            }
        }
    }
    assert!(defined_lhs.contains("root"), "frameassembly.gbnf must define 'root' entrypoint");
    for referenced in &rhs_non_terminals {
        assert!(defined_lhs.contains(referenced), "Undefined GBNF non-terminal '{referenced}' in frameassembly.gbnf");
    }
}

/// Gate 4: Verifies 6-way grammar and parser lockstep across `src/lexer/mod.rs`, `src/parser/`,
/// `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly.tmLanguage.json`,
/// plus automated RHS non-terminal resolution in `grammar.ebnf` and `frameassembly.gbnf`.
#[test]
fn test_gate4_constrained_decoding_grammar_lockstep() {
    let keywords = extract_lexer_lowercase_keywords();
    assert!(
        keywords.len() >= 640,
        "Expected at least 640 strict-lowercase lexer tokens, found {}",
        keywords.len()
    );

    let ebnf = fs::read_to_string("grammar.ebnf").expect("Missing grammar.ebnf");
    let gbnf = fs::read_to_string("frameassembly.gbnf").expect("Missing frameassembly.gbnf");
    let lark = fs::read_to_string("frameassembly.lark").expect("Missing frameassembly.lark");
    let tm_json = fs::read_to_string("frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json")
        .expect("Missing frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json");

    for (g_name, g_src) in [
        ("grammar.ebnf", &ebnf),
        ("frameassembly.gbnf", &gbnf),
        ("frameassembly.lark", &lark),
    ] {
        assert!(
            !g_src.contains("\"loop\"") && !g_src.contains("\"LOOP\""),
            "{} must not contain removed loop keyword",
            g_name
        );
    }
    assert!(
        lark.contains("str_or_ident:") && lark.contains("contextual_keyword"),
        "frameassembly.lark str_or_ident must union contextual_keyword so unquoted values parse cleanly"
    );

    let mut parser_files = Vec::new();
    collect_files_with_ext(Path::new("src/parser"), "rs", &mut parser_files);
    let mut all_parser_src = String::new();
    for pf in &parser_files {
        all_parser_src.push_str(&fs::read_to_string(pf).expect("Failed to read parser file"));
        all_parser_src.push('\n');
    }

    let mut missing = Vec::new();
    for variant in extract_lexer_token_variants() {
        let pat = format!("Token::{}", variant);
        if !all_parser_src.contains(&pat) {
            missing.push(format!("src/parser/ missing wiring for {}", pat));
        }
    }

    for kw in &keywords {
        let quoted = format!("\"{}\"", kw);
        if !ebnf.contains(&quoted) {
            missing.push(format!("grammar.ebnf missing {}", quoted));
        }
        if !gbnf.contains(&quoted) {
            missing.push(format!("frameassembly.gbnf missing {}", quoted));
        }
        if !lark.contains(&quoted) {
            missing.push(format!("frameassembly.lark missing {}", quoted));
        }
        if !tm_json.contains(kw.as_str()) {
            missing.push(format!("frameassembly.tmLanguage.json missing {}", kw));
        }
    }

    assert!(
        missing.is_empty(),
        "Six-way grammar & parser lockstep violations:\n{}",
        missing.join("\n")
    );

    verify_ebnf_non_terminal_resolution(&ebnf);
    verify_gbnf_non_terminal_resolution(&gbnf);
}

/// Canonical `docs/*.md` inventory (human guides first, then `13_for_nerds.md`), shared by Gate 5
/// (orphan check) and Gate 7 (`llms-full.txt` bundle order).
const CANONICAL_DOCS: [&str; 14] = [
    "README.md",
    "01_getting_started.md",
    "02_use_cases.md",
    "03_l2_protocols.md",
    "04_l3_protocols.md",
    "05_l4_transports.md",
    "06_l7_snmp.md",
    "07_l7_infra_and_telemetry.md",
    "08_l7_web_and_cloud.md",
    "09_l7_mail_auth_storage_db.md",
    "10_l7_industrial_ot.md",
    "11_topologies_and_dual_stack.md",
    "12_frasm_specification.md",
    "13_for_nerds.md",
];

/// Gate 5: Verifies `< 50 KB` size limits on Rust sources, `//!` module docstrings (`>= 50` words),
/// zero `0x00` NUL bytes across `src/**/*.rs`, `tests/*.rs`, `docs/*.md`, and `README.md`,
/// and canonical `docs/*.md` inventory without orphans (Markdown has no size cap).
#[test]
fn test_gate5_markdown_fasm_blocks_and_file_sizes() {
    let expected_docs: HashSet<&str> = CANONICAL_DOCS.into_iter().collect();

    let mut doc_files = Vec::new();
    collect_files_with_ext(Path::new("docs"), "md", &mut doc_files);
    assert_eq!(
        doc_files.len(),
        CANONICAL_DOCS.len(),
        "docs/ must contain exactly the canonical .md guides, found: {:?}",
        doc_files
    );

    for doc_path in &doc_files {
        let name = doc_path.file_name().unwrap().to_str().unwrap();
        assert!(
            expected_docs.contains(name),
            "Unexpected orphan doc file in docs/: {}",
            doc_path.display()
        );
        let bytes = fs::read(doc_path).unwrap();
        assert!(
            !bytes.contains(&0),
            "NUL byte found in {}",
            doc_path.display()
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.split_whitespace().count() >= 50,
            "{} has fewer than 50 words",
            doc_path.display()
        );
        if name != "13_for_nerds.md" {
            for tag in ["// PROMPT:", "// TOKENS:", "// INSTRUCTION:"] {
                assert!(
                    !text.contains(tag),
                    "Human-facing {} must not contain {}",
                    doc_path.display(),
                    tag
                );
            }
        }
    }

    let readme_str = fs::read_to_string("README.md").unwrap();
    for tag in ["// PROMPT:", "// TOKENS:", "// INSTRUCTION:"] {
        assert!(
            !readme_str.contains(tag),
            "Human-facing README.md must not contain {}",
            tag
        );
    }

    let mut rs_files = Vec::new();
    collect_files_with_ext(Path::new("src"), "rs", &mut rs_files);
    collect_files_with_ext(Path::new("frameassembly-wasm/src"), "rs", &mut rs_files);
    collect_files_with_ext(Path::new("tests"), "rs", &mut rs_files);
    for rs_path in &rs_files {
        let bytes = fs::read(rs_path).unwrap();
        assert!(
            !bytes.contains(&0),
            "NUL byte found in {}",
            rs_path.display()
        );
        assert!(
            bytes.len() < 50_000,
            "{} exceeds 50,000-byte limit ({} bytes)",
            rs_path.display(),
            bytes.len()
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.trim_start().starts_with("//!"),
            "{} must start with a //! module docstring",
            rs_path.display()
        );
        let doc_words: usize = text
            .lines()
            .filter(|l| l.trim_start().starts_with("//!"))
            .map(|l| l.split_whitespace().count())
            .sum();
        assert!(
            doc_words >= 50,
            "{} //! module docstring has only {} words (must be >= 50)",
            rs_path.display(),
            doc_words
        );
    }

    for root_file in [
        "README.md",
        "install.sh",
        "AGENTS.md",
        "CLAUDE.md",
        ".github/copilot-instructions.md",
        "llms.txt",
        "llms-full.txt",
        "grammar.ebnf",
        "frameassembly.gbnf",
        "frameassembly.lark",
        "context7.json",
        "codemeta.json",
        "CITATION.cff",
    ] {
        let bytes = fs::read(root_file).unwrap_or_else(|_| panic!("Missing {}", root_file));
        assert!(!bytes.contains(&0), "NUL byte found in {}", root_file);
    }
}

/// Gate 6: Verifies that every public field declared on every AST `*Spec` struct (plus
/// `TcpOptions` and `SctpParams`) in `src/ast/{l2,l3,l4,l7}/*.rs` is wired into and referenced
/// by the corresponding protocol builder, `src/packet.rs`, or `src/backend/`.
#[test]
fn test_gate6_ast_spec_fields_wired_to_builders() {
    let mut ast_files = Vec::new();
    for layer in ["l2", "l3", "l4", "l7"] {
        collect_files_with_ext(&Path::new("src/ast").join(layer), "rs", &mut ast_files);
    }
    ast_files.sort();

    let mut total_structs = 0usize;
    let mut total_fields = 0usize;
    let mut unwired_fields = Vec::new();

    for ast_path in &ast_files {
        let Some(file_stem) = ast_path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if file_stem == "mod" {
            continue;
        }
        let layer = ast_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .expect("AST file must reside under src/ast/<layer>/");

        let mut target_paths = vec![
            PathBuf::from("src/backend/mod.rs"),
            PathBuf::from("src/backend/l7_dispatch.rs"),
        ];
        if file_stem == "snmp" {
            collect_files_with_ext(Path::new("src/builders/l7/snmp"), "rs", &mut target_paths);
        } else if file_stem == "ipsec" {
            target_paths.push(PathBuf::from("src/builders/l3/ipsec.rs"));
            target_paths.push(PathBuf::from("src/builders/l3/esp.rs"));
            target_paths.push(PathBuf::from("src/builders/l3/ah.rs"));
        } else if file_stem == "tcp" || file_stem == "sctp" {
            target_paths.push(PathBuf::from(format!("src/builders/{}/{}.rs", layer, file_stem)));
            target_paths.push(PathBuf::from("src/packet.rs"));
        } else {
            target_paths.push(PathBuf::from(format!("src/builders/{}/{}.rs", layer, file_stem)));
        }

        let mut builder_source = String::new();
        for tp in &target_paths {
            if let Ok(src) = fs::read_to_string(tp) {
                builder_source.push_str(&src);
                builder_source.push('\n');
            }
        }

        let ast_src = fs::read_to_string(ast_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", ast_path.display(), e));
        let mut current_struct: Option<String> = None;

        for line in ast_src.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("pub struct ") {
                let name = rest
                    .split(['{', '<', '('])
                    .next()
                    .unwrap_or("")
                    .trim();
                if name.ends_with("Spec") || name == "TcpOptions" || name == "SctpParams" {
                    current_struct = Some(name.to_string());
                    total_structs += 1;
                } else {
                    current_struct = None;
                }
            } else if current_struct.is_some() && trimmed.starts_with('}') {
                current_struct = None;
            } else if let Some(struct_name) = &current_struct
                && let Some(rest) = trimmed.strip_prefix("pub ")
                && let Some((field_name, _)) = rest.split_once(':')
            {
                let field_name = field_name.trim();
                if field_name != "_marker" {
                    total_fields += 1;
                    let dot_access = format!(".{}", field_name);
                    if !builder_source.contains(&dot_access) && !builder_source.contains(field_name)
                    {
                        unwired_fields.push(format!(
                            "{}::{}::{}",
                            ast_path.display(),
                            struct_name,
                            field_name
                        ));
                    }
                }
            }
        }
    }

    assert!(
        total_structs >= 75 && total_fields >= 500,
        "Expected at least 75 AST Spec structs and 500 fields, found {} structs and {} fields",
        total_structs,
        total_fields
    );
    assert!(
        unwired_fields.is_empty(),
        "Unwired AST Spec fields not referenced in wire builders:\n{}",
        unwired_fields.join("\n")
    );
}

/// Verifies 1:1 per-protocol dissector file symmetry in `src/reverse/{l2,l3,l4,l7}/` and ensures
/// zero orphaned `src/reverse/dissect_*.rs` or legacy `src/reverse/l7/snmp.rs` files exist.
#[test]
fn test_reverse_decompiler_per_protocol_file_symmetry() {
    assert!(
        !Path::new("src/reverse/l7/snmp.rs").exists(),
        "Legacy monolithic src/reverse/l7/snmp.rs must not exist; use snmp1.rs, snmp2.rs, snmp3.rs"
    );

    let mut all_reverse_rs = Vec::new();
    collect_files_with_ext(Path::new("src/reverse"), "rs", &mut all_reverse_rs);
    for path in &all_reverse_rs {
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            !fname.starts_with("dissect_"),
            "Orphaned legacy dissector file found: {}",
            path.display()
        );
    }

    let l3_extra = ["ip", "ipv6", "icmpv6"];
    let l7_snmp = ["snmp1", "snmp2", "snmp3"];
    let layer_specs: [(&str, &[&str], &[&str]); 4] = [
        ("src/reverse/l2", &EXPECTED_L2, &[]),
        ("src/reverse/l3", &EXPECTED_L3, &l3_extra),
        ("src/reverse/l4", &EXPECTED_L4, &[]),
        ("src/reverse/l7", &EXPECTED_L7_NON_SNMP, &l7_snmp),
    ];

    for (dir_str, protos, extras) in layer_specs {
        let dir = Path::new(dir_str);
        assert!(dir.exists() && dir.is_dir(), "Missing reverse layer dir: {}", dir_str);
        let mut expected: HashSet<String> = HashSet::from(["mod.rs".to_string()]);
        for p in protos.iter().chain(extras.iter()) {
            expected.insert(format!("{}.rs", p));
        }

        let mut actual: HashSet<String> = HashSet::new();
        for entry in fs::read_dir(dir).expect("Failed to read reverse layer dir").flatten() {
            let p = entry.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rs") {
                actual.insert(p.file_name().unwrap().to_str().unwrap().to_string());
            }
        }
        assert_eq!(
            actual, expected,
            "1:1 file symmetry mismatch in {}",
            dir_str
        );
    }
}

/// Gate 7: Verifies v3.0.0 release packaging hygiene (no stray `output.pcap` or legacy `.vsix`
/// files), verifies `frameassembly-vscode/frameassembly-vscode-3.0.0.vsix` bundles the WASM-powered
/// Packet Studio assets without overwriting it, checks `llms.txt` (`< 512` lines, `< 25 KB`),
/// and verifies the prompt-injection context in `llms-full.txt` (`60–250 KB`, zero NULs, all
/// v3.0.0 markers/docs/grammars, and zero contributor-internal leaks).
#[test]
fn test_gate7_release_packaging_and_llms_bundle_sync() {
    for stray in [
        "output.pcap",
        "frameassembly-vscode/vsc-extension-quickstart.md",
        "frameassembly-vscode/frameassembly-vscode-1.2.1.vsix",
        "frameassembly-vscode/frameassembly-vscode-1.2.2.vsix",
        "frameassembly-vscode/frameassembly-vscode-1.4.5.vsix",
        "frameassembly-vscode/frameassembly-vscode-1.4.6.vsix",
        "frameassembly-vscode/frameassembly-vscode-1.5.0.vsix",
        "frameassembly-vscode/frameassembly-vscode-1.5.1.vsix",
        "frameassembly-vscode/frameassembly-vscode-2.0.0.vsix",
    ] {
        assert!(
            !Path::new(stray).exists(),
            "Stray or legacy artifact {} must not exist in v3.0.0",
            stray
        );
    }

    let vsix_v2 = Path::new("frameassembly-vscode/frameassembly-vscode-3.0.0.vsix");
    assert!(
        vsix_v2.exists(),
        "Bundled frameassembly-vscode/frameassembly-vscode-3.0.0.vsix must exist"
    );
    let py_check_vsix = r#"
import zipfile
with zipfile.ZipFile("frameassembly-vscode/frameassembly-vscode-3.0.0.vsix", "r") as zf:
    names = set(zf.namelist())
for req in [
    "extension/package.json",
    "extension/extension.js",
    "extension/protocol_schema.json",
    "extension/wasm/frameassembly_wasm_bg.wasm",
    "extension/readme.md",
    "extension/icon.png",
]:
    assert req in names, f"Missing {req} in frameassembly-vscode-3.0.0.vsix"
"#;
    let status = std::process::Command::new("python3")
        .arg("-c")
        .arg(py_check_vsix)
        .status()
        .expect("Failed to execute python3 for read-only VSIX verification");
    assert!(status.success(), "Read-only VSIX v3.0.0 inspection failed");

    let llms_txt = fs::read_to_string("llms.txt").expect("Missing llms.txt");
    let llms_lines = llms_txt.lines().count();
    assert!(
        llms_lines < 512 && llms_txt.len() < 25_000 && llms_txt.contains("3.0.0"),
        "llms.txt must be < 512 lines, < 25,000 bytes, and reference 3.0.0 (got {} lines, {} bytes)",
        llms_lines,
        llms_txt.len()
    );

    // Read-only verification of `llms-full.txt` (generated as a clean prompt-injection context).
    let full_bytes = fs::read("llms-full.txt").expect("Missing llms-full.txt");
    assert!(
        !full_bytes.contains(&0),
        "llms-full.txt must contain zero 0x00 NUL bytes"
    );
    assert!(
        (60_000..250_000).contains(&full_bytes.len()),
        "llms-full.txt must remain prompt-window friendly between 60 KB and 250 KB (got {} bytes)",
        full_bytes.len()
    );
    let full_txt = String::from_utf8(full_bytes).expect("llms-full.txt must be valid UTF-8");
    assert!(
        full_txt.contains("frameassembly demo.frasm") || full_txt.contains("frameassembly test.frasm"),
        "llms-full.txt missing default root CLI invocation (`frameassembly <input.frasm>`)"
    );
    for required_marker in [
        "3.0.0",
        "frameassembly show",
        "frameassembly reverse",
        "README.md",
        "grammar.ebnf",
        "frameassembly.gbnf",
        "frameassembly.lark",
    ] {
        assert!(
            full_txt.contains(required_marker),
            "llms-full.txt missing required v3.0.0 marker `{required_marker}`"
        );
    }
    for doc_name in CANONICAL_DOCS {
        assert!(
            full_txt.contains(doc_name),
            "llms-full.txt missing canonical doc reference `{doc_name}`"
        );
    }
    for leaked_internal in ["file_lock.sh", "PreToolUse", "// PROMPT:"] {
        assert!(
            !full_txt.contains(leaked_internal),
            "llms-full.txt must not leak contributor/training internals (`{leaked_internal}`)"
        );
    }
    assert!(
        !full_txt.contains("\n  LOOP ") && !full_txt.contains("\nLOOP "),
        "llms-full.txt must not contain legacy v1 LOOP blocks"
    );
}
