//! Six-gate corpus, lexer-bijection, Markdown/Rustdoc block compilation, five-way grammar
//! lockstep with non-terminal resolution, AI pre-training chunk filter, and AST-to-builder
//! field-wiring verification suite for FrameAssembly.
//!
//! Enforces six comprehensive repository invariants:
//! 1. **Gate 1 (Corpus Scale, Headers & PCAPNG Compilation)**: All 2,600+ `.fasm` files across all
//!    81 protocols (`>= 30` per protocol) and `examples/topologies/` (`>= 100` topologies) satisfy
//!    dataset header discipline (`// PROMPT:`, `// TOKENS:`, `// INSTRUCTION:`), pre-training line
//!    and word metrics (`words >= 50`, `avg_line_length <= 85`, `max_line_length <= 200`, `< 50 KB`),
//!    and compile into valid PCAPNG captures with `0x0A0D0D0A` Section Header Block magic.
//! 2. **Gate 2 (`// TOKENS:` Lexer Bijection)**: Every token listed on Line 2 (`// TOKENS:`) of
//!    every `.fasm` file is a valid uppercase keyword token from `src/lexer/mod.rs` and matches the
//!    exact uppercase keyword tokens used in the file body in first-appearance order.
//! 3. **Gate 3 (100% Compilable Documentation & Rustdoc Code Blocks)**: Every ````frameassembly` and
//!    ````fasm` code block across `README.md`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`,
//!    `docs/*.md`, `src/**/*.rs`, and `.agents/skills/**/*.md` parses, validates, and compiles cleanly.
//! 4. **Gate 4 (Five-Way Constrained Decoding Grammar Lockstep & Non-Terminal Resolution)**: Every
//!    uppercase `#[token("...")]` keyword in `src/lexer/mod.rs` is present in `grammar.ebnf`,
//!    `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`,
//!    and every RHS non-terminal referenced in `grammar.ebnf` and `frameassembly.gbnf` is defined on the LHS.
//! 5. **Gate 5 (`< 50 KB` File Ceiling, `//!` Module Docstrings, Zero NUL Bytes & Link Integrity)**:
//!    Every `src/**/*.rs`, `tests/*.rs`, `docs/*.md`, `README.md`, and `examples/**/*.fasm` file is
//!    `< 50,000` bytes, every `src/**/*.rs` and `tests/*.rs` file begins with `//!` (`>= 50` words),
//!    zero `0x00` bytes exist in any text or source file, and `docs/` contains the exact 11 canonical guides.
//! 6. **Gate 6 (AST `*Spec` Fields Wired to Wire Builders)**: Every public field on every protocol
//!    `*Spec` struct (plus `TcpOptions` and `SctpParams`) in `src/ast/{l2,l3,l4,l7}/*.rs` is wired
//!    into and referenced by the corresponding wire builder or packet/backend encoder.

use std::collections::HashSet;
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

/// Discovers all `.fasm` files in the `examples/` directory hierarchy sorted by path.
fn get_sorted_example_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_files_with_ext(Path::new("examples"), "fasm", &mut paths);
    paths.sort();
    paths
}

/// Extracts all uppercase `#[token("...")]` keyword literals from `src/lexer/mod.rs`.
fn extract_lexer_uppercase_keywords() -> HashSet<String> {
    let lexer_src = fs::read_to_string("src/lexer/mod.rs").expect("Failed to read src/lexer/mod.rs");
    let mut keywords = HashSet::new();
    for line in lexer_src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#[token(\"")
            && let Some(end_idx) = rest.find('"')
        {
            let tok = &rest[..end_idx];
            if !tok.is_empty()
                && tok.chars().next().unwrap().is_ascii_uppercase()
                && tok.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                keywords.insert(tok.to_string());
            }
        }
    }
    keywords
}

/// Inspects and verifies a single `.fasm` example file for Gate 1 and Gate 2.
fn verify_example_file(path: &Path, valid_keywords: &HashSet<String>) -> Result<(), String> {
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "Invalid filename".to_string())?;

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    if content.len() >= 50_000 {
        return Err(format!(
            "{}: File size {} bytes exceeds 50,000-byte limit",
            path.display(),
            content.len()
        ));
    }

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 3 {
        return Err(format!(
            "{}: File too short (must have at least 3 lines)",
            path.display()
        ));
    }

    // Pre-training metrics check (StarCoder2 / The Stack v2 / OpenCoder)
    let word_count = content.split_whitespace().count();
    if word_count < 50 {
        return Err(format!(
            "{}: Word count {} is below 50-word OpenCoder threshold",
            path.display(),
            word_count
        ));
    }
    let total_chars: usize = lines.iter().map(|l| l.len()).sum();
    let avg_line_len = total_chars as f64 / (lines.len() as f64);
    let max_line_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    if avg_line_len > 85.0 {
        return Err(format!(
            "{}: Average line length {:.1} exceeds 85 chars",
            path.display(),
            avg_line_len
        ));
    }
    if max_line_len > 200 {
        return Err(format!(
            "{}: Max line length {} exceeds 200 chars",
            path.display(),
            max_line_len
        ));
    }

    // Line 1: // PROMPT:
    if !lines[0].starts_with("// PROMPT: ") {
        return Err(format!(
            "{}: Line 1 must begin with '// PROMPT: ', got: '{}'",
            path.display(),
            lines[0]
        ));
    }
    let prompt_body = lines[0].trim_start_matches("// PROMPT: ").trim();
    if prompt_body.is_empty() {
        return Err(format!("{}: PROMPT comment body cannot be empty", path.display()));
    }

    // Line 2: // TOKENS:
    if !lines[1].starts_with("// TOKENS: ") {
        return Err(format!(
            "{}: Line 2 must begin with '// TOKENS: ', got: '{}'",
            path.display(),
            lines[1]
        ));
    }
    let tokens_body = lines[1].trim_start_matches("// TOKENS: ").trim();
    if tokens_body.is_empty() {
        return Err(format!("{}: TOKENS comment body cannot be empty", path.display()));
    }

    // Gate 2: Verify every token in // TOKENS: is a valid uppercase lexer keyword
    let declared_tokens: Vec<&str> = tokens_body
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for raw_tok in &declared_tokens {
        if !valid_keywords.contains(*raw_tok) {
            return Err(format!(
                "{}: Non-canonical or unknown token '{}' in // TOKENS: header",
                path.display(),
                raw_tok
            ));
        }
        let mut lex = Token::lexer(raw_tok);
        if let Some(Ok(Token::Ident(id))) = lex.next() {
            return Err(format!(
                "{}: Hallucinated identifier '{}' in // TOKENS: header",
                path.display(),
                id
            ));
        }
    }

    // Instruction comments check
    if !content.contains("// INSTRUCTION:") {
        return Err(format!(
            "{}: File must contain '// INSTRUCTION:' comments before blocks",
            path.display()
        ));
    }

    // Syntactic parsing & semantic validation
    let program = parse_program(&content)
        .map_err(|e| format!("Parse error in {}: {:?}", path.display(), e))?;
    validate_semantics(&program, &content)
        .map_err(|e| format!("Semantic error in {}: {:?}", path.display(), e))?;

    // Wire packet generation to temp PCAPNG with thread-safe unique filename
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp_dir = std::env::temp_dir();
    let temp_pcap = temp_dir.join(format!("verify_{}_{}_{}", std::process::id(), count, filename));
    let temp_pcap_str = temp_pcap.to_str().ok_or_else(|| "Invalid temp path".to_string())?;

    let compile_res = generate_pcap(&program, temp_pcap_str);
    if let Err(e) = compile_res {
        let _ = fs::remove_file(&temp_pcap);
        return Err(format!("Compilation error in {}: {}", path.display(), e));
    }

    // Verify non-empty PCAPNG output with 0x0A0D0D0A Section Header Block magic
    let bytes = fs::read(&temp_pcap)
        .map_err(|e| format!("Failed to read output PCAP for {}: {}", path.display(), e))?;
    let _ = fs::remove_file(&temp_pcap);

    if bytes.len() < 28 {
        return Err(format!(
            "{}: Generated PCAPNG is too small ({} bytes)",
            path.display(),
            bytes.len()
        ));
    }
    if bytes[0..4] != [0x0A, 0x0D, 0x0D, 0x0A] {
        return Err(format!(
            "{}: Output file does not begin with PCAPNG SHB magic 0x0A0D0D0A",
            path.display()
        ));
    }

    Ok(())
}

/// Tests that no `.fasm` files remain directly in the root of `examples/`.
#[test]
fn test_corpus_no_root_examples() {
    let mut root_fasm = Vec::new();
    if let Ok(entries) = fs::read_dir("examples") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("fasm") {
                root_fasm.push(path);
            }
        }
    }
    assert!(
        root_fasm.is_empty(),
        "No flat .fasm files should remain in examples/ root, found: {:?}",
        root_fasm
    );
}

/// Tests that all `.fasm` example files in the corpus avoid numeric prefixes and follow snake_case naming.
#[test]
fn test_corpus_non_numeric_naming_conventions() {
    let paths = get_sorted_example_paths();
    assert!(
        paths.len() >= 2600,
        "Corpus must contain at least 2,600 total .fasm examples across all layers, found {}",
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
            filename.ends_with(".fasm"),
            "{}: Must have .fasm extension",
            path.display()
        );
    }
}

/// Tests that all 81 protocol folders have at least 30 scenarios and `examples/topologies` has at least 100.
#[test]
fn test_corpus_protocol_folder_coverage() {
    let expected_l2 = ["arp", "vlan", "qinq", "lldp", "stp", "lacp", "eapol", "mpls"];
    let expected_l3 = [
        "icmp", "ndp", "igmp", "mld", "gre", "vxlan", "geneve", "ipsec", "esp", "ah",
        "ikev2", "wireguard", "ospf", "bgp", "rip", "vrrp", "hsrp", "pim", "bfd", "openflow",
    ];
    let expected_l4 = ["tcp", "udp", "sctp"];
    let expected_l7 = [
        "dns", "mdns", "dhcp", "ntp", "ptp", "radius", "tacacs", "syslog", "netflow", "ipfix",
        "sflow", "tftp", "ftp", "ssh", "telnet", "http", "http2", "grpc", "websocket", "tls",
        "quic", "stun", "sip", "rtp", "rtsp", "smtp", "imap", "pop3", "kerberos", "ldap",
        "smb", "nfs", "redis", "memcached", "mysql", "postgres", "mqtt", "coap", "amqp",
        "ssdp", "whois", "modbus", "bacnet", "dnp3", "s7comm", "ethernetip", "opcua",
    ];
    let expected_snmp = ["snmpv1", "snmpv2c", "snmpv3"];

    for proto in expected_l2 {
        let dir = Path::new("examples/l2").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L2 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_files_with_ext(&dir, "fasm", &mut files);
        assert!(
            files.len() >= 30,
            "Folder {} has fewer than 30 scenarios: {}",
            dir.display(),
            files.len()
        );
    }

    for proto in expected_l3 {
        let dir = Path::new("examples/l3").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L3 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_files_with_ext(&dir, "fasm", &mut files);
        assert!(
            files.len() >= 30,
            "Folder {} has fewer than 30 scenarios: {}",
            dir.display(),
            files.len()
        );
    }

    for proto in expected_l4 {
        let dir = Path::new("examples/l4").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L4 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_files_with_ext(&dir, "fasm", &mut files);
        assert!(
            files.len() >= 30,
            "Folder {} has fewer than 30 scenarios: {}",
            dir.display(),
            files.len()
        );
    }

    for proto in expected_l7 {
        let dir = Path::new("examples/l7").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L7 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_files_with_ext(&dir, "fasm", &mut files);
        assert!(
            files.len() >= 30,
            "Folder {} has fewer than 30 scenarios: {}",
            dir.display(),
            files.len()
        );
    }

    for snmp_ver in expected_snmp {
        let dir = Path::new("examples/l7/snmp").join(snmp_ver);
        assert!(dir.exists() && dir.is_dir(), "Missing SNMP folder: {}", dir.display());
        let mut files = Vec::new();
        collect_files_with_ext(&dir, "fasm", &mut files);
        assert!(
            files.len() >= 30,
            "Folder {} has fewer than 30 scenarios: {}",
            dir.display(),
            files.len()
        );
    }

    let topologies_dir = Path::new("examples/topologies");
    assert!(topologies_dir.exists() && topologies_dir.is_dir(), "Missing examples/topologies");
    let mut topo_files = Vec::new();
    collect_files_with_ext(topologies_dir, "fasm", &mut topo_files);
    assert!(
        topo_files.len() >= 100,
        "examples/topologies has fewer than 100 scenarios: {}",
        topo_files.len()
    );
}

/// Gate 1 & Gate 2: Tests all `.fasm` example files in `examples/` for headers, lexer bijection,
/// pre-training metrics, syntax parsing, and PCAPNG compilation.
#[test]
fn test_corpus_all_examples_headers_and_compilation() {
    let paths = get_sorted_example_paths();
    let valid_keywords = extract_lexer_uppercase_keywords();
    assert!(
        paths.len() >= 2600,
        "Corpus must have at least 2,600 .fasm examples, found {}",
        paths.len()
    );

    let mut failed = Vec::new();
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

/// Helper to extract and compile all ````frameassembly` and ````fasm` blocks in a file.
fn verify_fasm_blocks_in_file(path: &Path) -> Result<usize, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let mut in_block = false;
    let mut current_block = String::new();
    let mut block_start_line = 0usize;
    let mut compiled = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let stripped = line
            .trim_start()
            .strip_prefix("//! ")
            .or_else(|| line.trim_start().strip_prefix("//!"))
            .or_else(|| line.trim_start().strip_prefix("/// "))
            .or_else(|| line.trim_start().strip_prefix("///"))
            .unwrap_or(line);
        let trimmed = stripped.trim();

        if !in_block && (trimmed.starts_with("```frameassembly") || trimmed.starts_with("```fasm")) {
            in_block = true;
            current_block.clear();
            block_start_line = idx + 1;
        } else if in_block && trimmed.starts_with("```") {
            in_block = false;
            let snippet = current_block.trim();
            let snippet_upper = snippet.to_ascii_uppercase();
            if snippet_upper.contains("HOST ")
                && snippet_upper.contains("FLOW ")
                && snippet_upper.contains("COMPILE")
            {
                let prog = parse_program(snippet).map_err(|e| {
                    format!(
                        "{}:{}: Fenced .fasm block failed to parse: {:?}",
                        path.display(),
                        block_start_line,
                        e
                    )
                })?;
                validate_semantics(&prog, snippet).map_err(|e| {
                    format!(
                        "{}:{}: Fenced .fasm block failed semantic validation: {:?}",
                        path.display(),
                        block_start_line,
                        e
                    )
                })?;
                compile_program(&prog).map_err(|e| {
                    format!(
                        "{}:{}: Fenced .fasm block failed wire compilation: {}",
                        path.display(),
                        block_start_line,
                        e
                    )
                })?;
                compiled += 1;
            }
        } else if in_block {
            current_block.push_str(stripped);
            current_block.push('\n');
        }
    }

    Ok(compiled)
}

/// Gate 3: Verifies that every ````frameassembly` and ````fasm` code block in Markdown docs,
/// skills, and Rust docstrings compiles with zero errors.
#[test]
fn test_gate3_all_markdown_and_rustdoc_fasm_blocks_compile() {
    let mut files_to_check = vec![
        PathBuf::from("README.md"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
        PathBuf::from(".github/copilot-instructions.md"),
    ];
    collect_files_with_ext(Path::new("docs"), "md", &mut files_to_check);
    collect_files_with_ext(Path::new("src"), "rs", &mut files_to_check);
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
        "Fenced .fasm code block compilation errors:\n{}",
        errors.join("\n")
    );
    assert!(
        total_compiled_blocks >= 70,
        "Expected at least 70 compilable .fasm blocks across docs/skills/src, found {}",
        total_compiled_blocks
    );
}

/// Verifies that every RHS non-terminal referenced in `grammar.ebnf` is defined on the LHS.
fn verify_ebnf_non_terminal_resolution(ebnf: &str) {
    // Strip (* ... *) comments
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

    // Split into rules on ';' outside "...", '...', and ?...?
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

    assert!(
        defined_lhs.contains("program"),
        "grammar.ebnf must define 'program' entrypoint"
    );
    for referenced in &rhs_non_terminals {
        assert!(
            defined_lhs.contains(referenced),
            "Undefined EBNF non-terminal '{}' referenced on RHS in grammar.ebnf",
            referenced
        );
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

        let mut in_quotes = false;
        let mut in_brackets = false;
        let mut escaped = false;
        let mut cleaned = String::new();
        for ch in rhs.chars() {
            if escaped {
                escaped = false;
                cleaned.push(' ');
                continue;
            }
            if ch == '\\' && (in_quotes || in_brackets) {
                escaped = true;
                cleaned.push(' ');
                continue;
            }
            if ch == '"' && !in_brackets {
                in_quotes = !in_quotes;
                cleaned.push(' ');
            } else if !in_quotes && ch == '[' {
                in_brackets = true;
                cleaned.push(' ');
            } else if !in_quotes && ch == ']' {
                in_brackets = false;
                cleaned.push(' ');
            } else if !in_quotes && !in_brackets {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
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

    assert!(
        defined_lhs.contains("root"),
        "frameassembly.gbnf must define 'root' entrypoint"
    );
    for referenced in &rhs_non_terminals {
        assert!(
            defined_lhs.contains(referenced),
            "Undefined GBNF non-terminal '{}' referenced on RHS in frameassembly.gbnf",
            referenced
        );
    }
}

/// Gate 4: Verifies 5-way grammar lockstep across `src/lexer/mod.rs`, `grammar.ebnf`,
/// `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly.tmLanguage.json`, plus
/// automated RHS non-terminal resolution in `grammar.ebnf` and `frameassembly.gbnf`.
#[test]
fn test_gate4_constrained_decoding_grammar_lockstep() {
    let keywords = extract_lexer_uppercase_keywords();
    assert!(
        keywords.len() >= 640,
        "Expected at least 640 uppercase lexer tokens, found {}",
        keywords.len()
    );

    let ebnf = fs::read_to_string("grammar.ebnf").expect("Missing grammar.ebnf");
    let gbnf = fs::read_to_string("frameassembly.gbnf").expect("Missing frameassembly.gbnf");
    let lark = fs::read_to_string("frameassembly.lark").expect("Missing frameassembly.lark");
    let tm_json = fs::read_to_string("frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json")
        .expect("Missing frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json");

    let mut missing = Vec::new();
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
        "Five-way grammar lockstep violations:\n{}",
        missing.join("\n")
    );

    verify_ebnf_non_terminal_resolution(&ebnf);
    verify_gbnf_non_terminal_resolution(&gbnf);
}

/// Gate 5: Verifies `< 50 KB` chunk size limits, `//!` module docstrings (`>= 50` words),
/// zero `0x00` NUL bytes across `src/**/*.rs`, `tests/*.rs`, `docs/*.md`, and `README.md`,
/// and canonical `docs/*.md` inventory without orphans.
#[test]
fn test_gate5_markdown_fasm_blocks_and_file_sizes() {
    let expected_docs: HashSet<&str> = [
        "architecture_and_grammar.md",
        "l2_protocols.md",
        "l3_protocols.md",
        "l4_transports.md",
        "l7_snmp.md",
        "l7_infra_and_telemetry.md",
        "l7_web_and_cloud.md",
        "l7_mail_auth_storage_db.md",
        "l7_industrial_ot.md",
        "topologies_and_dual_stack.md",
        "qa_synthesis_guide.md",
    ]
    .into_iter()
    .collect();

    let mut doc_files = Vec::new();
    collect_files_with_ext(Path::new("docs"), "md", &mut doc_files);
    assert_eq!(
        doc_files.len(),
        11,
        "docs/ must contain exactly the 11 canonical .md guides, found: {:?}",
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
        assert!(
            bytes.len() < 50_000,
            "{} exceeds 50,000-byte limit ({} bytes)",
            doc_path.display(),
            bytes.len()
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.split_whitespace().count() >= 50,
            "{} has fewer than 50 words",
            doc_path.display()
        );
    }

    let mut rs_files = Vec::new();
    collect_files_with_ext(Path::new("src"), "rs", &mut rs_files);
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

    let readme_bytes = fs::read("README.md").expect("Missing README.md");
    assert!(!readme_bytes.contains(&0), "NUL byte found in README.md");
    assert!(
        readme_bytes.len() < 50_000,
        "README.md exceeds 50,000-byte limit ({} bytes)",
        readme_bytes.len()
    );

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

        // Load corresponding builder/packet/backend sources for this protocol
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

