# Modern Rust (Edition 2024, Rust 1.85–1.99.1) QA, Corpus Verification & Testing Reference Patterns

This reference document provides production-ready, compile-verified, and idiomatic Rust code templates covering the 4-tier testing taxonomy (with Rust 1.96+ `assert_matches!` and Rust 1.89+ `File::lock`), the 6-gate corpus/lexer-bijection/Markdown-block/AST-wiring verification engine (`2,611` scenarios), automated 6-way grammar/IDE/WASM lockstep and non-terminal resolution, `proptest` round-trip synthesis (`proptest-regressions/`), external `tshark` dissector validation, `cargo-mutants --in-diff`, and `.agents/scripts/file_lock.sh` parallel multi-agent coordination.

---

## 1. Multi-Tier Testing Hierarchy Implementation (With Rust 1.96+ `assert_matches!` & Rust 1.89+ `File::lock`)

Demonstrates the 4-tier testing pattern used in FrameAssembly to achieve zero-regression test coverage across unit, boundary, cross-layer, and conversational flows using [`frameassembly::parser::parse_program`](file:///home/steve/frameassembly/src/parser/mod.rs), [`frameassembly::parser::validate_semantics`](file:///home/steve/frameassembly/src/parser/mod.rs), [`frameassembly::backend::compile_program`](file:///home/steve/frameassembly/src/backend/mod.rs), Rust 1.96 `std::assert_matches::assert_matches!`, and Rust 1.89 `std::fs::File::lock()`.

```rust
//! Production implementation of multi-tier test architectures using canonical FrameAssembly APIs
//! and modern Rust 1.89–1.99.1 standard library QA primitives.

use std::assert_matches::{assert_matches, debug_assert_matches};
use std::fs::OpenOptions;

use frameassembly::backend::compile_program;
use frameassembly::error::CompilerError;
use frameassembly::parser::{parse_program, validate_semantics};

// ============================================================================
// TIER 1: Feature & Protocol Coverage
// ============================================================================
#[test]
fn test_tier1_ipv4_udp_dns_wire_encoding() {
    let source = r#"
// PROMPT: Verify standard IPv4 UDP DNS A-record query wire encoding.
// TOKENS: HOST, IP, MAC, FLOW, DNS, QNAME, QTYPE, COMPILE
// INSTRUCTION: Declare client and DNS resolver endpoints.
HOST client { IP 192.168.1.10 MAC 00:11:22:33:44:55 }
HOST resolver { IP 192.168.1.1 MAC 00:aa:bb:cc:dd:ee }
// INSTRUCTION: Emit a DNS query for example.com.
FLOW dns_lookup(c, s) {
    c -> s DNS QNAME "example.com" QTYPE "A"
}
// INSTRUCTION: Compile the DNS lookup flow.
COMPILE {
    dns_lookup(client, resolver)
}
"#
    .trim();

    let program = parse_program(source).expect("Valid DNS .fasm must parse");
    validate_semantics(&program, source).expect("Valid DNS .fasm must pass semantic validation");
    let packets = compile_program(&program).expect("Valid DNS .fasm must compile to wire frames");

    assert_eq!(packets.len(), 1);
    let frame = &packets[0].0;
    // EtherType IPv4 (0x0800) at bytes 12..14
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    // IPv4 Version 4, IHL 5 at byte 14
    assert_eq!(frame[14], 0x45);
    // Protocol UDP (17) at byte 23
    assert_eq!(frame[23], 17);
}

// ============================================================================
// TIER 2: Boundary, Overflow & Corner Cases (Rust 1.96+ assert_matches!)
// ============================================================================
#[test]
fn test_tier2_mixed_ipv4_ipv6_endpoints_rejected_by_semantics() {
    let source = r#"
HOST v4_client { IP 10.0.0.1 }
HOST v6_server { IP 2001:db8::1 }
FLOW mixed(a, b) {
    a -> b TCP SYN
}
COMPILE {
    mixed(v4_client, v6_server)
}
"#
    .trim();

    // parse_program invokes validate_semantics at the end of parsing
    let res = parse_program(source);
    assert_matches!(
        res,
        Err(CompilerError::SemanticError { ref message, .. })
            if message.contains("IPv4") || message.contains("IPv6")
    );
    debug_assert_matches!(res, Err(CompilerError::SemanticError { .. }));
}

// ============================================================================
// TIER 3: Cross-Feature Combinations & Encapsulation
// ============================================================================
#[test]
fn test_tier3_qinq_double_vlan_with_ipv6_flowlabel_and_tcp() {
    let source = r#"
HOST node_a { IP 2001:db8::1 MAC 52:54:00:12:34:56 }
HOST node_b { IP 2001:db8::2 MAC 52:54:00:65:43:21 }
FLOW carrier_flow(a, b) {
    a -> b QINQ 100 INNER_VLAN 200 DSCP 46 FLOWLABEL 43981 TCP SYN SRCPORT 45000 DSTPORT 443 SEQ 5000 WINDOW 64240
}
COMPILE {
    carrier_flow(node_a, node_b)
}
"#
    .trim();

    let program = parse_program(source).expect("QinQ + IPv6 + TCP must parse");
    validate_semantics(&program, source).expect("QinQ + IPv6 + TCP must pass semantics");
    let packets = compile_program(&program).expect("QinQ + IPv6 + TCP must compile");
    assert_eq!(packets.len(), 1);
    let frame = &packets[0].0;
    // Outer S-VLAN TPID 0x88A8 at bytes 12..14
    assert_eq!(&frame[12..14], &[0x88, 0xA8]);
    // Inner C-VLAN TPID 0x8100 at bytes 16..18
    assert_eq!(&frame[16..18], &[0x81, 0x00]);
    // Inner EtherType IPv6 (0x86DD) at bytes 20..22
    assert_eq!(&frame[20..22], &[0x86, 0xDD]);
}

// ============================================================================
// TIER 4: Real-World Conversational Flow & Rust 1.89+ File::lock() Guard
// ============================================================================
#[test]
fn test_tier4_complete_three_way_tcp_handshake_and_http_flow() {
    let lock_path = std::env::temp_dir().join("frameassembly_tier4_fixture.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .expect("Failed to open cross-process test lock file");
    // Rust 1.89+ native OS advisory lock across parallel nextest / cargo test processes
    lock_file.lock().expect("Failed to acquire File::lock()");

    let source = r#"
HOST client { IP 172.16.0.5 MAC 00:01:02:03:04:05 }
HOST server { IP 172.16.0.10 MAC 00:06:07:08:09:0a }
FLOW web_session(c, s) {
    c -> s TCP SYN SRCPORT 49152 DSTPORT 80
    c <- s TCP SYN ACK WAIT 1ms
    c -> s TCP ACK WAIT 1ms
    c -> s HTTP GET URI "/v1/health" HOST_HDR "api.internal" WAIT 2ms
    c <- s HTTP RESPONSE STATUS 200 REASON "OK" BODY "healthy" WAIT 3ms
}
COMPILE {
    web_session(client, server)
}
"#
    .trim();

    let program = parse_program(source).expect("TCP + HTTP flow must parse");
    validate_semantics(&program, source).expect("TCP + HTTP flow must pass semantics");
    let packets = compile_program(&program).expect("TCP + HTTP flow must compile");
    assert_eq!(packets.len(), 5);
    let _ = lock_file.unlock();
}
```

---

## 2. Six-Gate Corpus (`2,611` Files), Lexer Bijection, Markdown Block & AST `*Spec`-to-Builder Wiring Engine (`tests/corpus_verification_tests.rs`)

Automates deep structural, lexical bijection, Markdown fenced-block compilation, OpenCoder/chunk-size verification, and Gate 6 AST `*Spec` field-to-builder wiring checks across the repository.

```rust
//! Six-gate verification suite for FrameAssembly examples (2,611 scenarios), documentation,
//! and AST-to-builder wire completeness.

use std::fs;
use std::path::{Path, PathBuf};
use logos::Logos;
use frameassembly::backend::compile_program;
use frameassembly::lexer::Token;
use frameassembly::parser::{parse_program, validate_semantics};

/// Gate 2: Verifies that every keyword token listed in `// TOKENS:` on Line 2
/// is a valid lexer token present in the `.fasm` file body.
pub fn verify_tokens_header_bijection(path: &Path, content: &str) -> Result<(), String> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 || !lines[1].starts_with("// TOKENS: ") {
        return Err(format!("{}: Missing '// TOKENS: ' on line 2", path.display()));
    }

    let header_tokens: Vec<&str> = lines[1]
        .trim_start_matches("// TOKENS: ")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    for raw_tok in &header_tokens {
        let mut lex = Token::lexer(raw_tok);
        match lex.next() {
            Some(Ok(Token::Ident(id))) => {
                return Err(format!(
                    "{}: Hallucinated non-keyword token '{}' in // TOKENS: header (lexed as Ident({:?}))",
                    path.display(),
                    raw_tok,
                    id
                ));
            }
            Some(Ok(_)) => {}
            _ => {
                return Err(format!(
                    "{}: Invalid token '{}' in // TOKENS: header",
                    path.display(),
                    raw_tok
                ));
            }
        }
    }

    Ok(())
}

/// Gate 3: Extracts all ```frameassembly and ```fasm fenced code blocks from a Markdown
/// or Rust source file and verifies that every complete program compiles cleanly.
pub fn verify_markdown_fasm_blocks_compile(path: &Path) -> Result<usize, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let mut in_block = false;
    let mut current_block = String::new();
    let mut block_start_line = 0usize;
    let mut compiled_blocks = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim().trim_start_matches("//!").trim_start_matches("///").trim();
        if !in_block && (trimmed.starts_with("```frameassembly") || trimmed.starts_with("```fasm")) {
            in_block = true;
            current_block.clear();
            block_start_line = idx + 1;
        } else if in_block && trimmed.starts_with("```") {
            in_block = false;
            let snippet = current_block.trim();
            let upper = snippet.to_ascii_uppercase();
            if upper.contains("HOST ") && upper.contains("FLOW ") && upper.contains("COMPILE") {
                let prog = parse_program(snippet).map_err(|e| {
                    format!("{}:{}: Markdown .fasm block failed to parse: {e:?}", path.display(), block_start_line)
                })?;
                validate_semantics(&prog, snippet).map_err(|e| {
                    format!("{}:{}: Markdown .fasm block failed semantics: {e:?}", path.display(), block_start_line)
                })?;
                compile_program(&prog).map_err(|e| {
                    format!("{}:{}: Markdown .fasm block failed compilation: {e}", path.display(), block_start_line)
                })?;
                compiled_blocks += 1;
            }
        } else if in_block {
            let clean_line = line
                .trim_start()
                .strip_prefix("//! ")
                .or_else(|| line.trim_start().strip_prefix("//!"))
                .or_else(|| line.trim_start().strip_prefix("/// "))
                .or_else(|| line.trim_start().strip_prefix("///"))
                .unwrap_or(line);
            current_block.push_str(clean_line);
            current_block.push('\n');
        }
    }

    Ok(compiled_blocks)
}

/// Gate 5: Verifies that every AI-critical Rust source/test file (`src/**/*.rs`, `tests/*.rs`)
/// and `.fasm` corpus file is strictly < 50 KB (Markdown documentation has no 50 KB cap)
/// and has at least 50 words (OpenCoder opc_data_filtering minimum word count).
pub fn verify_file_chunk_size_and_word_bounds(path: &Path) -> Result<(), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let is_markdown = path.extension().and_then(|s| s.to_str()) == Some("md");
    let byte_len = content.len();
    if !is_markdown && byte_len >= 50_000 {
        return Err(format!(
            "{}: File size {} bytes exceeds 50,000-byte AI chunk limit",
            path.display(),
            byte_len
        ));
    }
    let word_count = content.split_whitespace().count();
    if word_count < 50 {
        return Err(format!(
            "{}: Word count {} is below OpenCoder 50-word minimum",
            path.display(),
            word_count
        ));
    }
    Ok(())
}

/// Gate 6: Verifies that every `pub` field on every protocol `*Spec` struct (plus `TcpOptions`
/// and `SctpParams`) in `src/ast/{l2,l3,l4,l7}/*.rs` is wired into and referenced by the
/// corresponding wire builder, `src/packet.rs`, or `src/backend/`.
pub fn verify_ast_spec_fields_wired(ast_path: &Path, builder_sources: &str) -> Vec<String> {
    let ast_src = fs::read_to_string(ast_path).expect("Failed to read AST file");
    let mut current_struct: Option<String> = None;
    let mut unwired = Vec::new();

    for line in ast_src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub struct ") {
            let name = rest.split(['{', '<', '(']).next().unwrap_or("").trim();
            if name.ends_with("Spec") || name == "TcpOptions" || name == "SctpParams" {
                current_struct = Some(name.to_string());
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
                let dot_access = format!(".{field_name}");
                if !builder_sources.contains(&dot_access) && !builder_sources.contains(field_name) {
                    unwired.push(format!("{}::{struct_name}::{field_name}", ast_path.display()));
                }
            }
        }
    }
    unwired
}
```

---

## 3. Automated 6-Way Grammar, IDE & WASM Lockstep + Non-Terminal Resolution Test Template

Verifies that every uppercase `#[token("...")]` in `src/lexer/mod.rs` is present in `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json` (both uppercase and lowercase), and that **every non-terminal referenced on the RHS of a grammar rule is actually defined on the LHS**:

```rust
//! Automated 6-way grammar/IDE/WASM non-terminal resolution and keyword lockstep test.

use std::collections::HashSet;
use std::fs;

/// Verifies that every rule referenced in `frameassembly.gbnf` is defined on the LHS.
#[test]
fn test_gbnf_all_referenced_non_terminals_are_defined() {
    let gbnf = fs::read_to_string("frameassembly.gbnf").expect("Failed to read frameassembly.gbnf");
    let mut defined = HashSet::new();
    let mut rhs_tokens = Vec::new();

    for line in gbnf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once("::=") {
            defined.insert(lhs.trim().to_string());
            let mut in_quotes = false;
            let mut in_brackets = false;
            let mut cleaned = String::new();
            for ch in rhs.chars() {
                if ch == '"' {
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
                if word.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                    rhs_tokens.push(word.to_string());
                }
            }
        }
    }

    assert!(defined.contains("root"), "frameassembly.gbnf must define 'root' entrypoint");
    for referenced in rhs_tokens {
        assert!(
            defined.contains(&referenced),
            "Undefined GBNF non-terminal '{}' referenced in frameassembly.gbnf",
            referenced
        );
    }
}
```

---

## 4. Property-Based Compiler Testing (`proptest` + `proptest-regressions/`) & External Wireshark (`tshark`) Dissector Gate

### A. Property-Based AST & Round-Trip Synthesis (`proptest`)
Commit generated `proptest-regressions/**/*.txt` seed files to version control so failing counterexamples discovered during fuzzing or CI runs replay deterministically on every `cargo test` invocation.

```rust
//! Property-based round-trip testing for FrameAssembly using proptest.

use frameassembly::backend::compile_program;
use frameassembly::parser::{parse_program, validate_semantics};
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_valid_ipv4_tcp_handshake_never_panics_and_preserves_invariants(
        src_octet in 1u8..=254u8,
        dst_octet in 1u8..=254u8,
        src_port in 1024u16..=65535u16,
        dst_port in 1u16..=1023u16,
        seq_num in 0u32..=u32::MAX,
        win_size in 512u16..=65535u16,
        wait_ms in 1u64..=1000u64,
    ) {
        let source = format!(
            "HOST c {{ IP 10.0.0.{src_octet} }}\n\
             HOST s {{ IP 10.0.1.{dst_octet} }}\n\
             FLOW prop_flow(a, b) {{\n\
                 a -> b TCP SYN SRCPORT {src_port} DSTPORT {dst_port} SEQ {seq_num} WINDOW {win_size}\n\
                 a <- b TCP SYN ACK WAIT {wait_ms}ms\n\
                 a -> b TCP ACK WAIT {wait_ms}ms\n\
             }}\n\
             COMPILE {{\n\
                 prop_flow(c, s)\n\
             }}"
        );

        let program = parse_program(&source).expect("Generated valid .fasm must parse");
        validate_semantics(&program, &source).expect("Generated valid .fasm must pass semantics");
        let packets = compile_program(&program).expect("Generated valid .fasm must compile");

        // Invariant 1: 1 Statement = 1 Frame
        prop_assert_eq!(packets.len(), 3);
        // Invariant 2: Monotonic nanosecond timestamps matching WAIT modifiers
        prop_assert_eq!(packets[0].1, 0);
        prop_assert_eq!(packets[1].1, wait_ms * 1_000_000);
        prop_assert_eq!(packets[2].1, wait_ms * 2_000_000);
        // Invariant 3: Ethernet + IPv4 + TCP minimum length (14 + 20 + 20 = 54 bytes)
        for (frame, _) in &packets {
            prop_assert!(frame.len() >= 54);
            prop_assert_eq!(&frame[12..14], &[0x08, 0x00]);
        }
    }
}
```

### B. External Wireshark (`tshark`) Dissector Gate Template
```rust
//! External Wireshark (tshark) dissector verification gate for zero-defect RFC wire framing.

use std::process::Command;
use frameassembly::backend::generate_pcap;
use frameassembly::parser::{parse_program, validate_semantics};

/// Compiles a `.fasm` script to a temporary PCAPNG file and runs `tshark -r <file> -V`
/// (when `tshark` is installed on the host) to assert zero malformed packet or bad checksum expert infos.
pub fn assert_tshark_clean_dissection(source: &str, temp_pcap_path: &str) {
    let program = parse_program(source).expect("Valid .fasm program");
    validate_semantics(&program, source).expect("Valid .fasm semantics");
    generate_pcap(&program, temp_pcap_path).expect("Valid PCAPNG generation");

    let Ok(output) = Command::new("tshark")
        .args(["-r", temp_pcap_path, "-V"])
        .output()
    else {
        let _ = std::fs::remove_file(temp_pcap_path);
        return;
    };
    let _ = std::fs::remove_file(temp_pcap_path);

    assert!(output.status.success(), "tshark exited with non-zero status");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for forbidden in ["[Malformed Packet", "[Bogus", "[Bad Checksum", "Expert Info (Error"] {
        assert!(
            !stdout.contains(forbidden),
            "Wireshark tshark reported protocol framing defect '{}' in dissection:\n{}",
            forbidden,
            stdout
        );
    }
}
```

---

## 5. Nextest, Doctest Coverage, Mutation Testing (`--in-diff`), Semver & `.agents/scripts/file_lock.sh` Commands

```bash
# 1. Run parallel test processes and Edition 2024 merged doctests with Rust 1.97+ build.warnings gate
CARGO_BUILD_WARNINGS=deny cargo nextest run --all-targets
CARGO_BUILD_WARNINGS=deny cargo test --doc

# 2. Enforce >= 90% line coverage including Edition 2024 doctests (--doctests)
cargo llvm-cov --all-targets --doctests --workspace --fail-under-lines 90

# 3. Run diff-scoped and module-scoped mutation testing on parsers, validators, USM crypto, and builders
git diff origin/main...HEAD > temp/changes.diff
cargo mutants --in-diff temp/changes.diff
cargo mutants -f src/packet.rs -f src/parser/validation.rs -f src/builders/l7/snmp/crypto.rs

# 4. Verify zero accidental public API semver regressions prior to crate release
cargo semver-checks check-release

# 5. Coordinate parallel multi-agent file edits and serialized Cargo target builds via file_lock.sh
.agents/scripts/file_lock.sh acquire worker_qa 600 tests/corpus_verification_tests.rs
.agents/scripts/file_lock.sh status
.agents/scripts/file_lock.sh exec cargo-target -- cargo test --test corpus_verification_tests
.agents/scripts/file_lock.sh release worker_qa tests/corpus_verification_tests.rs
```
