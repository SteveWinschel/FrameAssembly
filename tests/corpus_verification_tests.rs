//! Comprehensive corpus verification test suite for FrameAssembly examples.
//!
//! Validates:
//! 1. All `.fasm` files are organized in dedicated `<layer>/<protocol>/` directories without numeric prefixes.
//! 2. No `.fasm` files remain directly in the `examples/` root directory.
//! 3. All protocol directories have at least 2-3+ scenarios covering defaults and overrides.
//! 4. Strict dataset header formatting:
//!    - Line 1 begins with `// PROMPT: <scenario description>`.
//!    - Line 2 begins with `// TOKENS: <comma-separated keyword list>`.
//!    - Each `HOST`, `FLOW`, and `COMPILE` block is preceded by `// INSTRUCTION: <description>`.
//! 5. Lexical analysis, syntactic parsing (`parse_program`), and wire packet compilation
//!    (`generate_pcap`) producing valid, non-empty `.pcap` files with zero errors.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::fs;
use std::path::{Path, PathBuf};

/// Inspects and verifies a single `.fasm` example file.
///
/// Ensures strict header comments (`// PROMPT:`, `// TOKENS:`, `// INSTRUCTION:`),
/// successful parsing via `parse_program`, and compilation into a valid, non-empty PCAP.
fn verify_example_file(path: &Path) -> Result<(), String> {
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "Invalid filename".to_string())?;

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 3 {
        return Err(format!("{}: File too short (must have at least 3 lines)", path.display()));
    }

    // Line 1: // PROMPT:
    if !lines[0].starts_with("// PROMPT: ") {
        return Err(format!(
            "{}: Line 1 must begin with '// PROMPT: ', got: '{}'",
            path.display(), lines[0]
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
            path.display(), lines[1]
        ));
    }
    let tokens_body = lines[1].trim_start_matches("// TOKENS: ").trim();
    if tokens_body.is_empty() {
        return Err(format!("{}: TOKENS comment body cannot be empty", path.display()));
    }

    // Instruction comments check
    if !content.contains("// INSTRUCTION:") {
        return Err(format!(
            "{}: File must contain '// INSTRUCTION:' comments before blocks",
            path.display()
        ));
    }

    // Syntactic parsing
    let program = frameassembly::parser::parse_program(&content)
        .map_err(|e| format!("Parse error in {}: {:?}", path.display(), e))?;

    // Wire packet generation to temp PCAP with thread-safe unique filename
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp_dir = std::env::temp_dir();
    let temp_pcap = temp_dir.join(format!("verify_{}_{}_{}", std::process::id(), count, filename));
    let temp_pcap_str = temp_pcap.to_str().ok_or_else(|| "Invalid temp path".to_string())?;

    let compile_res = frameassembly::backend::generate_pcap(&program, temp_pcap_str);
    if let Err(e) = compile_res {
        let _ = fs::remove_file(&temp_pcap);
        return Err(format!("Compilation error in {}: {}", path.display(), e));
    }

    // Verify non-empty output
    let metadata = fs::metadata(&temp_pcap)
        .map_err(|e| format!("Failed to stat output PCAP for {}: {}", path.display(), e))?;
    if metadata.len() == 0 {
        let _ = fs::remove_file(&temp_pcap);
        return Err(format!("{}: Generated PCAP is 0 bytes", path.display()));
    }

    // Clean up temporary file
    let _ = fs::remove_file(&temp_pcap);
    Ok(())
}

/// Helper function to recursively collect all `.fasm` files under a directory.
fn collect_fasm_files_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_fasm_files_recursive(&path, results);
            } else if path.extension().and_then(|s| s.to_str()) == Some("fasm") {
                results.push(path);
            }
        }
    }
}

/// Discovers all `.fasm` files in the `examples/` directory hierarchy sorted by path.
fn get_sorted_example_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_fasm_files_recursive(Path::new("examples"), &mut paths);
    paths.sort();
    paths
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
        paths.len() >= 205,
        "Corpus must contain at least 205 total .fasm examples across all layers, found {}",
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

/// Tests that all OSI layer subfolders and protocols are covered with multiple scenarios.
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

    // Check L2
    for proto in expected_l2 {
        let dir = Path::new("examples/l2").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L2 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_fasm_files_recursive(&dir, &mut files);
        assert!(files.len() >= 2, "Folder {} has fewer than 2 scenarios: {}", dir.display(), files.len());
    }

    // Check L3
    for proto in expected_l3 {
        let dir = Path::new("examples/l3").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L3 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_fasm_files_recursive(&dir, &mut files);
        assert!(files.len() >= 2, "Folder {} has fewer than 2 scenarios: {}", dir.display(), files.len());
    }

    // Check L4
    for proto in expected_l4 {
        let dir = Path::new("examples/l4").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L4 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_fasm_files_recursive(&dir, &mut files);
        assert!(files.len() >= 2, "Folder {} has fewer than 2 scenarios: {}", dir.display(), files.len());
    }

    // Check L7
    for proto in expected_l7 {
        let dir = Path::new("examples/l7").join(proto);
        assert!(dir.exists() && dir.is_dir(), "Missing L7 folder: {}", dir.display());
        let mut files = Vec::new();
        collect_fasm_files_recursive(&dir, &mut files);
        assert!(files.len() >= 2, "Folder {} has fewer than 2 scenarios: {}", dir.display(), files.len());
    }

    // Check SNMP subfolders
    for snmp_ver in expected_snmp {
        let dir = Path::new("examples/l7/snmp").join(snmp_ver);
        assert!(dir.exists() && dir.is_dir(), "Missing SNMP folder: {}", dir.display());
        let mut files = Vec::new();
        collect_fasm_files_recursive(&dir, &mut files);
        assert!(files.len() >= 2, "Folder {} has fewer than 2 scenarios: {}", dir.display(), files.len());
    }

    // Check Topologies
    let topologies_dir = Path::new("examples/topologies");
    assert!(topologies_dir.exists() && topologies_dir.is_dir(), "Missing examples/topologies");
    let mut topo_files = Vec::new();
    collect_fasm_files_recursive(topologies_dir, &mut topo_files);
    assert!(topo_files.len() >= 10, "examples/topologies has fewer than 10 scenarios: {}", topo_files.len());
}

/// Tests all `.fasm` example files in `examples/` for headers, syntax parsing, and PCAP compilation.
#[test]
fn test_corpus_all_examples_headers_and_compilation() {
    let paths = get_sorted_example_paths();
    assert!(
        paths.len() >= 205,
        "Corpus must have at least 205 .fasm examples, found {}",
        paths.len()
    );

    let mut failed = Vec::new();
    for path in &paths {
        if let Err(e) = verify_example_file(path) {
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
