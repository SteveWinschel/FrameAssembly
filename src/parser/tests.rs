//! Unit tests for the parser module.

use super::*;
use crate::error::CompilerError;

/// Tests unescaping of escape sequences in string literals.
#[test]
fn test_unescape_string() {
    let raw = r#"hello\r\n\t\"world\"\\ \x41\x42 \u0043"#;
    let unescaped = unescape_string(raw).unwrap();
    assert_eq!(unescaped, "hello\r\n\t\"world\"\\ AB C");
}

/// Tests parsing of HEXPAYLOAD fields into byte vectors.
#[test]
fn test_hex_payload_parsing() {
    let input = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW f(c, s) {
            c -> s UDP HEXPAYLOAD "deadbeef 0102"
        }
        COMPILE { f(client, server) }
    "#;
    let prog = parse_program(input).unwrap();
    let stmt = &prog.flows[0].statements[0];
    assert_eq!(
        stmt.hex_payload.as_deref(),
        Some(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02][..])
    );
    assert_eq!(
        stmt.effective_payload(),
        Some(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02][..])
    );
}

/// Tests that contextual keywords can be used as identifiers for hosts and flows.
#[test]
fn test_contextual_keywords_as_identifiers() {
    let input = r#"
        HOST dns { IP 10.0.0.1 }
        HOST ms { IP 10.0.0.2 }
        FLOW get(s, m) {
            s -> m UDP PAYLOAD "query"
        }
        COMPILE { get(dns, ms) }
    "#;
    let prog = parse_program(input).unwrap();
    assert_eq!(prog.hosts[0].name, "dns");
    assert_eq!(prog.hosts[1].name, "ms");
    assert_eq!(prog.flows[0].name, "get");
}

/// Tests that duplicate HOST definitions result in a semantic error.
#[test]
fn test_semantic_error_duplicate_host() {
    let input = r#"
        HOST client { IP 10.0.0.1 }
        HOST client { IP 10.0.0.2 }
        COMPILE {}
    "#;
    let err = parse_program(input).unwrap_err();
    match err {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Duplicate HOST"));
        }
        _ => panic!("Expected SemanticError"),
    }
}

/// Tests that TTL values out of u8 range result in a semantic error.
#[test]
fn test_semantic_error_out_of_range_ttl() {
    let input = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW f(c, s) {
            c -> s UDP TTL 300
        }
        COMPILE { f(client, server) }
    "#;
    let err = parse_program(input).unwrap_err();
    match err {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("TTL 300 out of range"));
        }
        _ => panic!("Expected SemanticError"),
    }
}

/// Tests that mixing IPv4 and IPv6 hosts in a flow produces a semantic error.
#[test]
fn test_semantic_error_mixed_ipv4_ipv6() {
    let input = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP fe80::1 }
        FLOW f(c, s) {
            c -> s UDP PAYLOAD "hello"
        }
        COMPILE { f(client, server) }
    "#;
    let err = parse_program(input).unwrap_err();
    match err {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Mixed IPv4 and IPv6"));
        }
        _ => panic!("Expected SemanticError"),
    }
}

/// Tests that incompatible cross-protocol modifiers produce a semantic error.
#[test]
fn test_semantic_error_invalid_cross_protocol() {
    let input = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW f(c, s) {
            c -> s UDP SYN
        }
        COMPILE { f(client, server) }
    "#;
    let err = parse_program(input).unwrap_err();
    match err {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Invalid cross-protocol modifier"));
        }
        _ => panic!("Expected SemanticError"),
    }
}
