//! Unit tests for the FrameAssembly syntactic parser and semantic validation passes.
//!
//! This module verifies string escape sequence decoding (`\r`, `\n`, `\t`, `\xHH`, `\uXXXX`),
//! raw hexadecimal payload parsing (`HEXPAYLOAD`), top-level `HOST`, `FLOW`, and `COMPILE` block
//! parsing, protocol-scoped modifier disambiguation, and spanned semantic diagnostic reporting
//! across out-of-range fields, mixed IPv4/IPv6 endpoints, and duplicate symbol declarations.

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

/// Tests that shared keywords and shorthand modifiers do not shadow each other across protocols.
#[test]
fn test_no_cross_protocol_shadowing() {
    let input = r#"
        HOST client { IP 10.0.0.1 }
        HOST server { IP 10.0.0.2 }
        FLOW f(c, s) {
            c -> s SSH KEXINIT COOKIE "00112233445566778899aabbccddeeff"
            c -> s TACACS AUTHEN SEQ 1 DATA "secret"
            c -> s TELNET WILL OPTION 1 DATA "login: "
            c -> s REDIS GET KEY "session:1" VALUE "active"
            c -> s MEMCACHED SET KEY "k1" FLAGS 0 EXPTIME 60 VALUE "v1"
            c -> s MODBUS READ_HOLDING_REGISTERS TXID 1 UNITID 1 ADDR 100 COUNT 2 VALUE 42
            c -> s HTTP GET URI "/index.html" VERSION "1.1" STATUS 200
            c -> s QUIC INITIAL VERSION 1 DCID 0x1122334455667788 SCID "8877665544332211" TOKEN "deadbeef"
            c -> s COAP CON GET MSGID 42 TOKEN 0x1234 URI_PATH "sensors/temp"
            c -> s SYSLOG PRI 34 HOSTNAME "gw1" APP "sshd" MSGID "ID47" MSG "Accepted"
            c -> s SMB NEGOTIATE STATUS 0 SESSION_ID 100 MSGID 1
            c -> s LDAP MSGID 7 BIND_REQ BASE_DN "dc=example,dc=com"
            c -> s IMAP TAG "A001" CMD "LOGIN" STATUS "OK" RESPONSE "Logged in"
            c -> s OPCUA MSG_TYPE "OPN" CHUNK_TYPE "F" SECURE_CHANNEL_ID 1 REQID 99
            c -> s OPENFLOW VERSION 4 ECHO_REPLY XID 123
            c -> s DNS QUERY TXID 101 QNAME "example.com" QTYPE "A"
            c -> s WHOIS QUERY DOMAIN "example.com"
            c -> s MYSQL QUERY USER "root" SQL "SELECT 1"
            c -> s POSTGRES QUERY USER "postgres" SQL "SELECT 1"
            c -> s DHCP DISCOVER XID 0x12345678
            c -> s RIP REQUEST PREFIX 10.1.0.0 METRIC 1 TAG 10
            c -> s MQTT CONNECT CLIENT_ID "iot-1" KEEPALIVE 60
            c -> s S7COMM READ_VAR AREA "DB" DB_NUM 1 OFFSET 0
            c -> s DNP3 DIRECT_OPERATE SRC 1 DST 2 GROUP 12 VARIATION 1
            c -> s ETHERNETIP REGISTER_SESSION SESSION_HANDLE 1 STATUS 0
        }
        COMPILE { f(client, server) }
    "#;
    let prog = parse_program(input).unwrap();
    assert_eq!(prog.flows[0].statements.len(), 25);
}

/// Tests CRLF line endings and GRE sequence number (`SEQ`) field population.
#[test]
fn test_crlf_and_gre_seq_parsing() {
    let input = "HOST r1 { IP 10.0.0.1 }\r\nHOST r2 { IP 10.0.0.2 }\r\nFLOW f(a, b) {\r\n    a -> b GRE KEY 100 SEQ 5 CHECKSUM\r\n}\r\nCOMPILE { f(r1, r2) }\r\n";
    let prog = parse_program(input).unwrap();
    let stmt = &prog.flows[0].statements[0];
    match &stmt.protocol_spec {
        Some(ProtocolSpec::Gre(gre)) => {
            assert_eq!(gre.key, Some(100));
            assert_eq!(gre.seq, Some(5));
            assert!(gre.checksum);
        }
        other => panic!("Expected GreSpec, got {:?}", other),
    }
}
