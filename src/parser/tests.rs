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

/// Verifies that uppercase, lowercase, and mixed-case `.fasm` specifications compile to
/// byte-for-byte identical PCAPNG wire output while preserving string literal casing.
#[test]
fn test_case_insensitive_pcap_wire_equivalence() {
    let upper = r#"
        HOST client { IP 10.0.0.1 MAC 00:11:22:33:44:01 }
        HOST server { IP 10.0.0.2 MAC 00:11:22:33:44:02 }
        FLOW session(c, s) {
            c -> s TCP SYN SRCPORT 50000 DSTPORT 80 WINDOW 64240 MSS 1460
            s -> c TCP SYN ACK WINDOW 65535 WAIT 1MS
            c -> s TCP ACK WAIT 500US
            c -> s HTTP GET URI "/Api/V1/Status" HOST_HDR "Example.COM" WAIT 2MS
            s -> c HTTP STATUS 200 REASON "OK" BODY "{\"Status\":\"Healthy\"}" WAIT 1S
            c -> s DNS QUERY TXID 0x1a2b QNAME "api.example.com" QTYPE "AAAA"
        }
        COMPILE {
            LOOP 2 {
                session(client, server)
            }
        }
    "#;

    let lower = r#"
        host client { ip 10.0.0.1 mac 00:11:22:33:44:01 }
        host server { ip 10.0.0.2 mac 00:11:22:33:44:02 }
        flow session(c, s) {
            c -> s tcp syn srcport 50000 dstport 80 window 64240 mss 1460
            s -> c tcp syn ack window 65535 wait 1ms
            c -> s tcp ack wait 500us
            c -> s http get uri "/Api/V1/Status" host_hdr "Example.COM" wait 2ms
            s -> c http status 200 reason "OK" body "{\"Status\":\"Healthy\"}" wait 1s
            c -> s dns query txid 0x1a2b qname "api.example.com" qtype "aaaa"
        }
        compile {
            loop 2 {
                session(client, server)
            }
        }
    "#;

    let mixed = r#"
        Host Client { Ip 10.0.0.1 Mac 00:11:22:33:44:01 }
        hOsT sErVeR { iP 10.0.0.2 mAc 00:11:22:33:44:02 }
        Flow Session(C, S) {
            c -> S Tcp Syn SrcPort 50000 DstPort 80 Window 64240 Mss 1460
            S -> C tCp sYn aCk wInDoW 65535 Wait 1Ms
            C -> s TCP Ack wAiT 500uS
            c -> s Http Get Uri "/Api/V1/Status" Host_Hdr "Example.COM" Wait 2mS
            s -> c hTtP sTaTuS 200 Reason "OK" Body "{\"Status\":\"Healthy\"}" Wait 1s
            C -> S Dns Query TxId 0x1a2b Qname "api.example.com" Qtype "AaAa"
        }
        Compile {
            Loop 2 {
                sEsSiOn(cLiEnT, SeRvEr)
            }
        }
    "#;

    let prog_upper = parse_program(upper).unwrap();
    let prog_lower = parse_program(lower).unwrap();
    let prog_mixed = parse_program(mixed).unwrap();

    let packets_upper = crate::backend::compile_program(&prog_upper).unwrap();
    let packets_lower = crate::backend::compile_program(&prog_lower).unwrap();
    let packets_mixed = crate::backend::compile_program(&prog_mixed).unwrap();

    assert_eq!(packets_upper.len(), 12);
    assert_eq!(packets_upper, packets_lower);
    assert_eq!(packets_upper, packets_mixed);
}

/// Verifies case-insensitive duplicate `HOST`, `FLOW`, and flow parameter semantic errors.
#[test]
fn test_case_insensitive_duplicate_symbol_errors() {
    let dup_host = r#"
        host Client { ip 10.0.0.1 }
        HOST cLiEnT { ip 10.0.0.2 }
        compile {}
    "#;
    match parse_program(dup_host).unwrap_err() {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Duplicate HOST"));
        }
        other => panic!("Expected SemanticError for duplicate host, got {:?}", other),
    }

    let dup_flow = r#"
        host a { ip 10.0.0.1 }
        host b { ip 10.0.0.2 }
        flow WebTraffic(x, y) { x -> y tcp syn }
        FLOW webtraffic(x, y) { x -> y tcp ack }
        compile { WebTraffic(a, b) }
    "#;
    match parse_program(dup_flow).unwrap_err() {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Duplicate FLOW"));
        }
        other => panic!("Expected SemanticError for duplicate flow, got {:?}", other),
    }

    let dup_param = r#"
        host a { ip 10.0.0.1 }
        flow ping(Node, node) { Node -> node icmp echo_request }
        compile { ping(a, a) }
    "#;
    match parse_program(dup_param).unwrap_err() {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Duplicate parameter"));
        }
        other => panic!("Expected SemanticError for duplicate param, got {:?}", other),
    }
}
