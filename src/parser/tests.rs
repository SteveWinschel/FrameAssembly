//! Unit tests for the FrameAssembly syntactic parser and semantic validation passes.
//!
//! This module verifies string escape sequence decoding (`\r`, `\n`, `\t`, `\xHH`, `\uXXXX`),
//! raw hexadecimal payload parsing (`hexpayload`), top-level `host`, `flow`, and `compile` block
//! parsing, protocol-scoped modifier disambiguation (`whois`, `hellotime`, promoted sub-keywords),
//! self-healing v3.0.0 diagnostics, and spanned semantic diagnostic reporting across out-of-range
//! fields, mixed IPv4/IPv6 endpoints, and duplicate symbol declarations.

use super::*;
use crate::error::CompilerError;

/// Tests unescaping of escape sequences in string literals.
#[test]
fn test_unescape_string() {
    let raw = r#"hello\r\n\t\"world\"\\ \x41\x42 \u0043"#;
    let unescaped = unescape_string(raw).unwrap();
    assert_eq!(unescaped, "hello\r\n\t\"world\"\\ AB C");
}

/// Tests parsing of `hexpayload` fields into byte vectors.
#[test]
fn test_hex_payload_parsing() {
    let input = r#"
        host client { ip 10.0.0.1 }
        host server { ip 10.0.0.2 }
        flow f(c, s) {
            c -> s udp hexpayload "deadbeef 0102"
        }
        compile { f(client, server) }
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

/// Tests that contextual keywords (including newly promoted v3.0.0 sub-keywords) and hyphenated
/// names can be used as identifiers for hosts, flows, and parameters.
#[test]
fn test_contextual_keywords_and_hyphenated_identifiers() {
    let input = r#"
        host dns { ip 10.0.0.1 }
        host fw-dmz-01 { ip 10.0.0.2 }
        host read { ip 10.0.0.3 }
        flow pkttype(nop, shutdownack) {
            nop->shutdownack udp payload "query"
        }
        compile {
            pkttype(dns, fw-dmz-01)
            fw-dmz-01->read icmp echorequest
        }
    "#;
    let prog = parse_program(input).unwrap();
    assert_eq!(prog.hosts[0].name, "dns");
    assert_eq!(prog.hosts[1].name, "fw-dmz-01");
    assert_eq!(prog.hosts[2].name, "read");
    assert_eq!(prog.flows[0].name, "pkttype");
    let packets = crate::backend::compile_program(&prog).unwrap();
    assert_eq!(packets.len(), 2);
}

/// Tests that duplicate `host` definitions result in a semantic error.
#[test]
fn test_semantic_error_duplicate_host() {
    let input = r#"
        host client { ip 10.0.0.1 }
        host client { ip 10.0.0.2 }
        compile {}
    "#;
    let err = parse_program(input).unwrap_err();
    match err {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Duplicate HOST"));
        }
        _ => panic!("Expected SemanticError"),
    }
}

/// Tests that `ttl` values out of `u8` range result in a semantic error.
#[test]
fn test_semantic_error_out_of_range_ttl() {
    let input = r#"
        host client { ip 10.0.0.1 }
        host server { ip 10.0.0.2 }
        flow f(c, s) {
            c -> s udp ttl 300
        }
        compile { f(client, server) }
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
        host client { ip 10.0.0.1 }
        host server { ip fe80::1 }
        flow f(c, s) {
            c -> s udp payload "hello"
        }
        compile { f(client, server) }
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
        host client { ip 10.0.0.1 }
        host server { ip 10.0.0.2 }
        flow f(c, s) {
            c -> s udp syn
        }
        compile { f(client, server) }
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
        host client { ip 10.0.0.1 }
        host server { ip 10.0.0.2 }
        flow f(c, s) {
            c -> s ssh kexinit cookie "00112233445566778899aabbccddeeff"
            c -> s tacacs authen seq 1 data "secret"
            c -> s telnet will option 1 data "login: "
            c -> s redis get key "session:1" value "active"
            c -> s memcached set key "k1" flags 0 exptime 60 value "v1"
            c -> s modbus readholdingregisters txid 1 unitid 1 addr 100 count 2 value 42
            c -> s http get uri "/index.html" version "1.1" status 200
            c -> s quic initial version 1 dcid 0x1122334455667788 scid "8877665544332211" token "deadbeef"
            c -> s coap con get msgid 42 token 0x1234 uripath "sensors/temp"
            c -> s syslog pri 34 hostname "gw1" app "sshd" msgid "ID47" msg "Accepted"
            c -> s smb negotiate status 0 sessionid 100 msgid 1
            c -> s ldap msgid 7 bindreq basedn "dc=example,dc=com"
            c -> s imap tag "A001" cmd "LOGIN" status "OK" response "Logged in"
            c -> s opcua msgtype "OPN" chunktype "F" securechannelid 1 reqid 99
            c -> s openflow version 4 echoreply xid 123
            c -> s dns query txid 101 qname "example.com" qtype "A"
            c -> s whois query domain "example.com"
            c -> s mysql query user "root" sql "SELECT 1"
            c -> s postgres query user "postgres" sql "SELECT 1"
            c -> s dhcp discover xid 0x12345678
            c -> s rip request prefix 10.1.0.0 metric 1 tag 10
            c -> s mqtt connect clientid "iot-1" keepalive 60
            c -> s s7comm readvar area "DB" dbnum 1 offset 0
            c -> s dnp3 directoperate src 1 dst 2 group 12 variation 1
            c -> s ethernetip registersession sessionhandle 1 status 0
        }
        compile { f(client, server) }
    "#;
    let prog = parse_program(input).unwrap();
    assert_eq!(prog.flows[0].statements.len(), 25);
}

/// Verifies Critical Bugfix 1 (`whois` protocol vs `bacnet whois` disambiguation) and
/// Critical Bugfix 2 (`hellotime` unification across `stp` u16 and `hsrp` u8 `0..=255`),
/// plus promoted sub-keywords (`pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`).
#[test]
fn test_v2_whois_hellotime_and_promoted_subkeywords() {
    let input = r#"
        host a { ip 10.0.0.1 }
        host b { ip 10.0.0.2 }
        flow f(x, y) {
            x -> y whois domain "example.com"
            x -> y vlan 100 whois domain "iana.org"
            x -> y bacnet whois
            x -> y hsrp group 1 hellotime 3 holdtime 10 vip 10.0.0.254
            x -> y hellotime 5 hsrp group 2
            x -> y stp hellotime 512
            x -> y mqtt pkttype "CONNECT" clientid "dev-1"
            x -> y dnp3 read src 1 dst 2
            x -> y dnp3 write src 1 dst 2
            x -> y ethernetip nop
            x -> y tftp error errcode 1 errmsg "File not found"
            x -> y sctp shutdownack vtag 0x1234
            x -> y sflow agentip 10.0.0.1 samples 1
            x -> y tcp syn sackperm
        }
        compile { f(a, b) }
    "#;
    let prog = parse_program(input).unwrap();
    let stmts = &prog.flows[0].statements;
    assert_eq!(stmts[0].protocol, Protocol::Whois);
    assert_eq!(stmts[1].protocol, Protocol::Whois);
    assert_eq!(stmts[2].protocol, Protocol::Bacnet);
    match &stmts[2].protocol_spec {
        Some(ProtocolSpec::Bacnet(b)) => assert!(b.is_who_is),
        other => panic!("Expected BacnetSpec, got {:?}", other),
    }
    match &stmts[3].protocol_spec {
        Some(ProtocolSpec::Hsrp(h)) => assert_eq!(h.hellotime, Some(3)),
        other => panic!("Expected HsrpSpec, got {:?}", other),
    }
    match &stmts[4].protocol_spec {
        Some(ProtocolSpec::Hsrp(h)) => assert_eq!(h.hellotime, Some(5)),
        other => panic!("Expected HsrpSpec, got {:?}", other),
    }
    match &stmts[5].protocol_spec {
        Some(ProtocolSpec::Stp(s)) => assert_eq!(s.hello_time, Some(512)),
        other => panic!("Expected StpSpec, got {:?}", other),
    }
    match &stmts[11].protocol_spec {
        Some(ProtocolSpec::Sctp(s)) => assert_eq!(s.chunk.as_deref(), Some("SHUTDOWN_ACK")),
        other => panic!("Expected SctpParams, got {:?}", other),
    }
    assert!(crate::backend::compile_program(&prog).is_ok());

    let bad_hsrp = r#"
        host a { ip 10.0.0.1 }
        host b { ip 10.0.0.2 }
        compile {
            a -> b hellotime 300 hsrp
        }
    "#;
    match parse_program(bad_hsrp).unwrap_err() {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("HSRP hellotime 300 out of range (0..=255)"));
        }
        other => panic!("Expected SemanticError for HSRP hellotime > 255, got {:?}", other),
    }
}

/// Verifies v3.0.0 self-healing diagnostics for removed `loop` and uppercase/snake_case/kebab-case keywords.
#[test]
fn test_v2_self_healing_diagnostics() {
    use miette::Diagnostic;

    let cases = [
        (
            "HOST a { ip 10.0.0.1 }\ncompile {}",
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace 'HOST' with 'host'.",
        ),
        (
            "host a { ip 10.0.0.1 }\ncompile { a -> a icmp echo_request }",
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace 'echo_request' with 'echorequest'.",
        ),
        (
            "host a { ip 10.0.0.1 }\ncompile { a -> a tls client-hello }",
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace 'client-hello' with 'clienthello'.",
        ),
        (
            "host a { ip 10.0.0.1 }\ncompile { a -> a tcp syn wait 5MS }",
            "Keywords in FrameAssembly 2.0 are strictly lowercase without '_' or '-': replace 'MS' with 'ms'.",
        ),
        (
            "host a { ip 10.0.0.1 }\nflow f(x, y) { x -> y icmp }\ncompile { loop 2 { f(a, a) } }",
            "The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile { ... }'.",
        ),
    ];

    for (src, expected_help) in cases {
        let err = parse_program(src).unwrap_err();
        let help = err.help().expect("expected help string").to_string();
        assert_eq!(help, expected_help, "unexpected help for `{src}`");
    }
}

/// Tests CRLF line endings and GRE sequence number (`seq`) field population.
#[test]
fn test_crlf_and_gre_seq_parsing() {
    let input = "host r1 { ip 10.0.0.1 }\r\nhost r2 { ip 10.0.0.2 }\r\nflow f(a, b) {\r\n    a -> b gre key 100 seq 5 checksum\r\n}\r\ncompile { f(r1, r2) }\r\n";
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

/// Verifies that user-defined host, flow, and parameter identifiers resolve case-insensitively
/// while preserving string literal casing in wire output.
#[test]
fn test_user_identifier_case_insensitivity_and_wire_equivalence() {
    let lower_ids = r#"
        host client { ip 10.0.0.1 mac 00:11:22:33:44:01 }
        host server { ip 10.0.0.2 mac 00:11:22:33:44:02 }
        flow session(c, s) {
            c -> s tcp syn srcport 50000 dstport 80 window 64240 mss 1460
            s -> c tcp syn ack window 65535 wait 1ms
            c -> s tcp ack wait 500us
            c -> s http get uri "/Api/V1/Status" hosthdr "Example.COM" wait 2ms
            s -> c http status 200 reason "OK" body "{\"Status\":\"Healthy\"}" wait 1s
            c -> s dns query txid 0x1a2b qname "api.example.com" qtype "AAAA"
        }
        compile {
            session(client, server)
            session(client, server)
        }
    "#;

    let mixed_ids = r#"
        host Client { ip 10.0.0.1 mac 00:11:22:33:44:01 }
        host sErVeR { ip 10.0.0.2 mac 00:11:22:33:44:02 }
        flow Session(C, S) {
            c -> S tcp syn srcport 50000 dstport 80 window 64240 mss 1460
            S -> C tcp syn ack window 65535 wait 1ms
            C -> s tcp ack wait 500us
            c -> s http get uri "/Api/V1/Status" hosthdr "Example.COM" wait 2ms
            s -> c http status 200 reason "OK" body "{\"Status\":\"Healthy\"}" wait 1s
            C -> S dns query txid 0x1a2b qname "api.example.com" qtype "AaAa"
        }
        compile {
            sEsSiOn(cLiEnT, SeRvEr)
            Session(CLIENT, server)
        }
    "#;

    let prog_lower = parse_program(lower_ids).unwrap();
    let prog_mixed = parse_program(mixed_ids).unwrap();

    let packets_lower = crate::backend::compile_program(&prog_lower).unwrap();
    let packets_mixed = crate::backend::compile_program(&prog_mixed).unwrap();

    assert_eq!(packets_lower.len(), 12);
    assert_eq!(packets_lower, packets_mixed);
}

/// Verifies case-insensitive duplicate `host`, `flow`, and flow parameter semantic errors.
#[test]
fn test_case_insensitive_duplicate_symbol_errors() {
    let dup_host = r#"
        host Client { ip 10.0.0.1 }
        host cLiEnT { ip 10.0.0.2 }
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
        flow webtraffic(x, y) { x -> y tcp ack }
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
        flow ping(Node, node) { Node -> node icmp echorequest }
        compile { ping(a, a) }
    "#;
    match parse_program(dup_param).unwrap_err() {
        CompilerError::SemanticError { message, .. } => {
            assert!(message.contains("Duplicate parameter"));
        }
        other => panic!(
            "Expected SemanticError for duplicate param, got {:?}",
            other
        ),
    }
}

/// Verifies that colon-separated, hyphen-separated, and Cisco dotted-quad MAC addresses compile to identical wire bytes.
#[test]
fn test_multi_format_mac_wire_equivalence() {
    let colon_fasm = r#"
        host sw1 { ip 10.0.0.1 mac 00:1a:2b:3c:4d:5e }
        host sw2 { ip 10.0.0.2 mac aabb.ccdd.eeff }
        flow check(a, b) {
            a -> b srcmac 00:1a:2b:3c:4d:5e dstmac aa:bb:cc:dd:ee:ff arp request sendermac 00:1a:2b:3c:4d:5e targetmac aa:bb:cc:dd:ee:ff targetip 10.0.0.2
            a -> b stp rootid "00:1a:2b:3c:4d:5e" bridgeid "aa:bb:cc:dd:ee:ff"
        }
        compile { check(sw1, sw2) }
    "#;

    let hyphen_fasm = r#"
        host sw1 { ip 10.0.0.1 mac 00-1A-2B-3C-4D-5E }
        host sw2 { ip 10.0.0.2 mac AA-BB-CC-DD-EE-FF }
        flow check(a, b) {
            a -> b srcmac 00-1A-2B-3C-4D-5E dstmac AA-BB-CC-DD-EE-FF arp request sendermac 00-1A-2B-3C-4D-5E targetmac AA-BB-CC-DD-EE-FF targetip 10.0.0.2
            a -> b stp rootid "00-1A-2B-3C-4D-5E" bridgeid "AA-BB-CC-DD-EE-FF"
        }
        compile { check(sw1, sw2) }
    "#;

    let cisco_fasm = r#"
        host sw1 { ip 10.0.0.1 mac 001a.2b3c.4d5e }
        host sw2 { ip 10.0.0.2 mac aabb.ccdd.eeff }
        flow check(a, b) {
            a -> b srcmac 001a.2b3c.4d5e dstmac aabb.ccdd.eeff arp request sendermac 001a.2b3c.4d5e targetmac aabb.ccdd.eeff targetip 10.0.0.2
            a -> b stp rootid "001a.2b3c.4d5e" bridgeid "aabb.ccdd.eeff"
        }
        compile { check(sw1, sw2) }
    "#;

    let frames_colon =
        crate::backend::compile_program(&parse_program(colon_fasm).unwrap()).unwrap();
    let frames_hyphen =
        crate::backend::compile_program(&parse_program(hyphen_fasm).unwrap()).unwrap();
    let frames_cisco =
        crate::backend::compile_program(&parse_program(cisco_fasm).unwrap()).unwrap();

    assert_eq!(frames_colon, frames_hyphen);
    assert_eq!(frames_colon, frames_cisco);
}

/// Verifies plain-English parser diagnostics for structural traps and networking aliases without compiler jargon.
#[test]
fn test_plain_english_parser_structural_and_networking_hints() {
    use miette::Diagnostic;

    let cases = [
        (
            "host r1 { mac 00:11:22:33:44:55 } flow f(a, b) { a -> b icmp } compile { f(r1, r1) }",
            "requires an 'IP <address>' field",
        ),
        (
            "host r1 {} flow f(a, b) { a -> b icmp } compile { f(r1, r1) }",
            "must specify at least an 'IP <address>' or 'MAC <address>' field",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f { r1 -> r1 icmp } compile { f(r1) }",
            "is missing its endpoint parameter list '(a, b)'",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b icmp }",
            "missing 'compile { ... }' block",
        ),
        (
            "host r1 { ip 10.0.0.1 } r1 -> r1 icmp compile {}",
            "is outside a flow block",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b tcp sport 80 } compile { f(r1, r1) }",
            "srcport <port>",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b tcp dport 443 } compile { f(r1, r1) }",
            "dstport <port>",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b tcp ack 100 } compile { f(r1, r1) }",
            "acknum 100",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b hoplimit 64 icmp } compile { f(r1, r1) }",
            "Use 'ttl <value>'",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b tos 46 icmp } compile { f(r1, r1) }",
            "dscp <0..63>",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b vlan_id 100 icmp } compile { f(r1, r1) }",
            "vlan 100",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b qinq 100 200 icmp } compile { f(r1, r1) }",
            "innervlan",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b http get uri \"/\" host \"example.com\" } compile { f(r1, r1) }",
            "hosthdr",
        ),
        (
            "host r1 { ip 10.0.0.1 } flow f(a, b) { a -> b tcp srcprot 80 } compile { f(r1, r1) }",
            "Did you mean 'srcport'?",
        ),
    ];

    for (src, expected_msg) in cases {
        let err = parse_program(src).unwrap_err();
        let rendered = format!(
            "{} {}",
            err,
            err.help().map(|h| h.to_string()).unwrap_or_default()
        );
        assert!(
            rendered.contains(expected_msg),
            "For input `{src}`, expected `{expected_msg}`, got `{rendered}`"
        );
        assert!(!rendered.contains("AST"));
        assert!(!rendered.contains("Ident("));
        assert!(!rendered.ends_with("Syntax error: "));
    }
}

/// Verifies MAC-only `host` definitions and inline frame statements inside `compile`.
#[test]
fn test_mac_only_hosts_and_inline_compile_statements() {
    let input = r#"
        host sw1 { mac 00:11:22:33:44:01 }
        host sw2 { mac 00:11:22:33:44:02 }
        compile {
            sw1 -> sw2 lldp chassisid "sw1" portid "Gi0/1" ttl 120
            sw1 -> sw2 vlan 100 payload "l2-frame"
        }
    "#;
    let prog = parse_program(input).unwrap();
    assert_eq!(prog.hosts[0].ip, None);
    assert_eq!(prog.hosts[0].mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]));
    assert_eq!(prog.compile_block.len(), 2);
    let packets = crate::backend::compile_program(&prog).unwrap();
    assert_eq!(packets.len(), 2);
}
