//! Unit tests for the FrameAssembly syntactic parser and semantic validation passes.
//!
//! This module verifies string escape sequence decoding (`\r`, `\n`, `\t`, `\xHH`, `\uXXXX`),
//! raw hexadecimal payload parsing (`hexpayload`), top-level `host`, `flow`, and `compile` block
//! parsing, protocol-scoped modifier disambiguation (`whois`, `hellotime`, promoted sub-keywords),
//! self-healing v3.0.0 diagnostics, and spanned semantic diagnostic reporting across out-of-range
//! fields, mixed IPv4/IPv6 endpoints, and duplicate symbol declarations, as well as Wave 2
//! additions including EDNS0/multi-RR DNS records, RIP commands, SMTP data, STUN mapped ports,
//! signed Kerberos/LDAP/NTP fields, CoAP tokens, QUIC 0..=20-byte CIDs, S7comm SZL/areas,
//! numeric Modbus exception codes, BACnet Complex-ACK/Real floats, and empty payload handling.

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
            assert!(message.contains("Duplicate host"));
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
            "Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace 'HOST' with 'host'.",
        ),
        (
            "host a { ip 10.0.0.1 }\ncompile { a -> a icmp echo_request }",
            "Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace 'echo_request' with 'echorequest'.",
        ),
        (
            "host a { ip 10.0.0.1 }\ncompile { a -> a tls client-hello }",
            "Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace 'client-hello' with 'clienthello'.",
        ),
        (
            "host a { ip 10.0.0.1 }\ncompile { a -> a tcp syn wait 5MS }",
            "Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace 'MS' with 'ms'.",
        ),
        (
            "host a { ip 10.0.0.1 }\nflow f(x, y) { x -> y icmp }\ncompile { loop 2 { f(a, a) } }",
            "The 'loop' block was removed in FrameAssembly 2.0: replace 'loop' with 'repeat' (or invoke flows/frames directly inside 'compile { ... }').",
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
            assert!(message.contains("Duplicate host"));
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
            assert!(message.contains("Duplicate flow"));
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
            "requires an 'ip <address>' field",
        ),
        (
            "host r1 {} flow f(a, b) { a -> b icmp } compile { f(r1, r1) }",
            "must specify at least an 'ip <address>' or 'mac <address>' field",
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

/// Verifies UTF-8 BOM skipping, missing-protocol rejection, `wait` overflow handling,
/// beginner diagnostics, and expanded L2/L3/L7 semantic bounds.
#[test]
fn test_bom_missing_protocol_wait_overflow_and_bounds() {
    use miette::Diagnostic;

    // 1. UTF-8 BOM compiles cleanly without shifting byte spans
    let bom_src = "\u{feff}host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b icmp }\n";
    assert!(parse_program(bom_src).is_ok());

    // 2. Standalone vlan / qinq / mpls remain valid, while bare lines without protocol fail cleanly
    for ok_l2 in [
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b vlan 100 }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b qinq 100 innervlan 200 pcp 5 dei 1 }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b mpls 1000 }",
        "host sw1 { mac 00:11:22:33:44:01 }\nhost sw2 { mac 00:11:22:33:44:02 }\ncompile { sw1 -> sw2 lldp ttl 300 }",
    ] {
        assert!(parse_program(ok_l2).is_ok(), "Expected valid program: {ok_l2}");
    }

    for missing_proto in [
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b payload \"hi\" }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b dstport 80 }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b syn }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b transport udp }",
    ] {
        let err = parse_program(missing_proto).unwrap_err();
        assert!(
            err.to_string().contains("missing a protocol keyword"),
            "Unexpected error for `{missing_proto}`: {err}"
        );
    }

    // 3. `wait` overflow and missing-unit hints (zero panic, no bogus `flow call '5'`)
    let overflow_err = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b icmp wait 400000000m }",
    )
    .unwrap_err();
    assert!(overflow_err.to_string().contains("wait duration"));

    let missing_unit_err = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b tcp syn wait 5 }",
    )
    .unwrap_err();
    assert!(missing_unit_err.to_string().contains("missing time unit"));
    assert!(!missing_unit_err.to_string().contains("flow call"));

    // 4. Beginner diagnostics (`port`, raw IP, L4+L7 combo, unquoted `/`, smart quotes, non-hijacked help)
    let port_err = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b tcp port 80 }",
    )
    .unwrap_err();
    assert!(port_err.to_string().contains("dstport"));
    assert!(
        !port_err
            .help()
            .unwrap()
            .to_string()
            .contains("acknum <number>")
    );

    let raw_ip_err = parse_program(
        "host a { ip 10.0.0.1 }\ncompile { 10.0.0.1 -> a icmp }",
    )
    .unwrap_err();
    assert!(raw_ip_err.to_string().contains("Declare a host block first"));

    let multi_proto_err = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b tcp http get }",
    )
    .unwrap_err();
    assert!(multi_proto_err.to_string().contains("Multiple protocols"));

    let unquoted_uri = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b http get uri /index.html }",
    )
    .unwrap_err();
    assert!(unquoted_uri.to_string().contains("double quotes"));

    let smart_quote = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b udp payload \u{201c}hi\u{201d} }",
    )
    .unwrap_err();
    assert!(smart_quote.to_string().contains("smart quotes"));

    // 5. Semantic range and IP-version checks
    let bad_semantic_cases = [
        (
            "host a { ip 2001:db8::1 }\nhost b { ip 2001:db8::2 }\ncompile { a -> b igmp }",
            "requires IPv4 endpoints",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b ndp }",
            "requires IPv6 endpoints",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b mld }",
            "requires IPv6 endpoints",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b qinq 5000 icmp }",
            "QinQ VLAN ID 5000 out of range",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b qinq 100 innervlan 5000 icmp }",
            "QinQ innervlan ID 5000 out of range",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b vlan 100 pcp 8 icmp }",
            "PCP 8 out of range",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b vlan 100 dei 2 icmp }",
            "DEI 2 out of range",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b mpls 2000000 icmp }",
            "MPLS label 2000000 out of range",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b syslog facility 24 msg \"x\" }",
            "Syslog facility 24 out of range",
        ),
        (
            "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b syslog severity 8 msg \"x\" }",
            "Syslog severity 8 out of range",
        ),
    ];
    for (src, expected) in bad_semantic_cases {
        let err = parse_program(src).unwrap_err();
        assert!(
            err.to_string().contains(expected),
            "For `{src}`, expected `{expected}`, got `{err}`"
        );
    }
}

/// Verifies uniform single-line string unescaping (`\0`, `\u{...}`, `\x80..\xff`) and rejection
/// of unknown or malformed escape sequences across all quoted string modifiers.
#[test]
fn test_wave1_string_escapes_and_malformed_escape_errors() {
    use super::ident::unescape_bytes;

    let decoded = unescape_string(r#"a\0b\n\t\"c\"\\\u{1F600}"#).unwrap();
    assert_eq!(decoded, "a\0b\n\t\"c\"\\\u{1F600}");
    assert_eq!(unescape_bytes(r"\xff\x80\0").unwrap(), vec![0xff, 0x80, 0x00]);

    for bad in [r"bad\z", r"bad\x4", r"bad\u12", r"bad\u{}", r"bad\u{D800}", r"bad\"] {
        assert!(unescape_string(bad).is_err(), "expected error for `{bad}`");
        assert!(unescape_bytes(bad).is_err(), "expected error for `{bad}`");
    }

    let ok_prog = parse_program(
        r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s http post uri "/ok" body "{\"k\":\"v\n\"}" comment "step\t1\nok"
            c -> s udp payload "\xff\xfe\0"
        }
        "#,
    )
    .unwrap();
    let RunStatement::Frame(stmt0) = &ok_prog.compile_block[0] else {
        panic!("expected frame");
    };
    assert_eq!(stmt0.comment.as_deref(), Some("step\t1\nok"));
    let RunStatement::Frame(stmt1) = &ok_prog.compile_block[1] else {
        panic!("expected frame");
    };
    assert_eq!(stmt1.payload_bytes.as_deref(), Some(&[0xff, 0xfe, 0x00][..]));

    for bad_src in [
        "host c { ip 10.0.0.1 }\nhost s { ip 10.0.0.2 }\ncompile { c -> s http get body \"bad\\z\" }",
        "host c { ip 10.0.0.1 }\nhost s { ip 10.0.0.2 }\ncompile { c -> s syslog msg \"bad\\u{}\" }",
        "host c { ip 10.0.0.1 }\nhost s { ip 10.0.0.2 }\ncompile { c -> s comment \"bad\\x4\" icmp }",
        "host c { ip 10.0.0.1 }\nhost s { ip 10.0.0.2 }\ncompile { c -> s udp payload \"bad\\q\" }",
    ] {
        let err = parse_program(bad_src).unwrap_err();
        assert!(
            matches!(err, CompilerError::ParseError { .. }),
            "expected ParseError for `{bad_src}`, got {err:?}"
        );
    }
}

/// Verifies `repeat <u64> { ... }`, nested `flow` composition, DFS cycle detection,
/// unshadowed global `host` refs inside flows, and duplicate `ip`/`mac` rejection in `host`.
#[test]
fn test_wave1_repeat_flow_composition_global_hosts_and_host_dups() {
    let prog = parse_program(
        r#"
        host gw { ip 10.0.0.254 }
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        flow sub_ping(src, dst) {
            src -> dst icmp echorequest
            dst -> gw icmp echoreply
        }
        flow session(a, b) {
            repeat 2 {
                sub_ping(a, b)
            }
            a -> s udp
        }
        compile {
            repeat 0 {
                c -> s arp
            }
            repeat 3 {
                session(c, s)
            }
        }
        "#,
    )
    .unwrap();
    // Each session emits 2*2 + 1 = 5 protocols; repeated 3 times = 15.
    assert_eq!(prog.emitted_protocols().len(), 15);
    assert!(matches!(prog.flows[1].body[0], FlowStatement::Repeat { count: 2, .. }));
    assert!(matches!(prog.compile_block[0], RunStatement::Repeat { count: 0, .. }));

    let cycle = r#"
        host a { ip 10.0.0.1 }
        host b { ip 10.0.0.2 }
        flow f1(x, y) { f2(x, y) }
        flow f2(x, y) { f1(x, y) }
        compile { f1(a, b) }
    "#;
    let cyc_err = parse_program(cycle).unwrap_err();
    assert!(
        cyc_err.to_string().contains("Cyclic flow"),
        "got: {cyc_err}"
    );

    let shadow_bad = r#"
        host c { ip 10.0.0.1 }
        host bad { mac 00:11:22:33:44:55 }
        flow f(a) { a -> bad icmp }
        compile { f(c) }
    "#;
    let ip_err = parse_program(shadow_bad).unwrap_err();
    assert!(ip_err.to_string().contains("requires an 'ip <address>'"), "got: {ip_err}");

    for dup_host in [
        "host h { ip 10.0.0.1 ip 10.0.0.2 }\ncompile {}",
        "host h { mac 00:11:22:33:44:01 mac 00:11:22:33:44:02 }\ncompile {}",
    ] {
        let err = parse_program(dup_host).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }
}

/// Verifies fail-closed post-protocol modifier parsing, Wave 1 L2/L3/L4/SCTP modifiers,
/// multi-label MPLS stacks, spanned semantic rejections, and Quick Fix mappings.
#[test]
fn test_wave1_fail_closed_modifiers_mpls_stack_and_quick_fixes() {
    for bad in [
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b udp community \"public\" }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b udp nop }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b arp method \"GET\" }",
    ] {
        let err = parse_program(bad).unwrap_err();
        assert!(
            matches!(err, CompilerError::ParseError { .. }),
            "expected fail-closed ParseError for `{bad}`, got: {err:?}"
        );
    }

    let ok = parse_program(
        r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s mpls 100 exp 5 mplsttl 64 mpls 200 fcs routeralert badipchecksum badchecksum tcp syn sackblock 100 200 sackblock 300 400 tcpmd5 "00112233445566778899aabbccddeeff" tfo "0102030405060708"
            c -> s udp nochecksum
            c -> s sctp shutdowncomplete vtag 0x1234
            c -> s ldap searchreq transport sctp
            c -> s ntp transport tcp
            c -> s ldap transport udp
            c -> s dnp3 response src 1 dst 2
        }
        "#,
    )
    .unwrap();
    let RunStatement::Frame(f0) = &ok.compile_block[0] else {
        panic!("expected frame");
    };
    assert!(f0.l2.fcs);
    assert!(f0.l3.router_alert);
    assert!(f0.l3.bad_ip_checksum);
    assert!(f0.l4.bad_checksum);
    assert_eq!(f0.l2.mpls_stack.len(), 2);
    assert_eq!(f0.l2.mpls_stack[0].bos, Some(0));
    assert_eq!(f0.l2.mpls_stack[1].bos, Some(1));
    assert_eq!(f0.l2.mpls.as_ref().map(|m| m.label), Some(100));
    let opts = f0.l4.tcp_options.as_ref().unwrap();
    assert_eq!(opts.sack_blocks, vec![(100, 200), (300, 400)]);
    assert_eq!(opts.tcp_md5.as_ref().map(Vec::len), Some(16));
    assert_eq!(opts.tfo.as_deref(), Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]));

    for (bad_sem, needle) in [
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b qinq 100 vlan 200 }", "qinq"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b innervlan 200 icmp }", "innervlan"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b pcp 5 icmp }", "pcp"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b dei 1 icmp }", "dei"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b exp 3 icmp }", "mpls"),
        ("host a { ip 2001:db8::1 }\nhost b { ip 2001:db8::2 }\ncompile { a -> b df icmp }", "IPv4"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b flowlabel 1 icmp }", "IPv6"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b fragoffset 9000 icmp }", "fragoffset 9000 out of range"),
        ("host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b tcp nochecksum }", "nochecksum"),
        ("host a { ip 2001:db8::1 }\nhost b { ip 2001:db8::2 }\ncompile { a -> b badipchecksum udp }", "badipchecksum"),
    ] {
        let err = parse_program(bad_sem).unwrap_err();
        assert!(err.to_string().contains(needle), "For `{bad_sem}`, got: {err}");
    }

    for (alias_src, expected_fix) in [
        ("host a { ip 10.0.0.1 }\ncompile { a -> a tds }", "replace 'tds' with 'mssql'"),
        ("host a { ip 10.0.0.1 }\ncompile { a -> a rfb }", "replace 'rfb' with 'vnc'"),
        ("host a { ip 10.0.0.1 }\ncompile { a -> a skinny }", "replace 'skinny' with 'sccp'"),
        ("host a { ip 10.0.0.1 }\ncompile { a -> a knx }", "replace 'knx' with 'knxnetip'"),
    ] {
        let err = parse_program(alias_src).unwrap_err();
        assert!(err.to_string().contains(expected_fix), "got: {err}");
    }

    let ospf_area_err = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b ospf hello area 0.0.0.1 }",
    )
    .unwrap_err();
    let ospf_area_msg = ospf_area_err.to_string();
    assert!(
        ospf_area_msg.contains("unexpected modifier 'area' for protocol 'ospf'")
            && ospf_area_msg.contains("replace 'area' with 'areaid'")
            && !ospf_area_msg.contains("Did you mean 'arp'?"),
        "got: {ospf_area_msg}"
    );
}

/// Tests Wave 2 DNS/mDNS EDNS0 flags (`edns0`, `udpsize`, `dobit`), multi-RR `rdata`, and `SOA`/`SRV`.
#[test]
fn test_wave2_dns_edns0_multi_rdata_soa_srv() {
    let input = r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s dns response txid 42 qname "example.com" qtype "A" rdata "1.2.3.4" rdata "5.6.7.8" edns0 udpsize 4096 dobit
            c -> s mdns response qname "_sip._tcp.local" qtype "SRV" rdata "10 60 5060 sip.local" edns0 udpsize 1472
            c -> s dns response qname "example.com" qtype "SOA" rdata "ns1.example.com hostmaster.example.com 2024010101 3600 600 86400 300"
        }
    "#;
    let prog = parse_program(input).unwrap();
    let RunStatement::Frame(f0) = &prog.compile_block[0] else {
        panic!("expected DNS frame");
    };
    let Some(ProtocolSpec::Dns(dns)) = &f0.protocol_spec else {
        panic!("expected DnsSpec");
    };
    assert!(dns.edns0);
    assert_eq!(dns.udp_size, Some(4096));
    assert!(dns.do_bit);
    assert_eq!(dns.rdata, Some("1.2.3.4"));
    assert_eq!(dns.rdata_list, vec!["1.2.3.4", "5.6.7.8"]);

    let RunStatement::Frame(f1) = &prog.compile_block[1] else {
        panic!("expected mDNS frame");
    };
    let Some(ProtocolSpec::Mdns(mdns)) = &f1.protocol_spec else {
        panic!("expected MdnsSpec");
    };
    assert!(mdns.edns0);
    assert_eq!(mdns.udp_size, Some(1472));
    assert_eq!(mdns.qtype, Some("SRV"));

    let bad_udpsize = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b dns udpsize 70000 }",
    )
    .unwrap_err();
    assert!(matches!(bad_udpsize, CompilerError::ParseError { .. }));

    let bad_multi_ns = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b dns response qname \"example.com\" qtype \"NS\" rdata \"ns1.example.com\" rdata \"bad..ns\" }",
    )
    .unwrap_err();
    assert!(matches!(bad_multi_ns, CompilerError::SemanticError { .. }));
}

/// Tests Wave 2 RIP `command`, SMTP `data`, STUN `xormappedaddr <ip> <port>`, and explicit empty payloads.
#[test]
fn test_wave2_rip_command_smtp_data_stun_port_and_empty_payload() {
    let input = r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s rip command "request" prefix 10.0.0.0 metric 1
            s -> c rip command 2 prefix 10.2.0.0 metric 2
            c -> s smtp data body "Subject: Test\r\n\r\nHello\r\n.\r\n"
            s -> c stun bindingresponse txid 1 xormappedaddr 203.0.113.5 54321
            s -> c stun bindingresponse txid 2 xormappedaddr 203.0.113.6
            c -> s mqtt publish topic "sensors/temp" payload ""
            c -> s websocket text payload ""
        }
    "#;
    let prog = parse_program(input).unwrap();
    let RunStatement::Frame(f0) = &prog.compile_block[0] else {
        panic!("expected frame 0");
    };
    assert!(matches!(
        &f0.protocol_spec,
        Some(ProtocolSpec::Rip(RipSpec { command: Some(RipCommand::Request), .. }))
    ));
    let RunStatement::Frame(f1) = &prog.compile_block[1] else {
        panic!("expected frame 1");
    };
    assert!(matches!(
        &f1.protocol_spec,
        Some(ProtocolSpec::Rip(RipSpec { command: Some(RipCommand::Response), .. }))
    ));
    let RunStatement::Frame(f2) = &prog.compile_block[2] else {
        panic!("expected frame 2");
    };
    assert!(matches!(
        &f2.protocol_spec,
        Some(ProtocolSpec::Smtp(SmtpSpec { cmd: Some("DATA"), .. }))
    ));
    let RunStatement::Frame(f3) = &prog.compile_block[3] else {
        panic!("expected frame 3");
    };
    let Some(ProtocolSpec::Stun(stun3)) = &f3.protocol_spec else {
        panic!("expected StunSpec");
    };
    assert_eq!(stun3.xor_mapped_port, Some(54321));
    let RunStatement::Frame(f4) = &prog.compile_block[4] else {
        panic!("expected frame 4");
    };
    let Some(ProtocolSpec::Stun(stun4)) = &f4.protocol_spec else {
        panic!("expected StunSpec");
    };
    assert_eq!(stun4.xor_mapped_port, None);
    let RunStatement::Frame(f5) = &prog.compile_block[5] else {
        panic!("expected frame 5");
    };
    assert!(matches!(
        &f5.protocol_spec,
        Some(ProtocolSpec::Mqtt(MqttSpec { payload: Some(""), .. }))
    ));
    let RunStatement::Frame(f6) = &prog.compile_block[6] else {
        panic!("expected frame 6");
    };
    assert!(matches!(
        &f6.protocol_spec,
        Some(ProtocolSpec::Websocket(WebsocketSpec { payload: Some(""), .. }))
    ));

    let bad_rip = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b rip command \"invalid\" }",
    )
    .unwrap_err();
    assert!(matches!(bad_rip, CompilerError::ParseError { .. }));

    let bad_stun_port = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b stun bindingresponse xormappedaddr 203.0.113.5 70000 }",
    )
    .unwrap_err();
    assert!(matches!(bad_stun_port, CompilerError::SemanticError { .. }));
}

/// Tests Wave 2 signed integer parsing (`kerberos etype`, `ldap msgid`, `ntp precision`) and bounds.
#[test]
fn test_wave2_signed_kerberos_ldap_ntp_bounds() {
    let prog = parse_program(
        r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s kerberos asreq etype -17
            c -> s ldap bindreq msgid -1
            c -> s ntp vn 4 mode 3 precision -20
            c -> s ntp precision -128
            c -> s ntp precision 127
            c -> s msgid "ID47" syslog pri 34
        }
        "#,
    )
    .unwrap();
    let RunStatement::Frame(f0) = &prog.compile_block[0] else {
        panic!("expected frame 0");
    };
    assert!(matches!(
        &f0.protocol_spec,
        Some(ProtocolSpec::Kerberos(KerberosSpec { etype: Some(-17), .. }))
    ));
    let RunStatement::Frame(f1) = &prog.compile_block[1] else {
        panic!("expected frame 1");
    };
    assert!(matches!(
        &f1.protocol_spec,
        Some(ProtocolSpec::Ldap(LdapSpec { msgid: Some(-1), .. }))
    ));
    let RunStatement::Frame(f2) = &prog.compile_block[2] else {
        panic!("expected frame 2");
    };
    assert!(matches!(
        &f2.protocol_spec,
        Some(ProtocolSpec::Ntp(NtpSpec { precision: Some(-20), .. }))
    ));
    let RunStatement::Frame(f3) = &prog.compile_block[3] else {
        panic!("expected frame 3");
    };
    assert!(matches!(
        &f3.protocol_spec,
        Some(ProtocolSpec::Ntp(NtpSpec { precision: Some(-128), .. }))
    ));
    let RunStatement::Frame(f4) = &prog.compile_block[4] else {
        panic!("expected frame 4");
    };
    assert!(matches!(
        &f4.protocol_spec,
        Some(ProtocolSpec::Ntp(NtpSpec { precision: Some(127), .. }))
    ));

    for bad_ntp in [
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b ntp precision -129 }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b ntp precision 128 }",
    ] {
        let err = parse_program(bad_ntp).unwrap_err();
        assert!(
            err.to_string().contains("-128..=127"),
            "expected precision range error for `{bad_ntp}`, got: {err}"
        );
    }
}

/// Tests Wave 2 CoAP `<= 8`B tokens, QUIC `0..=20`B CID validation, and S7comm `szl` / `area` checks.
#[test]
fn test_wave2_coap_token_quic_cid_and_s7comm_area_szl() {
    let prog = parse_program(
        r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s coap con get token "my_tok12"
            c -> s coap non post token 0x1122334455667788
            c -> s quic initial dcid "" scid "0102030405060708090a0b0c0d0e0f1011121314"
            c -> s quic handshake dcid 0x112233445566778899aa
            c -> s s7comm szl
            c -> s s7comm readvar area "mk" dbnum 0 offset 4 count 2
        }
        "#,
    )
    .unwrap();
    let RunStatement::Frame(f0) = &prog.compile_block[0] else {
        panic!("expected frame 0");
    };
    let Some(ProtocolSpec::Coap(coap0)) = &f0.protocol_spec else {
        panic!("expected CoapSpec");
    };
    assert_eq!(coap0.token_bytes.as_deref(), Some(b"my_tok12".as_slice()));

    let RunStatement::Frame(f1) = &prog.compile_block[1] else {
        panic!("expected frame 1");
    };
    let Some(ProtocolSpec::Coap(coap1)) = &f1.protocol_spec else {
        panic!("expected CoapSpec");
    };
    assert_eq!(coap1.token_bytes.as_ref().map(Vec::len), Some(8));

    let RunStatement::Frame(f2) = &prog.compile_block[2] else {
        panic!("expected frame 2");
    };
    let Some(ProtocolSpec::Quic(q2)) = &f2.protocol_spec else {
        panic!("expected QuicSpec");
    };
    assert_eq!(q2.dcid_bytes.as_deref(), Some(&[][..]));
    assert_eq!(q2.scid_bytes.as_ref().map(Vec::len), Some(20));

    let RunStatement::Frame(f3) = &prog.compile_block[3] else {
        panic!("expected frame 3");
    };
    let Some(ProtocolSpec::Quic(q3)) = &f3.protocol_spec else {
        panic!("expected QuicSpec");
    };
    assert_eq!(q3.dcid_bytes.as_ref().map(Vec::len), Some(10));

    let RunStatement::Frame(f4) = &prog.compile_block[4] else {
        panic!("expected frame 4");
    };
    assert!(matches!(
        &f4.protocol_spec,
        Some(ProtocolSpec::S7comm(S7commSpec { func: Some("SZL"), .. }))
    ));
    let RunStatement::Frame(f5) = &prog.compile_block[5] else {
        panic!("expected frame 5");
    };
    assert!(matches!(
        &f5.protocol_spec,
        Some(ProtocolSpec::S7comm(S7commSpec { area: Some(0x83), .. }))
    ));

    for bad in [
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b coap token \"123456789\" }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b coap token 0x112233445566778899 }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b quic initial dcid \"00112233445566778899aabbccddeeff0011223344\" }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b quic initial scid \"abc\" }",
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b s7comm area \"BOGUS\" }",
    ] {
        let err = parse_program(bad).unwrap_err();
        assert!(
            matches!(err, CompilerError::ParseError { .. }),
            "expected ParseError for `{bad}`, got: {err:?}"
        );
    }

    let bad_s7_num = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b s7comm area 300 }",
    )
    .unwrap_err();
    assert!(matches!(bad_s7_num, CompilerError::SemanticError { .. }));
}

/// Tests Wave 2 OT parser additions: numeric Modbus FCs / `errcode`, BACnet `complexack` / `real`, and OPC UA / EtherNet/IP.
#[test]
fn test_wave2_ot_modbus_bacnet_opcua_ethernetip() {
    let prog = parse_program(
        r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s modbus func 43 addr 1
            s -> c modbus func 0x83 errcode 2 isresponse
            s -> c bacnet complexack writeproperty real 72.5
            c -> s bacnet writeproperty real -12.5
            s -> c bacnet complexack real "-3.25"
            c -> s bacnet real 23
            c -> s opcua msgtype "MSG" nodeid 631
            c -> s ethernetip listservices
        }
        "#,
    )
    .unwrap();
    let RunStatement::Frame(f0) = &prog.compile_block[0] else {
        panic!("expected frame 0");
    };
    assert!(matches!(
        &f0.protocol_spec,
        Some(ProtocolSpec::Modbus(ModbusSpec { func: Some("43"), .. }))
    ));
    let RunStatement::Frame(f1) = &prog.compile_block[1] else {
        panic!("expected frame 1");
    };
    assert!(matches!(
        &f1.protocol_spec,
        Some(ProtocolSpec::Modbus(ModbusSpec {
            func: Some("0x83"),
            exception_code: Some(2),
            is_response: true,
            ..
        }))
    ));
    let RunStatement::Frame(f2) = &prog.compile_block[2] else {
        panic!("expected frame 2");
    };
    assert!(matches!(
        &f2.protocol_spec,
        Some(ProtocolSpec::Bacnet(BacnetSpec {
            is_complex_ack: true,
            is_write_property: true,
            real_value: Some(b),
            ..
        })) if *b == 72.5_f32.to_bits()
    ));
    let RunStatement::Frame(f3) = &prog.compile_block[3] else {
        panic!("expected frame 3");
    };
    assert!(matches!(
        &f3.protocol_spec,
        Some(ProtocolSpec::Bacnet(BacnetSpec {
            real_value: Some(b),
            ..
        })) if *b == (-12.5_f32).to_bits()
    ));
    let RunStatement::Frame(f4) = &prog.compile_block[4] else {
        panic!("expected frame 4");
    };
    assert!(matches!(
        &f4.protocol_spec,
        Some(ProtocolSpec::Bacnet(BacnetSpec {
            real_value: Some(b),
            ..
        })) if *b == (-3.25_f32).to_bits()
    ));
    let RunStatement::Frame(f5) = &prog.compile_block[5] else {
        panic!("expected frame 5");
    };
    assert!(matches!(
        &f5.protocol_spec,
        Some(ProtocolSpec::Bacnet(BacnetSpec {
            real_value: Some(b),
            ..
        })) if *b == 23.0_f32.to_bits()
    ));
    let RunStatement::Frame(f6) = &prog.compile_block[6] else {
        panic!("expected frame 6");
    };
    assert!(matches!(
        &f6.protocol_spec,
        Some(ProtocolSpec::Opcua(OpcuaSpec { node_id: Some("631"), .. }))
    ));

    let bad_modbus_exc = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b modbus errcode 300 }",
    )
    .unwrap_err();
    assert!(matches!(bad_modbus_exc, CompilerError::SemanticError { .. }));

    let bad_bacnet_real = parse_program(
        "host a { ip 10.0.0.1 }\nhost b { ip 10.0.0.2 }\ncompile { a -> b bacnet real \"nan\" }",
    )
    .unwrap_err();
    assert!(matches!(bad_bacnet_real, CompilerError::ParseError { .. }));

    let udp_ctrl_nochecksum = parse_program(
        r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s rip request nochecksum
            c -> s hsrp group 1 nochecksum
            c -> s bfd mydisc 1 nochecksum
        }
        "#,
    )
    .unwrap();
    assert_eq!(udp_ctrl_nochecksum.compile_block.len(), 3);
}
