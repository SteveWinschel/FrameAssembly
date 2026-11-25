//! Unit tests for the FrameAssembly backend evaluation and PCAPNG emission engine.
//!
//! This test suite verifies host endpoint resolution from environment bindings, RFC 1112 IPv4
//! and RFC 2464 IPv6 multicast MAC address derivation, deterministic unicast MAC fallbacks,
//! default destination port mappings across Layer 2 through Layer 7 protocols, TCP/UDP transport
//! selection, and end-to-end PCAPNG file generation.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Tests endpoint resolution from the environment mapping.
#[test]
fn test_resolve_endpoint_success() {
    let mut env = HashMap::new();
    let host = HostDef {
        name: "node_a",
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        span: (0, 10),
    };
    env.insert("node_a", host.clone());

    let arg = Argument::Variable("node_a");
    let resolved = resolve_endpoint(&arg, &env).expect("Failed to resolve defined host");
    assert_eq!(resolved.name, "node_a");
    assert_eq!(
        resolved.ip,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
    );
    assert_eq!(resolved.mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
}

/// Tests that resolving an undefined variable returns an error.
#[test]
fn test_resolve_endpoint_undefined_error() {
    let env = HashMap::new();
    let arg = Argument::Variable("unknown_node");
    let result = resolve_endpoint(&arg, &env);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Undefined variable"));
}

/// Tests that an explicit statement-level MAC override takes highest precedence.
#[test]
fn test_derive_mac_statement_override() {
    let stmt_mac = Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    let host_mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let derived = derive_mac(host_mac, stmt_mac, ip, true);
    assert_eq!(derived, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
}

/// Tests that host-level configured MAC is used when no statement override is present.
#[test]
fn test_derive_mac_host_fallback() {
    let stmt_mac = None;
    let host_mac = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let derived = derive_mac(host_mac, stmt_mac, ip, true);
    assert_eq!(derived, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

/// Tests RFC 1112 IPv4 multicast MAC derivation (01:00:5E + low 23 bits of IP).
#[test]
fn test_derive_mac_ipv4_multicast_rfc1112() {
    // 224.0.0.1 -> 01:00:5e:00:00:01
    let mcast_ip1 = Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)));
    let mac1 = derive_mac(None, None, mcast_ip1, false);
    assert_eq!(mac1, [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);

    // 239.255.1.2 -> 01:00:5e:7f:01:02 (255 & 0x7F = 0x7F)
    let mcast_ip2 = Some(IpAddr::V4(Ipv4Addr::new(239, 255, 1, 2)));
    let mac2 = derive_mac(None, None, mcast_ip2, false);
    assert_eq!(mac2, [0x01, 0x00, 0x5E, 0x7F, 0x01, 0x02]);
}

/// Tests RFC 2464 IPv6 multicast MAC derivation (33:33 + low 32 bits of IPv6).
#[test]
fn test_derive_mac_ipv6_multicast_rfc2464() {
    // ff02::1 -> 33:33:00:00:00:01
    let mcast_v6 = Some(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)));
    let mac = derive_mac(None, None, mcast_v6, false);
    assert_eq!(mac, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
}

/// Tests deterministic unicast default MAC derivation for caller and callee endpoints.
#[test]
fn test_derive_mac_unicast_defaults() {
    let caller_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let callee_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));

    let caller_mac = derive_mac(None, None, caller_ip, true);
    let callee_mac = derive_mac(None, None, callee_ip, false);

    assert_eq!(caller_mac, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(callee_mac, [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    assert_eq!(
        derive_mac(None, None, None, true),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
    );
    assert_eq!(
        derive_mac(None, None, None, false),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
    );
}

/// Tests standard default destination port assignment across diverse protocol categories.
#[test]
fn test_default_dst_port_mappings() {
    assert_eq!(default_dst_port(&Protocol::Dns, None), 53);
    assert_eq!(default_dst_port(&Protocol::Dhcp, None), 67);
    assert_eq!(default_dst_port(&Protocol::Ntp, None), 123);
    assert_eq!(default_dst_port(&Protocol::Http, None), 80);
    assert_eq!(default_dst_port(&Protocol::Http2, None), 443);
    assert_eq!(default_dst_port(&Protocol::Bgp, None), 179);
    assert_eq!(default_dst_port(&Protocol::Vxlan, None), 4789);
    assert_eq!(default_dst_port(&Protocol::Wireguard, None), 51820);
    assert_eq!(default_dst_port(&Protocol::Modbus, None), 502);

    // SNMP Trap vs Get port
    assert_eq!(default_dst_port(&Protocol::Snmp1, Some(&SnmpPduType::Trap)), 162);
    assert_eq!(default_dst_port(&Protocol::Snmp2, Some(&SnmpPduType::Get)), 161);

    // L2 / L3 header protocols return 0
    assert_eq!(default_dst_port(&Protocol::Arp, None), 0);
    assert_eq!(default_dst_port(&Protocol::Icmp, None), 0);
    assert_eq!(default_dst_port(&Protocol::Ospf, None), 0);
}

/// Tests TCP protocol categorization and transport override logic.
#[test]
fn test_is_tcp_protocol_logic() {
    // Native TCP protocols
    assert!(is_tcp_protocol(&Protocol::Tcp, None));
    assert!(is_tcp_protocol(&Protocol::Bgp, None));
    assert!(is_tcp_protocol(&Protocol::Http, None));
    assert!(is_tcp_protocol(&Protocol::Ssh, None));

    // Dual-personality protocols: default TCP, override to UDP
    assert!(is_tcp_protocol(&Protocol::Modbus, None));
    assert!(!is_tcp_protocol(&Protocol::Modbus, Some(TransportProto::Udp)));

    // Default UDP protocols: default UDP, override to TCP
    assert!(!is_tcp_protocol(&Protocol::Dns, None));
    assert!(is_tcp_protocol(&Protocol::Dns, Some(TransportProto::Tcp)));
}

/// Tests complete end-to-end PCAP file generation through `generate_pcap`.
#[test]
fn test_generate_pcap_end_to_end() {
    let dsl = r#"
host client { ip 10.0.0.1 mac 00:11:22:33:44:55 }
host server { ip 10.0.0.2 mac 00:aa:bb:cc:dd:ee }

flow test_flow(c, s) {
    c -> s udp dstport 8080 srcport 5000 payload "FrameAssembly Test"
}

compile {
    test_flow(client, server)
}
"#;
    let program = crate::parser::parse_program(dsl).expect("Failed to parse valid DSL");

    let temp_dir = std::env::temp_dir();
    let temp_pcap = temp_dir.join(format!(
        "test_frameassembly_backend_{}.pcap",
        std::process::id()
    ));
    let pcap_path = temp_pcap.to_str().expect("Valid path");

    let result = generate_pcap(&program, pcap_path);
    assert!(result.is_ok(), "generate_pcap failed: {:?}", result.err());

    // Verify file exists and is non-empty
    let metadata = std::fs::metadata(&temp_pcap).expect("PCAP file must exist");
    assert!(metadata.len() > 24, "PCAP must contain global header and packets");

    // Clean up
    let _ = std::fs::remove_file(&temp_pcap);
}

/// Tests broadcast IPv4 MAC mapping, SCTP L4 transport exclusion, and emitted frame limit guard.
#[test]
fn test_v33_broadcast_mac_sctp_transport_and_repeat_cap() {
    let bcast_ip = Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
    assert_eq!(derive_mac(None, None, bcast_ip, false), [0xFF; 6]);
    assert!(!is_tcp_protocol(&Protocol::Http, Some(TransportProto::Sctp)));
    assert!(!is_tcp_protocol(&Protocol::Dns, Some(TransportProto::Sctp)));

    let ok_dsl = r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s udp comment "repeat probe"
        }
    "#;
    let mut prog = crate::parser::parse_program(ok_dsl).expect("base program should parse");
    let frame_item = prog.compile_block.pop().expect("one frame");
    prog.compile_block.push(RunStatement::Repeat {
        count: (MAX_EMITTED_FRAMES as u64) + 1,
        body: vec![match frame_item {
            RunStatement::Frame(s) => RunStatement::Frame(s),
            other => other,
        }],
        span: (0, 10),
    });
    let err = compile_program_with_metadata(&prog)
        .expect_err("Should reject exceeding MAX_EMITTED_FRAMES");
    assert!(err.contains("100000"));
}

/// Tests TCP high-water sequence tracking, post-teardown port rotation, s -> c reply ports,
/// SCTP L7 carrier, RFC TTL defaults, and PCAPNG metadata propagation.
#[test]
fn test_v33_tcp_state_reply_ports_ttl_and_metadata() {
    let dsl = r#"
        host c { ip 10.0.0.1 }
        host s { ip 10.0.0.2 }
        compile {
            c -> s tcp syn
            c -> s tcp psh ack payload "hello!"
            c -> s tcp psh ack seq 1001 payload "hello!"
            c -> s tcp psh ack
            c -> s tcp fin ack
            c -> s tcp syn comment "reopen"
            c -> s radius accessrequest id 1 user "alice"
            s -> c radius accessaccept id 1
            c -> s ospf hello
            c -> s http transport sctp
        }
    "#;
    let prog = crate::parser::parse_program(dsl).expect("v3.3 DSL should parse");
    let (frames, hosts) = compile_program_with_metadata(&prog).expect("v3.3 program should compile");
    assert_eq!(frames.len(), 10);
    assert_eq!(hosts.len(), 2);
    // Frame 3 after rexmit preserves high-water mark (1001 + 6 = 1007)
    let data2_seq = u32::from_be_bytes(frames[3].data[38..42].try_into().unwrap());
    assert_eq!(data2_seq, 1007);
    // Frame 5 fresh SYN after FIN rotates client port 12345 -> 12346 and resets ISN to 1000
    let syn2_sport = u16::from_be_bytes(frames[5].data[34..36].try_into().unwrap());
    let syn2_seq = u32::from_be_bytes(frames[5].data[38..42].try_into().unwrap());
    assert_eq!((syn2_sport, syn2_seq), (12346, 1000));
    assert_eq!(frames[5].comment.as_deref(), Some("reopen"));
    // Frame 7 s -> c RADIUS reply keeps srcport 1812 without clobbering dstport
    let rad_sport = u16::from_be_bytes(frames[7].data[34..36].try_into().unwrap());
    let rad_dport = u16::from_be_bytes(frames[7].data[36..38].try_into().unwrap());
    assert_eq!((rad_sport, rad_dport), (1812, 12345));
    // Frame 8 OSPF omitted TTL defaults to 1
    assert_eq!(frames[8].data[22], 1);
    // Frame 9 HTTP over SCTP emits IP protocol 132
    assert_eq!(frames[9].data[23], 132);
}
