//! Unit tests for the FrameAssembly backend PCAP emission engine.
//!
//! Tests endpoint resolution, RFC-compliant multicast/unicast MAC derivation,
//! transport protocol defaults, destination port mappings, and PCAP file generation.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Tests endpoint resolution from the environment mapping.
#[test]
fn test_resolve_endpoint_success() {
    let mut env = HashMap::new();
    let host = HostDef {
        name: "node_a",
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        span: (0, 10),
    };
    env.insert("node_a", host.clone());

    let arg = Argument::Variable("node_a");
    let resolved = resolve_endpoint(&arg, &env).expect("Failed to resolve defined host");
    assert_eq!(resolved.name, "node_a");
    assert_eq!(resolved.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
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
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let derived = derive_mac(host_mac, stmt_mac, ip, true);
    assert_eq!(derived, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
}

/// Tests that host-level configured MAC is used when no statement override is present.
#[test]
fn test_derive_mac_host_fallback() {
    let stmt_mac = None;
    let host_mac = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let derived = derive_mac(host_mac, stmt_mac, ip, true);
    assert_eq!(derived, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

/// Tests RFC 1112 IPv4 multicast MAC derivation (01:00:5E + low 23 bits of IP).
#[test]
fn test_derive_mac_ipv4_multicast_rfc1112() {
    // 224.0.0.1 -> 01:00:5e:00:00:01
    let mcast_ip1 = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    let mac1 = derive_mac(None, None, mcast_ip1, false);
    assert_eq!(mac1, [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);

    // 239.255.1.2 -> 01:00:5e:7f:01:02 (255 & 0x7F = 0x7F)
    let mcast_ip2 = IpAddr::V4(Ipv4Addr::new(239, 255, 1, 2));
    let mac2 = derive_mac(None, None, mcast_ip2, false);
    assert_eq!(mac2, [0x01, 0x00, 0x5E, 0x7F, 0x01, 0x02]);
}

/// Tests RFC 2464 IPv6 multicast MAC derivation (33:33 + low 32 bits of IPv6).
#[test]
fn test_derive_mac_ipv6_multicast_rfc2464() {
    // ff02::1 -> 33:33:00:00:00:01
    let mcast_v6 = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
    let mac = derive_mac(None, None, mcast_v6, false);
    assert_eq!(mac, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
}

/// Tests deterministic unicast default MAC derivation for caller and callee endpoints.
#[test]
fn test_derive_mac_unicast_defaults() {
    let caller_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let callee_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    let caller_mac = derive_mac(None, None, caller_ip, true);
    let callee_mac = derive_mac(None, None, callee_ip, false);

    assert_eq!(caller_mac, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(callee_mac, [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
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
HOST client { IP 10.0.0.1 MAC 00:11:22:33:44:55 }
HOST server { IP 10.0.0.2 MAC 00:aa:bb:cc:dd:ee }

FLOW test_flow(c, s) {
    c -> s UDP DSTPORT 8080 SRCPORT 5000 PAYLOAD "FrameAssembly Test"
}

COMPILE {
    test_flow(client, server)
}
"#;
    let program = crate::parser::parse_program(dsl).expect("Failed to parse valid DSL");

    let temp_dir = std::env::temp_dir();
    let temp_pcap = temp_dir.join("test_frameassembly_backend.pcap");
    let pcap_path = temp_pcap.to_str().expect("Valid path");

    let result = generate_pcap(&program, pcap_path);
    assert!(result.is_ok(), "generate_pcap failed: {:?}", result.err());

    // Verify file exists and is non-empty
    let metadata = std::fs::metadata(&temp_pcap).expect("PCAP file must exist");
    assert!(metadata.len() > 24, "PCAP must contain global header and packets");

    // Clean up
    let _ = std::fs::remove_file(&temp_pcap);
}
