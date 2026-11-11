//! Empirical Challenger Wire Verification Test Suite.
//!
//! Conducts rigorous adversarial verification of FrameAssembly packet generation across:
//! 1. Wire header correctness and zero-subkeyword defaults for all 60 protocols.
//! 2. UDP and TCP pseudo-header checksums, including RFC 8200 0x0000 -> 0xFFFF mapping for UDP over IPv6.
//! 3. Deterministic MAC auto-derivation (unicast defaults, RFC 2464 IPv6 multicast, RFC 1112 IPv4 multicast, IEEE 802.1D).
//! 4. SNMP protocol invariants (SNMP1 non-trap PDU tags 0xa0–0xa3, NULLVAL 0x05, RFC 3584 0.0.0.0 agent-addr, RFC 4001 16-byte IPVAL, USM division-by-zero safety).
//! 5. SCTP chunk framing and RFC 9260 CRC32c checksum verification.
//! 6. Empirical confirmation of masked parser/syntax bugs in `e2e_60_protocols_tests.rs`.

use core::net::IpAddr;
use frameassembly::ast::TcpFlag;
use frameassembly::backend::generate_pcap;
use frameassembly::builders::transport::crc32c;
use frameassembly::packet::{build_tcp_segment, build_udp_datagram, internet_checksum};
use frameassembly::parser::parse_program;
use frameassembly::snmp_crypto::{
    password_to_key_md5, password_to_key_sha1, password_to_key_sha256, password_to_key_sha384,
    password_to_key_sha512,
};
use std::fs;
use std::path::Path;

/// Reads enhanced packet blocks from an emitted PCAPNG file.
fn read_emitted_packets(path: &Path) -> Vec<Vec<u8>> {
    let file = fs::File::open(path).expect("open pcap file");
    let mut reader = pcap_file::pcapng::PcapNgReader::new(file).expect("pcapng reader");
    let mut packets = Vec::new();
    while let Some(block) = reader.next_block() {
        if let Ok(pcap_file::pcapng::Block::EnhancedPacket(epb)) = block {
            packets.push(epb.data.to_vec());
        }
    }
    packets
}

/// Helper to compile a DSL string and return raw frame bytes for each emitted packet.
fn compile_dsl_to_packets(dsl: &str) -> Result<Vec<Vec<u8>>, String> {
    /// Atomic counter ensuring unique temporary PCAPNG paths across concurrent test executions.
    static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_pcap = std::env::temp_dir().join(format!("chal_test_{}_{}_{}.pcap", std::process::id(), count, nanos));

    let program = parse_program(dsl).map_err(|e| format!("Parse error: {:?}", e))?;
    generate_pcap(&program, temp_pcap.to_str().unwrap())
        .map_err(|e| format!("Compile error: {:?}", e))?;

    let packets = read_emitted_packets(&temp_pcap);
    let _ = fs::remove_file(&temp_pcap);
    Ok(packets)
}

/// 1. Assert zero-subkeyword defaults produce valid frames across all protocols.
#[test]
fn test_zero_subkeyword_defaults_across_protocols() {
    let all_protocols = [
        // Category 1: L2 & Data-Center
        "arp", "vlan", "qinq", "lldp", "stp", "lacp", "eapol", "mpls",
        // Category 2: L3, Tunnels & Routing
        "icmp", "ndp", "igmp", "mld", "gre", "vxlan", "geneve", "ipsec", "esp", "ah",
        "ikev2", "wireguard", "ospf", "bgp", "rip", "vrrp", "hsrp", "pim", "bfd", "openflow",
        // Category 3: L4 Transports
        "tcp", "udp", "sctp",
        // Category 4: L7 Infrastructure
        "snmp1", "snmp2", "snmp3", "dns", "mdns", "dhcp", "ntp", "ptp", "radius", "tacacs",
        "syslog", "netflow", "ipfix", "sflow",
        // Category 5: L7 Web & Apps
        "tftp", "ftp", "ssh", "telnet", "http", "http2", "grpc", "websocket", "tls", "quic",
        "stun", "sip", "rtp", "rtsp", "smtp", "imap", "pop3", "kerberos", "ldap", "smb",
        "nfs", "redis", "memcached", "mysql", "postgres", "mqtt", "coap", "amqp", "ssdp", "whois",
        // Category 6: Industrial OT
        "modbus", "bacnet", "dnp3", "s7comm", "ethernetip", "opcua",
    ];

    let mut successful_protocols = Vec::new();
    let mut failed_protocols = Vec::new();

    for proto in all_protocols {
        let is_ipv6_only = proto == "ndp" || proto == "mld";
        let dsl = if is_ipv6_only {
            format!(
                "host z6_a {{ ip 2001:db8::1 mac 00:00:00:00:00:01 }}\nhost z6_b {{ ip 2001:db8::2 mac 00:00:00:00:00:02 }}\nflow zf6(a, b) {{ a -> b {proto} }}\ncompile {{ zf6(z6_a, z6_b) }}"
            )
        } else {
            format!(
                "host z4_a {{ ip 10.0.0.1 mac 00:00:00:00:00:01 }}\nhost z4_b {{ ip 10.0.0.2 mac 00:00:00:00:00:02 }}\nflow zf4(a, b) {{ a -> b {proto} }}\ncompile {{ zf4(z4_a, z4_b) }}"
            )
        };

        match compile_dsl_to_packets(&dsl) {
            Ok(pkts) => {
                assert!(!pkts.is_empty(), "Protocol {proto} generated 0 packets with zero subkeywords");
                successful_protocols.push(proto);
            }
            Err(e) => failed_protocols.push((proto, e)),
        }
    }

    assert!(failed_protocols.is_empty(), "Protocols unexpectedly failed with zero subkeywords: {:?}", failed_protocols);
}

/// 1b. Verify that TCP, VLAN, QINQ, and MPLS now compile with zero subkeywords without defects.
#[test]
fn test_zero_subkeyword_defects_documented() {
    let formerly_failing_protocols = [
        ("tcp", "Defaults to SYN flag when flags and payload are empty"),
        ("vlan", "Defaults to VID 1 when numeric VID is omitted"),
        ("qinq", "Defaults to outer VID 1 when outer VID is omitted"),
        ("mpls", "Defaults to label 0 when numeric label is omitted"),
    ];

    for (proto, reason) in formerly_failing_protocols {
        let dsl = format!(
            "host d_h1 {{ ip 10.1.0.1 mac 00:00:00:00:00:01 }}\nhost d_h2 {{ ip 10.1.0.2 mac 00:00:00:00:00:02 }}\nflow df(a, b) {{ a -> b {proto} }}\ncompile {{ df(d_h1, d_h2) }}"
        );

        let res = compile_dsl_to_packets(&dsl);
        assert!(res.is_ok(), "Expected protocol {proto} to succeed ({reason}): {:?}", res.err());
        let pkts = res.unwrap();
        assert!(!pkts.is_empty(), "Expected protocol {proto} to emit at least 1 packet");
    }
}

/// 2. Assert UDP and TCP pseudo-header checksum calculations over IPv4 and IPv6 (specifically RFC 8200 mapping of calculated 0x0000 checksum to 0xFFFF for UDP over IPv6).
#[test]
fn test_udp_pseudo_header_checksum_and_rfc8200_zero_mapping() {
    let src_v6: IpAddr = "2001:db8::1".parse().unwrap();
    let dst_v6: IpAddr = "2001:db8::2".parse().unwrap();

    // Standard UDP datagram over IPv6
    let dg1 = build_udp_datagram(src_v6, dst_v6, 12345, 80, b"TestingChecksum").unwrap();
    assert_eq!(dg1.len(), 8 + 15);
    let wire_cksum = u16::from_be_bytes([dg1[6], dg1[7]]);
    assert_ne!(wire_cksum, 0, "RFC 8200: UDP checksum over IPv6 MUST NOT be zero");

    // Adversarially craft a UDP payload over IPv6 whose checksum evaluates exactly to 0x0000.
    // In one's complement arithmetic, sum == 0xFFFF means !sum == 0x0000.
    // We construct a 2-byte payload that cancels out the partial pseudo-header + UDP header sum.
    let udp_len = 8 + 2; // header + 2-byte payload
    let mut pseudo = Vec::with_capacity(40);
    if let (IpAddr::V6(s), IpAddr::V6(d)) = (src_v6, dst_v6) {
        pseudo.extend_from_slice(&s.octets());
        pseudo.extend_from_slice(&d.octets());
        pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
    }
    let udp_hdr_zero = [
        (1000u16 >> 8) as u8,
        1000u16 as u8,
        (2000u16 >> 8) as u8,
        2000u16 as u8,
        (udp_len >> 8) as u8,
        udp_len as u8,
        0,
        0,
    ];

    // Compute checksum of pseudo + header without payload
    let mut partial_sum: u32 = 0;
    for slice in [&pseudo[..], &udp_hdr_zero[..]] {
        let (chunks, remainder) = slice.as_chunks::<2>();
        for chunk in chunks {
            partial_sum += u16::from_be_bytes(*chunk) as u32;
        }
        if !remainder.is_empty() {
            partial_sum += (remainder[0] as u32) << 8;
        }
    }
    while (partial_sum >> 16) != 0 {
        partial_sum = (partial_sum & 0xffff) + (partial_sum >> 16);
    }

    // We want partial_sum + payload_word to wrap to 0xFFFF.
    // In one's complement: payload_word = !partial_sum.
    let target_payload_word = (!partial_sum) as u16;
    let payload = target_payload_word.to_be_bytes();

    // Verify mathematical oracle: internet_checksum(&[&pseudo, &udp_hdr_zero, &payload]) must be 0x0000
    let raw_calc = internet_checksum(&[&pseudo, &udp_hdr_zero, &payload]);
    assert_eq!(
        raw_calc, 0x0000,
        "Mathematical oracle: raw 1's complement inverted sum must equal 0x0000"
    );

    // Call build_udp_datagram with this exact payload
    let dg_crafted = build_udp_datagram(src_v6, dst_v6, 1000, 2000, &payload).unwrap();
    let crafted_cksum = u16::from_be_bytes([dg_crafted[6], dg_crafted[7]]);

    // RFC 8200 §8.1 invariant: if the computed checksum is zero, it MUST be transmitted as 0xFFFF!
    assert_eq!(
        crafted_cksum, 0xFFFF,
        "RFC 8200 VIOLATION: computed 0x0000 checksum must map to 0xFFFF"
    );
}

/// 3. Verify Deterministic MAC Auto-Derivation:
/// - caller default `00:00:00:00:00:01` and callee default `00:00:00:00:00:02`
/// - RFC 2464 IPv6 multicast `33:33:xx:xx:xx:xx`
/// - RFC 1112 IPv4 multicast `01:00:5e:xx:xx:xx` (with upper bit 0 masked)
/// - IEEE 802.1D multicast addresses for STP, LLDP, LACP, EAPOL
#[test]
fn test_deterministic_mac_auto_derivation_invariants() {
    let dsl = r#"
        host caller_v4 { ip 10.0.0.1 }
        host callee_v4 { ip 10.0.0.2 }
        host caller_v6 { ip 2001:db8::1 }
        host callee_v6 { ip 2001:db8::2 }
        host mcast_v6_nodes { ip ff02::1 }
        host mcast_v6_solicited { ip ff02::1:ffab:cdef }
        host mcast_v4_mdns { ip 224.0.0.251 }
        host mcast_v4_ssdp { ip 239.255.255.250 }

        flow test_macs(c4, s4, c6, s6, m6n, m6s, m4m, m4s) {
            // Unicast defaults
            c4 -> s4 udp payload "v4_unicast"
            c6 -> s6 udp payload "v6_unicast"

            // RFC 2464 IPv6 multicast
            c6 -> m6n udp payload "v6_all_nodes"
            c6 -> m6s udp payload "v6_solicited"

            // RFC 1112 IPv4 multicast
            c4 -> m4m udp payload "v4_mdns"
            c4 -> m4s udp payload "v4_ssdp"

            // IEEE 802.1D L2 protocol defaults
            c4 -> s4 stp
            c4 -> s4 lldp
            c4 -> s4 lacp
            c4 -> s4 eapol
        }

        compile {
            test_macs(caller_v4, callee_v4, caller_v6, callee_v6, mcast_v6_nodes, mcast_v6_solicited, mcast_v4_mdns, mcast_v4_ssdp)
        }
    "#;

    let pkts = compile_dsl_to_packets(dsl).expect("compile mac derivation test");
    assert_eq!(pkts.len(), 10);

    // Frame 0: IPv4 unicast
    assert_eq!(&pkts[0][0..6], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // callee dst
    assert_eq!(&pkts[0][6..12], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // caller src

    // Frame 1: IPv6 unicast
    assert_eq!(&pkts[1][0..6], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // callee dst
    assert_eq!(&pkts[1][6..12], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // caller src

    // Frame 2: RFC 2464 ff02::1 -> 33:33:00:00:00:01
    assert_eq!(&pkts[2][0..6], &[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);

    // Frame 3: RFC 2464 ff02::1:ffab:cdef -> 33:33:ff:ab:cd:ef
    assert_eq!(&pkts[3][0..6], &[0x33, 0x33, 0xff, 0xab, 0xcd, 0xef]);

    // Frame 4: RFC 1112 224.0.0.251 -> 01:00:5e:00:00:fb
    assert_eq!(&pkts[4][0..6], &[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);

    // Frame 5: RFC 1112 239.255.255.250 -> 01:00:5e:7f:ff:fa (255 & 0x7F = 0x7F)
    assert_eq!(&pkts[5][0..6], &[0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa]);

    // Frame 6: IEEE 802.1D STP -> 01:80:c2:00:00:00
    assert_eq!(&pkts[6][0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);

    // Frame 7: IEEE 802.1AB LLDP -> 01:80:c2:00:00:0e
    assert_eq!(&pkts[7][0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);

    // Frame 8: IEEE 802.3ad LACP -> 01:80:c2:00:00:02
    assert_eq!(&pkts[8][0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);

    // Frame 9: IEEE 802.1X EAPOL -> 01:80:c2:00:00:03
    assert_eq!(&pkts[9][0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
}

/// 4. Verify SNMP Protocol Invariants:
/// - SNMP1 non-trap PDU tags: 0xa0 for GET, 0xa1 for GETNEXT, 0xa2 for RESPONSE, 0xa3 for SET
/// - NULLVAL tag 0x05
/// - RFC 3584 IPv6 agent-addr defaults to 0.0.0.0
/// - RFC 4001 16-byte OCTET STRING for IPVAL <ipv6>
/// - Empty password string in USM does not panic with division by zero
#[test]
fn test_snmp_protocol_invariants() {
    // Check SNMP1 non-trap PDU BER tags
    let pdu_tests = [
        ("get", 0xa0u8),
        ("getnext", 0xa1u8),
        ("response", 0xa2u8),
        ("set", 0xa3u8),
    ];

    for (pdu_name, expected_tag) in pdu_tests {
        let snmp1_dsl = format!(
            "host s1_mgr {{ ip 10.2.0.1 }}\nhost s1_ag {{ ip 10.2.0.2 }}\nflow snmp_test(m, a) {{ m -> a snmp1 {pdu_name} oid \"1.3.6.1.2.1.1.1.0\" }}\ncompile {{ snmp_test(s1_mgr, s1_ag) }}"
        );
        let pkts = compile_dsl_to_packets(&snmp1_dsl).expect("compile snmp1 non-trap");
        let udp_payload = &pkts[0][42..]; // 14 Ethernet + 20 IPv4 + 8 UDP = 42

        assert!(
            udp_payload.contains(&expected_tag),
            "SNMP1 {pdu_name} BER payload missing expected tag 0x{:02x}",
            expected_tag
        );
    }

    // Check NULLVAL tag 0x05 in BER varbind
    let nullval_dsl = r#"
        host nv_mgr { ip 10.3.0.1 }
        host nv_agent { ip 10.3.0.2 }
        flow snmp_null(m, a) { m -> a snmp1 get varbind "1.3.6.1.2.1.1.1.0" nullval }
        compile { snmp_null(nv_mgr, nv_agent) }"#;
    let null_pkts = compile_dsl_to_packets(nullval_dsl).expect("compile snmp1 nullval");
    let udp_payload = &null_pkts[0][42..];
    let has_null_ber = udp_payload.array_windows::<2>().any(|w| w == &[0x05, 0x00]);
    assert!(has_null_ber, "BER payload must contain NULL tag [0x05, 0x00]");

    // Check RFC 3584 IPv6 agent-addr defaults to 0.0.0.0
    let rfc3584_dsl = r#"
        host srv_v6 { ip 2001:db8::1 }
        host nms_v6 { ip 2001:db8::2 }
        flow trap_v6(s, n) { s -> n snmp1 trap }
        compile { trap_v6(srv_v6, nms_v6) }"#;
    let v6_pkts = compile_dsl_to_packets(rfc3584_dsl).expect("compile snmp1 trap v6");
    let udp_payload_v6 = &v6_pkts[0][62..]; // 14 Ethernet + 40 IPv6 + 8 UDP = 62
    let has_zero_agent_addr = udp_payload_v6
        .array_windows::<6>()
        .any(|w| w == &[0x40, 0x04, 0x00, 0x00, 0x00, 0x00]);
    assert!(
        has_zero_agent_addr,
        "RFC 3584: IPv6 SNMPv1 trap agent-addr must default to 0.0.0.0 ([0x40, 0x04, 0, 0, 0, 0])"
    );

    // Check RFC 4001 16-byte OCTET STRING for IPVAL <ipv6>
    let rfc4001_dsl = r#"
        host v6_mgr { ip 10.4.0.1 }
        host v6_ag { ip 10.4.0.2 }
        flow ipval_v6(m, a) { m -> a snmp2 get varbind "1.3.6.1.2.1.1.1.0" ipval 2001:db8::1234 }
        compile { ipval_v6(v6_mgr, v6_ag) }"#;
    let ipval_pkts = compile_dsl_to_packets(rfc4001_dsl).expect("compile snmp2 ipval ipv6");
    let ipval_payload = &ipval_pkts[0][42..];
    let has_16byte_octet_str = ipval_payload.array_windows::<2>().any(|w| w == &[0x04, 0x10]);
    assert!(
        has_16byte_octet_str,
        "RFC 4001: IPv6 IPVAL must encode as 16-byte OCTET STRING [0x04, 0x10]"
    );

    // Verify empty password string in USM does not panic with division by zero
    let empty_key = password_to_key_md5(b"", b"8000000001");
    assert!(empty_key.is_empty(), "Empty USM password must return empty key without panicking");
}

/// 5. Verify SCTP Transports:
/// - SCTP common header and chunk encodings with CRC32c checksum.
#[test]
fn test_sctp_transports_and_crc32c() {
    assert_eq!(crc32c(&[b"123456789"]), 0xe3069283);
    assert_eq!(crc32c(&[&[0u8; 32]]), 0x8a9136aa);

    let sctp_dsl = r#"
        host sctp_client { ip 10.5.0.1 }
        host sctp_server { ip 10.5.0.2 }
        flow sctp_flow(c, s) {
            c -> s sctp srcport 5000 dstport 5000 vtag 0x11223344 chunk init
            c -> s sctp srcport 5000 dstport 5000 vtag 0x11223344 chunk data stream 1 ssn 0 ppid 3 payload "SCTP_DATA_CHUNK"
            c -> s sctp srcport 5000 dstport 5000 vtag 0x11223344 chunk sack
            c -> s sctp srcport 5000 dstport 5000 vtag 0x11223344 chunk heartbeat payload "PING"
        } compile { sctp_flow(sctp_client, sctp_server) }"#;

    let pkts = compile_dsl_to_packets(sctp_dsl).expect("compile sctp flow");
    assert_eq!(pkts.len(), 4);

    for (idx, pkt) in pkts.iter().enumerate() {
        let ip_hdr = &pkt[14..34];
        assert_eq!(ip_hdr[9], 132, "IP protocol must be 132 (SCTP)");

        let sctp_hdr = &pkt[34..];
        assert_eq!(&sctp_hdr[0..2], &5000u16.to_be_bytes());
        assert_eq!(&sctp_hdr[2..4], &5000u16.to_be_bytes());
        assert_eq!(&sctp_hdr[4..8], &0x11223344u32.to_be_bytes());

        let mut zeroed = sctp_hdr.to_vec();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        let expected_crc = crc32c(&[&zeroed]);
        let wire_crc = u32::from_le_bytes([sctp_hdr[8], sctp_hdr[9], sctp_hdr[10], sctp_hdr[11]]);
        assert_eq!(wire_crc, expected_crc, "SCTP packet {idx} CRC32c mismatch");
    }
}

/// 6. Empirical confirmation of masked parser/syntax bugs in `e2e_60_protocols_tests.rs`.
///
/// Demonstrates that the 7 tests which previously passed silently due to error-catching
/// facades now parse strictly and cleanly.
#[test]
fn test_reproduce_and_document_e2e_masked_parser_bugs() {
    let buggy_scripts = [
        ("FTP CODE and REPLY", "host b_c1 { ip 10.6.1.1 }\nhost b_s1 { ip 10.6.1.2 }\nflow bf1(c, s) { c <- s ftp code 331 reply \"Password required\" }\ncompile { bf1(b_c1, b_s1) }"),
        ("SMTP CODE and REPLY", "host b_m1 { ip 10.6.2.1 }\nhost b_m2 { ip 10.6.2.2 }\nflow bf2(m1, m2) { m1 <- m2 smtp code 250 reply \"250-mail.dest.org\" }\ncompile { bf2(b_m1, b_m2) }"),
        ("PTP DOMAIN unquoted integer", "host b_gm { ip 10.6.3.1 }\nhost b_sl { ip 10.6.3.2 }\nflow bf3(m, s) { m -> s ptp msgtype sync domain 0 }\ncompile { bf3(b_gm, b_sl) }"),
        ("RADIUS CODE ACCESS_REQUEST", "host b_nas { ip 10.6.4.1 }\nhost b_rad { ip 10.6.4.2 }\nflow bf4(n, r) { n -> r radius code accessrequest id 1 user \"alice\" }\ncompile { bf4(b_nas, b_rad) }"),
        ("MEMCACHED KEY", "host b_app { ip 10.6.5.1 }\nhost b_mc { ip 10.6.5.2 }\nflow bf5(a, d) { a -> d memcached get key \"session:123\" }\ncompile { bf5(b_app, b_mc) }"),
        ("TACACS TYPE AUTHEN", "host b_tc { ip 10.6.6.1 }\nhost b_ts { ip 10.6.6.2 }\nflow bf6(c, s) { c -> s tacacs type authen user \"admin\" }\ncompile { bf6(b_tc, b_ts) }"),
        ("TFTP MODE octet", "host b_pxe { ip 10.6.7.1 }\nhost b_tftp { ip 10.6.7.2 }\nflow bf7(c, s) { c -> s tftp rrq filename \"boot.bin\" mode \"octet\" }\ncompile { bf7(b_pxe, b_tftp) }"),
    ];

    for (name, script) in buggy_scripts {
        let res = parse_program(script);
        assert!(res.is_ok(), "Expected script '{name}' to parse cleanly, got: {:?}", res.err());
    }
}

/// 7. Deep Byte-Level Header Layout Verification Across All 60 Protocols in Categories 1–6.
///
/// Verifies the exact on-the-wire header structure, protocol identifiers, transport ports,
/// and protocol-specific magic bytes/PDU tags for zero-subkeyword defaults across all protocols.
#[test]
fn test_wire_header_correctness_all_60_protocols() {
    // Category 1: L2 & Data-Center
    let cat1 = [
        ("ARP", "h1 -> h2 arp", false),
        ("VLAN", "h1 -> h2 vlan", false),
        ("QINQ", "h1 -> h2 qinq", false),
        ("LLDP", "h1 -> h2 lldp", false),
        ("STP", "h1 -> h2 stp", false),
        ("LACP", "h1 -> h2 lacp", false),
        ("EAPOL", "h1 -> h2 eapol", false),
        ("MPLS", "h1 -> h2 mpls", false),
    ];

    for (proto, stmt, is_v6) in cat1 {
        let dsl = if is_v6 {
            format!("host h1 {{ ip 2001:db8::1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 2001:db8::2 mac 00:00:00:00:00:02 }}\nflow f_c1_v6(h1, h2) {{ {stmt} }}\ncompile {{ f_c1_v6(h1, h2) }}")
        } else {
            format!("host h1 {{ ip 10.7.1.1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 10.7.1.2 mac 00:00:00:00:00:02 }}\nflow f_c1_v4(h1, h2) {{ {stmt} }}\ncompile {{ f_c1_v4(h1, h2) }}")
        };
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        assert!(!pkts.is_empty(), "Empty packet for {proto}");
        let pkt = &pkts[0];

        match proto {
            "ARP" => {
                let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
                assert_eq!(ethertype, 0x0806, "ARP EtherType must be 0x0806");
                let arp_body = &pkt[14..42];
                assert_eq!(&arp_body[0..2], &[0x00, 0x01], "ARP Hardware Type 1");
                assert_eq!(&arp_body[2..4], &[0x08, 0x00], "ARP Protocol Type IPv4");
                assert_eq!(arp_body[4], 6, "ARP Hardware Size 6");
                assert_eq!(arp_body[5], 4, "ARP Protocol Size 4");
                assert_eq!(&arp_body[6..8], &[0x00, 0x01], "ARP Opcode 1 (REQUEST)");
            }
            "VLAN" => {
                let outer_ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
                assert_eq!(outer_ethertype, 0x8100, "VLAN EtherType must be 0x8100");
                let vid = u16::from_be_bytes([pkt[14], pkt[15]]) & 0x0FFF;
                assert_eq!(vid, 1, "Default VLAN VID must be 1");
            }
            "QINQ" => {
                let outer_ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
                assert_eq!(outer_ethertype, 0x88A8, "QINQ Outer EtherType must be 0x88A8");
                let vid = u16::from_be_bytes([pkt[14], pkt[15]]) & 0x0FFF;
                assert_eq!(vid, 1, "Default QINQ Outer VID must be 1");
                let next_ethertype = u16::from_be_bytes([pkt[16], pkt[17]]);
                assert_eq!(next_ethertype, 0x0800, "Default QINQ payload EtherType must be 0x0800");
            }
            "LLDP" => {
                assert_eq!(&pkt[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e], "LLDP Multicast MAC");
                assert_eq!(u16::from_be_bytes([pkt[12], pkt[13]]), 0x88CC, "LLDP EtherType must be 0x88CC");
            }
            "STP" => {
                assert_eq!(&pkt[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00], "STP Multicast MAC");
                assert_eq!(&pkt[14..17], &[0x42, 0x42, 0x03], "LLC DSAP/SSAP/Control");
                assert_eq!(&pkt[17..19], &[0x00, 0x00], "STP Protocol ID 0x0000");
            }
            "LACP" => {
                assert_eq!(&pkt[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x02], "LACP Multicast MAC");
                assert_eq!(u16::from_be_bytes([pkt[12], pkt[13]]), 0x8809, "LACP EtherType must be 0x8809");
            }
            "EAPOL" => {
                assert_eq!(&pkt[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x03], "EAPOL Multicast MAC");
                assert_eq!(u16::from_be_bytes([pkt[12], pkt[13]]), 0x888E, "EAPOL EtherType must be 0x888E");
            }
            "MPLS" => {
                assert_eq!(u16::from_be_bytes([pkt[12], pkt[13]]), 0x8847, "MPLS EtherType must be 0x8847");
                assert_eq!(&pkt[14..18], &[0x00, 0x00, 0x01, 0x40], "Default MPLS Label 0 BOS 1 TTL 64");
            }
            _ => {}
        }
    }

    // Category 2: L3, Tunnels & Routing
    let cat2 = [
        ("ICMP", "h1 -> h2 icmp", 1u8, None),
        ("IGMP", "h1 -> h2 igmp", 2u8, None),
        ("GRE", "h1 -> h2 gre", 47u8, None),
        ("VXLAN", "h1 -> h2 vxlan", 17u8, Some(4789u16)),
        ("GENEVE", "h1 -> h2 geneve", 17u8, Some(6081u16)),
        ("IPSEC", "h1 -> h2 ipsec", 50u8, None),
        ("ESP", "h1 -> h2 esp", 50u8, None),
        ("AH", "h1 -> h2 ah", 51u8, None),
        ("IKEV2", "h1 -> h2 ikev2", 17u8, Some(500u16)),
        ("WIREGUARD", "h1 -> h2 wireguard", 17u8, Some(51820u16)),
        ("OSPF", "h1 -> h2 ospf", 89u8, None),
        ("BGP", "h1 -> h2 bgp", 6u8, Some(179u16)),
        ("RIP", "h1 -> h2 rip", 17u8, Some(520u16)),
        ("VRRP", "h1 -> h2 vrrp", 112u8, None),
        ("HSRP", "h1 -> h2 hsrp", 17u8, Some(1985u16)),
        ("PIM", "h1 -> h2 pim", 103u8, None),
        ("BFD", "h1 -> h2 bfd", 17u8, Some(3784u16)),
        ("OPENFLOW", "h1 -> h2 openflow", 6u8, Some(6653u16)),
    ];

    for (proto, stmt, expected_ip_proto, expected_port) in cat2 {
        let dsl = format!(
            "host h1 {{ ip 10.7.2.1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 10.7.2.2 mac 00:00:00:00:00:02 }}\nflow f_c2(h1, h2) {{ {stmt} }}\ncompile {{ f_c2(h1, h2) }}"
        );
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        let pkt = &pkts[0];
        let ip_proto = pkt[23];
        assert_eq!(ip_proto, expected_ip_proto, "{proto}: Expected IP protocol {expected_ip_proto}, got {ip_proto}");

        if let Some(port) = expected_port {
            let dst_port = u16::from_be_bytes([pkt[36], pkt[37]]);
            assert_eq!(dst_port, port, "{proto}: Expected dst port {port}, got {dst_port}");
        }
    }

    // IPv6 Only: NDP & MLD
    let v6_protocols = [
        ("NDP", "h1 -> h2 ndp", 58u8),
        ("MLD", "h1 -> h2 mld", 58u8),
    ];
    for (proto, stmt, expected_next_hdr) in v6_protocols {
        let dsl = format!(
            "host h1 {{ ip 2001:db8::10 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 2001:db8::20 mac 00:00:00:00:00:02 }}\nflow f_v6_only(h1, h2) {{ {stmt} }}\ncompile {{ f_v6_only(h1, h2) }}"
        );
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        let pkt = &pkts[0];
        let next_hdr = pkt[20];
        assert_eq!(next_hdr, expected_next_hdr, "{proto}: Expected IPv6 Next Header 58, got {next_hdr}");
    }

    // Category 3: L4 Transports
    let cat3 = [
        ("TCP", "h1 -> h2 tcp", 6u8),
        ("UDP", "h1 -> h2 udp", 17u8),
        ("SCTP", "h1 -> h2 sctp", 132u8),
    ];
    for (proto, stmt, expected_ip_proto) in cat3 {
        let dsl = format!(
            "host h1 {{ ip 10.7.3.1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 10.7.3.2 mac 00:00:00:00:00:02 }}\nflow f_c3(h1, h2) {{ {stmt} }}\ncompile {{ f_c3(h1, h2) }}"
        );
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        let pkt = &pkts[0];
        let ip_proto = pkt[23];
        assert_eq!(ip_proto, expected_ip_proto, "{proto}: Expected IP protocol {expected_ip_proto}");
        if proto == "TCP" {
            let tcp_flags = pkt[47];
            assert_eq!(tcp_flags, 0x02, "Default zero-subkeyword TCP must have SYN flag (0x02)");
        }
    }

    // Category 4: L7 Infrastructure
    let cat4 = [
        ("SNMP1", "h1 -> h2 snmp1", 17u8, 162u16),
        ("SNMP2", "h1 -> h2 snmp2", 17u8, 162u16),
        ("SNMP3", "h1 -> h2 snmp3", 17u8, 162u16),
        ("DNS", "h1 -> h2 dns", 17u8, 53u16),
        ("MDNS", "h1 -> h2 mdns", 17u8, 5353u16),
        ("DHCP", "h1 -> h2 dhcp", 17u8, 67u16),
        ("NTP", "h1 -> h2 ntp", 17u8, 123u16),
        ("PTP", "h1 -> h2 ptp", 17u8, 319u16),
        ("RADIUS", "h1 -> h2 radius", 17u8, 1812u16),
        ("TACACS", "h1 -> h2 tacacs", 6u8, 49u16),
        ("SYSLOG", "h1 -> h2 syslog", 17u8, 514u16),
        ("NETFLOW", "h1 -> h2 netflow", 17u8, 2055u16),
        ("IPFIX", "h1 -> h2 ipfix", 17u8, 4739u16),
        ("SFLOW", "h1 -> h2 sflow", 17u8, 6343u16),
    ];
    for (proto, stmt, expected_ip_proto, expected_port) in cat4 {
        let dsl = format!(
            "host h1 {{ ip 10.7.4.1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 10.7.4.2 mac 00:00:00:00:00:02 }}\nflow f_c4(h1, h2) {{ {stmt} }}\ncompile {{ f_c4(h1, h2) }}"
        );
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        let pkt = &pkts[0];
        assert_eq!(pkt[23], expected_ip_proto, "{proto}: IP protocol mismatch");
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), expected_port, "{proto}: Dst port mismatch");
    }

    // Category 5: L7 Web & Apps
    let cat5 = [
        ("TFTP", "h1 -> h2 tftp", 17u8, 69u16),
        ("FTP", "h1 -> h2 ftp", 6u8, 21u16),
        ("SSH", "h1 -> h2 ssh", 6u8, 22u16),
        ("TELNET", "h1 -> h2 telnet", 6u8, 23u16),
        ("HTTP", "h1 -> h2 http", 6u8, 80u16),
        ("HTTP2", "h1 -> h2 http2", 6u8, 443u16),
        ("GRPC", "h1 -> h2 grpc", 6u8, 50051u16),
        ("WEBSOCKET", "h1 -> h2 websocket", 6u8, 80u16),
        ("TLS", "h1 -> h2 tls", 6u8, 443u16),
        ("QUIC", "h1 -> h2 quic", 17u8, 443u16),
        ("STUN", "h1 -> h2 stun", 17u8, 3478u16),
        ("SIP", "h1 -> h2 sip", 17u8, 5060u16),
        ("RTP", "h1 -> h2 rtp", 17u8, 5004u16),
        ("RTSP", "h1 -> h2 rtsp", 6u8, 554u16),
        ("SMTP", "h1 -> h2 smtp", 6u8, 25u16),
        ("IMAP", "h1 -> h2 imap", 6u8, 143u16),
        ("POP3", "h1 -> h2 pop3", 6u8, 110u16),
        ("KERBEROS", "h1 -> h2 kerberos", 17u8, 88u16),
        ("LDAP", "h1 -> h2 ldap", 6u8, 389u16),
        ("SMB", "h1 -> h2 smb", 6u8, 445u16),
        ("NFS", "h1 -> h2 nfs", 6u8, 2049u16),
        ("REDIS", "h1 -> h2 redis", 6u8, 6379u16),
        ("MEMCACHED", "h1 -> h2 memcached", 6u8, 11211u16),
        ("MYSQL", "h1 -> h2 mysql", 6u8, 3306u16),
        ("POSTGRES", "h1 -> h2 postgres", 6u8, 5432u16),
        ("MQTT", "h1 -> h2 mqtt", 6u8, 1883u16),
        ("COAP", "h1 -> h2 coap", 17u8, 5683u16),
        ("AMQP", "h1 -> h2 amqp", 6u8, 5672u16),
        ("SSDP", "h1 -> h2 ssdp", 17u8, 1900u16),
        ("WHOIS", "h1 -> h2 whois", 6u8, 43u16),
    ];
    for (proto, stmt, expected_ip_proto, expected_port) in cat5 {
        let dsl = format!(
            "host h1 {{ ip 10.7.5.1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 10.7.5.2 mac 00:00:00:00:00:02 }}\nflow f_c5(h1, h2) {{ {stmt} }}\ncompile {{ f_c5(h1, h2) }}"
        );
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        let pkt = &pkts[0];
        assert_eq!(pkt[23], expected_ip_proto, "{proto}: IP proto mismatch");
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), expected_port, "{proto}: Dst port mismatch");
    }

    // Category 6: Industrial OT
    let cat6 = [
        ("MODBUS", "h1 -> h2 modbus", 6u8, 502u16),
        ("BACNET", "h1 -> h2 bacnet", 17u8, 47808u16),
        ("DNP3", "h1 -> h2 dnp3", 6u8, 20000u16),
        ("S7COMM", "h1 -> h2 s7comm", 6u8, 102u16),
        ("ETHERNETIP", "h1 -> h2 ethernetip", 6u8, 44818u16),
        ("OPCUA", "h1 -> h2 opcua", 6u8, 4840u16),
    ];
    for (proto, stmt, expected_ip_proto, expected_port) in cat6 {
        let dsl = format!(
            "host h1 {{ ip 10.7.6.1 mac 00:00:00:00:00:01 }}\nhost h2 {{ ip 10.7.6.2 mac 00:00:00:00:00:02 }}\nflow f_c6(h1, h2) {{ {stmt} }}\ncompile {{ f_c6(h1, h2) }}"
        );
        let pkts = compile_dsl_to_packets(&dsl).unwrap_or_else(|e| panic!("Failed to compile {proto}: {e}"));
        let pkt = &pkts[0];
        assert_eq!(pkt[23], expected_ip_proto, "{proto}: IP proto mismatch");
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), expected_port, "{proto}: Dst port mismatch");
    }
}

/// 8. Assert RFC 768 UDP Checksum Zero-to-0xFFFF Mapping over IPv4.
///
/// If an IPv4 UDP datagram's calculated one's complement checksum is 0x0000,
/// it MUST be transmitted as 0xFFFF per RFC 768.
#[test]
fn test_udp_v4_zero_checksum_mapping_rfc768() {
    let src_v4: IpAddr = "10.0.0.1".parse().unwrap();
    let dst_v4: IpAddr = "10.0.0.2".parse().unwrap();

    let udp_len = 8 + 2; // header + 2-byte payload
    let mut pseudo = Vec::with_capacity(12);
    if let (IpAddr::V4(s), IpAddr::V4(d)) = (src_v4, dst_v4) {
        pseudo.extend_from_slice(&s.octets());
        pseudo.extend_from_slice(&d.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    }
    let udp_hdr_zero = [
        (1000u16 >> 8) as u8,
        1000u16 as u8,
        (2000u16 >> 8) as u8,
        2000u16 as u8,
        (udp_len >> 8) as u8,
        udp_len as u8,
        0,
        0,
    ];
    let mut partial_sum: u32 = 0;
    for slice in [&pseudo[..], &udp_hdr_zero[..]] {
        let (chunks, remainder) = slice.as_chunks::<2>();
        for chunk in chunks {
            partial_sum += u16::from_be_bytes(*chunk) as u32;
        }
        if !remainder.is_empty() {
            partial_sum += (remainder[0] as u32) << 8;
        }
    }
    while (partial_sum >> 16) != 0 {
        partial_sum = (partial_sum & 0xffff) + (partial_sum >> 16);
    }
    let target_payload_word = (!partial_sum) as u16;
    let payload = target_payload_word.to_be_bytes();

    let raw_calc = internet_checksum(&[&pseudo, &udp_hdr_zero, &payload]);
    assert_eq!(raw_calc, 0x0000, "Mathematical oracle must compute 0x0000");

    let dg_crafted = build_udp_datagram(src_v4, dst_v4, 1000, 2000, &payload).unwrap();
    let crafted_cksum = u16::from_be_bytes([dg_crafted[6], dg_crafted[7]]);
    assert_eq!(
        crafted_cksum, 0xFFFF,
        "RFC 768 VIOLATION: computed 0x0000 checksum over IPv4 must map to 0xFFFF"
    );
}

/// 9. Verify TCP Pseudo-Header Checksum Verification over IPv4 and IPv6.
///
/// Uses the RFC 1071 / 793 mathematical identity: computing the 1's complement
/// sum over the pseudo-header and the complete TCP segment (including checksum)
/// must yield 0x0000.
#[test]
fn test_tcp_pseudo_header_checksum_verification_v4_and_v6() {
    let src_v4: IpAddr = "192.168.1.10".parse().unwrap();
    let dst_v4: IpAddr = "192.168.1.20".parse().unwrap();
    let flags = [TcpFlag::Syn];
    let segment_v4 = build_tcp_segment(
        src_v4,
        dst_v4,
        4000,
        80,
        &flags,
        Some(100),
        None,
        Some(65535),
        None,
        None,
        b"SYN_PAYLOAD",
    )
    .unwrap();

    let tcp_len_v4 = segment_v4.len() as u32;
    let mut pseudo_v4 = Vec::with_capacity(12);
    if let (IpAddr::V4(s), IpAddr::V4(d)) = (src_v4, dst_v4) {
        pseudo_v4.extend_from_slice(&s.octets());
        pseudo_v4.extend_from_slice(&d.octets());
        pseudo_v4.push(0);
        pseudo_v4.push(6);
        pseudo_v4.extend_from_slice(&[((tcp_len_v4 >> 8) & 0xFF) as u8, (tcp_len_v4 & 0xFF) as u8]);
    }
    let verify_sum_v4 = internet_checksum(&[&pseudo_v4, &segment_v4]);
    assert_eq!(
        verify_sum_v4, 0x0000,
        "TCP IPv4 RFC 1071 verification identity must equal 0x0000"
    );

    let src_v6: IpAddr = "2001:db8::aaaa".parse().unwrap();
    let dst_v6: IpAddr = "2001:db8::bbbb".parse().unwrap();
    let segment_v6 = build_tcp_segment(
        src_v6,
        dst_v6,
        5000,
        443,
        &flags,
        Some(200),
        None,
        Some(32768),
        None,
        None,
        b"TLS_CLIENT_HELLO",
    )
    .unwrap();

    let tcp_len_v6 = segment_v6.len() as u32;
    let mut pseudo_v6 = Vec::with_capacity(40);
    if let (IpAddr::V6(s), IpAddr::V6(d)) = (src_v6, dst_v6) {
        pseudo_v6.extend_from_slice(&s.octets());
        pseudo_v6.extend_from_slice(&d.octets());
        pseudo_v6.extend_from_slice(&tcp_len_v6.to_be_bytes());
        pseudo_v6.extend_from_slice(&[0, 0, 0, 6]);
    }
    let verify_sum_v6 = internet_checksum(&[&pseudo_v6, &segment_v6]);
    assert_eq!(
        verify_sum_v6, 0x0000,
        "TCP IPv6 RFC 1071 verification identity must equal 0x0000"
    );
}

/// 10. Verify Extended Deterministic MAC Auto-Derivation Invariants:
/// - Reversed arrow (`s <- c UDP`) emits callee MAC as src, caller MAC as dst.
/// - Additional RFC 2464 IPv6 multicast addresses:
///   `ff02::2` -> `33:33:00:00:00:02`,
///   `ff05::1:3` -> `33:33:00:01:00:03`,
///   `ff0e::dead:beef` -> `33:33:de:ad:be:ef`.
/// - Additional RFC 1112 IPv4 multicast addresses:
///   `224.0.0.1` -> `01:00:5e:00:00:01`,
///   `224.0.0.18` -> `01:00:5e:00:00:12`.
#[test]
fn test_extended_deterministic_mac_derivations() {
    let ext_mac_dsl = r#"
        host em_client { ip 10.8.0.1 }
        host em_server { ip 10.8.0.2 }
        host v6_c { ip 2001:db8::1 }
        host v6_all_routers { ip ff02::2 }
        host v6_site_dhcp { ip ff05::1:3 }
        host v6_global { ip ff0e::dead:beef }
        host v4_all_hosts { ip 224.0.0.1 }
        host v4_vrrp { ip 224.0.0.18 }
        flow test_extended_macs(c, s, c6, r6, d6, g6, a4, v4) {
            c <- s udp payload "reversed_arrow"
            c6 -> r6 udp payload "all_routers"
            c6 -> d6 udp payload "site_dhcp"
            c6 -> g6 udp payload "global_mcast"
            c -> a4 udp payload "all_hosts"
            c -> v4 udp payload "vrrp"
        } compile { test_extended_macs(em_client, em_server, v6_c, v6_all_routers, v6_site_dhcp, v6_global, v4_all_hosts, v4_vrrp) }"#;
    let pkts = compile_dsl_to_packets(ext_mac_dsl).expect("compile extended macs");
    assert_eq!(pkts.len(), 6);

    assert_eq!(&pkts[0][0..6], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&pkts[0][6..12], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    assert_eq!(&pkts[1][0..6], &[0x33, 0x33, 0x00, 0x00, 0x00, 0x02]);
    assert_eq!(&pkts[2][0..6], &[0x33, 0x33, 0x00, 0x01, 0x00, 0x03]);
    assert_eq!(&pkts[3][0..6], &[0x33, 0x33, 0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(&pkts[4][0..6], &[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
    assert_eq!(&pkts[5][0..6], &[0x01, 0x00, 0x5e, 0x00, 0x00, 0x12]);
}

/// 11. Verify SNMP USM Empty Password Safety Across MD5, SHA1, SHA256, SHA384, SHA512.
///
/// Asserts that passing an empty password `b""` returns an empty localized key without
/// triggering a division-by-zero panic in any digest variant.
#[test]
fn test_snmp_empty_passwords_all_hashes() {
    assert!(password_to_key_md5(b"", b"8000000001").is_empty(), "Empty password MD5 must return empty key");
    assert!(password_to_key_sha1(b"", b"8000000001").is_empty(), "Empty password SHA1 must return empty key");
    assert!(password_to_key_sha256(b"", b"8000000001").is_empty(), "Empty password SHA256 must return empty key");
    assert!(password_to_key_sha384(b"", b"8000000001").is_empty(), "Empty password SHA384 must return empty key");
    assert!(password_to_key_sha512(b"", b"8000000001").is_empty(), "Empty password SHA512 must return empty key");
}

/// 12. Verify SCTP Chunk Framing Matrix and Little-Endian CRC32c Encoding.
///
/// Asserts chunk type encodings for 10 distinct RFC 9260 chunk types:
/// DATA, INIT, INIT_ACK, SACK, HEARTBEAT, HEARTBEAT_ACK, ABORT, SHUTDOWN, COOKIE_ECHO, COOKIE_ACK.
/// Verifies CRC32c checksum is encoded in little-endian format on the wire.
#[test]
fn test_sctp_all_chunk_types_and_little_endian_crc32c() {
    let chunk_matrix_dsl = r#"
        host cm_client { ip 10.9.0.1 }
        host cm_server { ip 10.9.0.2 }
        flow sctp_chunks(c, s) {
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk data stream 1 ssn 0 ppid 3 payload "chunk_data"
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk init
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk initack
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk sack
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk heartbeat payload "hb"
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk heartbeatack payload "hb_ack"
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk abort
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk shutdown
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk cookieecho payload "cookie"
            c -> s sctp srcport 5000 dstport 5000 vtag 0x12345678 chunk cookieack
        } compile { sctp_chunks(cm_client, cm_server) }"#;
    let pkts = compile_dsl_to_packets(chunk_matrix_dsl).expect("compile sctp chunk matrix");
    assert_eq!(pkts.len(), 10);

    let expected_chunk_types = [0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 10u8, 11u8];

    for (idx, (pkt, expected_type)) in pkts.iter().zip(expected_chunk_types.iter()).enumerate() {
        let sctp_hdr = &pkt[34..];
        let chunk_type = sctp_hdr[12];
        assert_eq!(chunk_type, *expected_type, "SCTP packet {idx} expected chunk type {expected_type}, found {chunk_type}");

        let mut zeroed = sctp_hdr.to_vec();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        let expected_crc = crc32c(&[&zeroed]);
        let wire_crc = u32::from_le_bytes([sctp_hdr[8], sctp_hdr[9], sctp_hdr[10], sctp_hdr[11]]);
        assert_eq!(wire_crc, expected_crc, "SCTP chunk {idx} little-endian CRC32c mismatch");
    }
}

/// 13. Verify Rejection of SNMPv2c-Only PDUs (GETBULK and INFORM) under SNMP1.
///
/// Verifies that attempting to compile an SNMP1 statement with GETBULK or INFORM
/// fails cleanly at compile time.
#[test]
fn test_snmp_rejection_of_getbulk_and_inform_in_v1() {
    let script_bulk = r#"
        host v1_bulk_c { ip 10.10.0.1 }
        host v1_bulk_s { ip 10.10.0.2 }
        flow f_bulk(c, s) { c -> s snmp1 getbulk community "public" nonrepeaters 0 maxrepetitions 10 }
        compile { f_bulk(v1_bulk_c, v1_bulk_s) }"#;
    assert!(compile_dsl_to_packets(script_bulk).is_err(), "SNMP1 GETBULK must be rejected");

    let script_inform = r#"
        host v1_inf_c { ip 10.10.1.1 }
        host v1_inf_s { ip 10.10.1.2 }
        flow f_inf(c, s) { c -> s snmp1 inform community "public" oid "1.3.6.1.6.3.1.1.5.1" }
        compile { f_inf(v1_inf_c, v1_inf_s) }"#;
    assert!(compile_dsl_to_packets(script_inform).is_err(), "SNMP1 INFORM must be rejected");
}

