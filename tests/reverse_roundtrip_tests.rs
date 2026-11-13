//! Comprehensive end-to-end round-trip verification suite (`fasm -> pcap -> reverse -> fasm -> pcap`)
//! for FrameAssembly v3.0.0's 5-stage PCAP and PCAPNG to `.frasm` reverse decompiler across all 81
//! native Layer 2 through Layer 7 protocols.
//!
//! This integration test suite verifies that every protocol supported by FrameAssembly compiles to
//! binary PCAPNG frames, decompiles via [`frameassembly::reverse::reverse_pcap_bytes`],
//! [`frameassembly::reverse::reverse_pcap_reader`], and [`frameassembly::reverse::reverse_pcap_file`]
//! into strict-lowercase v3.0.0 `.frasm` code (with zero `//` diagnostic comments, sequential
//! `host1` / `host2` topology discovery, native protocol keywords without stepping down to
//! `hexpayload`, and inline `compile { ... }` statements), and recompiles to byte-for-byte
//! identical Ethernet II wire frames with identical relative nanosecond timestamps.

use std::borrow::Cow;
use std::fs;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use frameassembly::backend::compile_program;
use frameassembly::parser::{parse_program, validate_semantics};
use frameassembly::reverse::{reverse_pcap_bytes, reverse_pcap_file, reverse_pcap_reader};
use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::Block;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};

/// Serializes `(frame_bytes, timestamp_ns)` pairs into an in-memory PCAPNG byte buffer with
/// `LINKTYPE_ETHERNET` and `IfTsResol(9)` nanosecond timestamp precision.
fn frames_to_pcapng(frames: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = PcapNgWriter::new(&mut buf).expect("initialize in-memory PcapNgWriter");
    let idb = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65535,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    };
    writer
        .write_block(&Block::InterfaceDescription(idb))
        .expect("write InterfaceDescriptionBlock");
    for (data, ts) in frames {
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(*ts),
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: Vec::new(),
        };
        writer
            .write_block(&Block::EnhancedPacket(epb))
            .expect("write EnhancedPacketBlock");
    }
    buf
}

/// Compiles `fasm_src`, decompiles the emitted PCAPNG via `reverse_pcap_bytes`, verifies v3.0.0
/// strict-lowercase formatting (`host1`, `host2`, zero `hexpayload`, presence of `expected_kw`),
/// recompiles the decompiled `.frasm`, and asserts byte-for-byte frame and timestamp equality.
fn assert_protocol_roundtrip(label: &str, fasm_src: &str, expected_kw: &str) -> String {
    let prog = parse_program(fasm_src)
        .unwrap_or_else(|e| panic!("[{label}] failed to parse original .frasm: {e:?}"));
    validate_semantics(&prog, fasm_src)
        .unwrap_or_else(|e| panic!("[{label}] failed original semantic validation: {e:?}"));
    let orig_frames = compile_program(&prog)
        .unwrap_or_else(|e| panic!("[{label}] failed to compile original .frasm: {e}"));
    assert!(
        !orig_frames.is_empty(),
        "[{label}] original program produced zero frames"
    );

    let pcap_bytes = frames_to_pcapng(&orig_frames);
    let rev = reverse_pcap_bytes(&pcap_bytes)
        .unwrap_or_else(|e| panic!("[{label}] reverse_pcap_bytes failed: {e}"));

    assert_eq!(
        rev.packet_count,
        orig_frames.len(),
        "[{label}] reversed packet_count mismatch"
    );
    assert!(
        rev.host_count >= 2,
        "[{label}] expected at least 2 discovered hosts, got {}",
        rev.host_count
    );
    assert!(
        !rev.fasm.lines().any(|line| line.trim_start().starts_with("//")),
        "[{label}] reversed .frasm must not contain comments:\n{}",
        rev.fasm
    );
    assert!(
        rev.fasm.contains("host host1") && rev.fasm.contains("host host2"),
        "[{label}] reversed .frasm must declare host1 and host2:\n{}",
        rev.fasm
    );
    assert!(
        !rev.fasm.contains("\nflow ") && !rev.fasm.contains("loop "),
        "[{label}] reversed .frasm must not emit flow or loop blocks:\n{}",
        rev.fasm
    );
    assert!(
        rev.fasm.contains("compile {\n"),
        "[{label}] reversed .frasm must contain inline compile block:\n{}",
        rev.fasm
    );
    if matches!(expected_kw, "vxlan" | "geneve") {
        assert!(
            rev.fasm.contains(&format!("-> host2 {expected_kw}")),
            "[{label}] overlay protocol '{expected_kw}' stepped down to raw UDP fallback:\n{}",
            rev.fasm
        );
    } else {
        assert!(
            !rev.fasm.contains("hexpayload"),
            "[{label}] native protocol dissector stepped down to hexpayload:\n{}",
            rev.fasm
        );
    }
    assert!(
        rev.fasm.contains(expected_kw),
        "[{label}] expected keyword '{expected_kw}' in reversed .frasm:\n{}",
        rev.fasm
    );

    let reprog = parse_program(&rev.fasm).unwrap_or_else(|e| {
        panic!(
            "[{label}] failed to re-parse decompiled .frasm: {e:?}\n--- FASM ---\n{}",
            rev.fasm
        )
    });
    validate_semantics(&reprog, &rev.fasm).unwrap_or_else(|e| {
        panic!(
            "[{label}] failed semantic validation on decompiled .frasm: {e:?}\n--- FASM ---\n{}",
            rev.fasm
        )
    });
    let reframes = compile_program(&reprog).unwrap_or_else(|e| {
        panic!(
            "[{label}] failed to re-compile decompiled .frasm: {e}\n--- FASM ---\n{}",
            rev.fasm
        )
    });

    assert_eq!(
        orig_frames.len(),
        reframes.len(),
        "[{label}] frame count mismatch after round-trip"
    );

    let orig_base = orig_frames[0].1;
    let re_base = reframes[0].1;
    for (idx, ((orig_b, orig_ts), (re_b, re_ts))) in
        orig_frames.iter().zip(reframes.iter()).enumerate()
    {
        assert_eq!(
            orig_b,
            re_b,
            "[{label}] frame #{} wire bytes mismatch!\n--- Decompiled FASM ---\n{}",
            idx + 1,
            rev.fasm
        );
        assert_eq!(
            orig_ts.saturating_sub(orig_base),
            re_ts.saturating_sub(re_base),
            "[{label}] frame #{} relative timestamp mismatch",
            idx + 1
        );
    }

    rev.fasm
}

/// Runs a dual-stack (IPv4 and IPv6) round-trip test for a protocol statement body.
fn assert_dual_stack_roundtrip(label: &str, stmt_body: &str, expected_kw: &str) {
    let v4_src = format!(
        "host h1 {{ ip 10.10.1.1 mac 00:11:22:33:44:01 }}\n\
         host h2 {{ ip 10.10.1.2 mac 00:11:22:33:44:02 }}\n\
         flow f(a, b) {{ a -> b {stmt_body} }}\n\
         compile {{ f(h1, h2) }}\n"
    );
    assert_protocol_roundtrip(&format!("{label}_ipv4"), &v4_src, expected_kw);

    let v6_src = format!(
        "host h1 {{ ip 2001:db8:10::1 mac 00:11:22:33:44:01 }}\n\
         host h2 {{ ip 2001:db8:10::2 mac 00:11:22:33:44:02 }}\n\
         flow f(a, b) {{ a -> b {stmt_body} }}\n\
         compile {{ f(h1, h2) }}\n"
    );
    assert_protocol_roundtrip(&format!("{label}_ipv6"), &v6_src, expected_kw);
}

/// Verifies in one exhaustive pass that all 81 zero-keyword RFC-default protocol statements
/// round-trip through `reverse_pcap_bytes` emitting protocol-specific keywords rather than
/// stepping down to `hexpayload`.
#[test]
fn test_all_81_protocols_zero_keyword_roundtrip_without_hexpayload() {
    let ipv4_79: &[(&str, &str)] = &[
        // L2 (8 — note vlan/qinq/mpls over IP hosts carry default IPv4 ICMP/UDP or L2 ethertype)
        ("arp", "arp"),
        ("vlan 100 icmp", "vlan 100"),
        ("qinq 200 innervlan 50 icmp", "qinq 200 innervlan 50"),
        ("lldp", "lldp"),
        ("stp", "stp"),
        ("lacp", "lacp"),
        ("eapol", "eapol"),
        ("mpls 1000 icmp", "mpls 1000"),
        // L3 IPv4-capable (18 of 20; ndp & mld are IPv6-only)
        ("icmp", "icmp"),
        ("igmp", "igmp"),
        ("gre", "gre"),
        ("vxlan", "vxlan"),
        ("geneve", "geneve"),
        ("ipsec", "esp"),
        ("esp", "esp"),
        ("ah", "ah"),
        ("ikev2", "ikev2"),
        ("wireguard", "wireguard"),
        ("ospf", "ospf"),
        ("bgp", "bgp"),
        ("rip", "rip"),
        ("vrrp", "vrrp"),
        ("hsrp", "hsrp"),
        ("pim", "pim"),
        ("bfd", "bfd"),
        ("openflow", "openflow"),
        // L4 (3)
        ("tcp", "tcp"),
        ("udp", "udp"),
        ("sctp", "sctp"),
        // L7 (50)
        ("snmp1", "snmp1"),
        ("snmp2", "snmp2"),
        ("snmp3", "snmp3"),
        ("dns", "dns"),
        ("mdns", "mdns"),
        ("dhcp", "dhcp"),
        ("ntp", "ntp"),
        ("ptp", "ptp"),
        ("radius", "radius"),
        ("tacacs", "tacacs"),
        ("syslog", "syslog"),
        ("netflow", "netflow"),
        ("ipfix", "ipfix"),
        ("sflow", "sflow"),
        ("tftp", "tftp"),
        ("ftp", "ftp"),
        ("ssh", "ssh"),
        ("telnet", "telnet"),
        ("http", "http"),
        ("http2", "http2"),
        ("grpc", "grpc"),
        ("websocket", "websocket"),
        ("tls", "tls"),
        ("quic", "quic"),
        ("stun", "stun"),
        ("sip", "sip"),
        ("rtp", "rtp"),
        ("rtsp", "rtsp"),
        ("smtp", "smtp"),
        ("imap", "imap"),
        ("pop3", "pop3"),
        ("kerberos", "kerberos"),
        ("ldap", "ldap"),
        ("smb", "smb"),
        ("nfs", "nfs"),
        ("redis", "redis"),
        ("memcached", "memcached"),
        ("mysql", "mysql"),
        ("postgres", "postgres"),
        ("mqtt", "mqtt"),
        ("coap", "coap"),
        ("amqp", "amqp"),
        ("ssdp", "ssdp"),
        ("whois", "whois"),
        ("modbus", "modbus"),
        ("bacnet", "bacnet"),
        ("dnp3", "dnp3"),
        ("s7comm", "s7comm"),
        ("ethernetip", "ethernetip"),
        ("opcua", "opcua"),
    ];
    assert_eq!(ipv4_79.len(), 79);

    let mut stepped_down_or_hex = Vec::new();
    for &(stmt, expected_kw) in ipv4_79 {
        let src = format!(
            "host h1 {{ ip 10.99.0.1 mac 00:11:22:33:44:01 }}\n\
             host h2 {{ ip 10.99.0.2 mac 00:11:22:33:44:02 }}\n\
             compile {{ h1 -> h2 {stmt} }}\n"
        );
        let fasm = assert_protocol_roundtrip(&format!("zero_kw_{stmt}"), &src, expected_kw);
        if !matches!(stmt, "vxlan" | "geneve") && fasm.contains("hexpayload") {
            stepped_down_or_hex.push((stmt, fasm));
        }
    }

    for &(stmt, expected_kw) in &[("ndp", "ndp"), ("mld", "mld")] {
        let src = format!(
            "host h1 {{ ip 2001:db8:99::1 mac 00:11:22:33:44:01 }}\n\
             host h2 {{ ip 2001:db8:99::2 mac 00:11:22:33:44:02 }}\n\
             compile {{ h1 -> h2 {stmt} }}\n"
        );
        let fasm = assert_protocol_roundtrip(&format!("zero_kw_{stmt}"), &src, expected_kw);
        if !matches!(stmt, "vxlan" | "geneve") && fasm.contains("hexpayload") {
            stepped_down_or_hex.push((stmt, fasm));
        }
    }

    assert!(
        stepped_down_or_hex.is_empty(),
        "Zero-keyword protocols unexpectedly emitted hexpayload:\n{:#?}",
        stepped_down_or_hex
    );
}

/// Verifies round-trip decompilation and byte-identical recompilation across all 8 Layer 2 protocols.
#[test]
fn test_roundtrip_all_8_l2_protocols() {
    let arp_v4 = r#"
        host a { ip 192.168.1.10 mac 00:11:22:33:44:01 }
        host b { ip 192.168.1.20 mac 00:11:22:33:44:02 }
        flow f(x, y) {
            x -> y arp request wait 5ms
            x <- y arp reply wait 5ms
            x -> y arp request gratuitous wait 5ms
        }
        compile { f(a, b) }
    "#;
    let fasm = assert_protocol_roundtrip("l2_arp_ipv4", arp_v4, "arp request");
    assert!(fasm.contains("arp reply") && fasm.contains("gratuitous"));

    let l2_cases: &[(&str, &str, &str)] = &[
        (
            "l2_vlan",
            "vlan 150 pcp 5 dei 1 ethertype 0x88b5 payload \"vlan-l2\"",
            "vlan 150",
        ),
        (
            "l2_qinq",
            "qinq 200 innervlan 50 pcp 3 ethertype 0x88b5 payload \"qinq-l2\"",
            "qinq 200 innervlan 50",
        ),
        (
            "l2_mpls",
            "mpls 1048 exp 4 bos 1 mplsttl 32 payload \"mpls-l2\"",
            "mpls 1048",
        ),
        (
            "l2_lldp",
            "lldp chassisid \"core-01\" portid \"Gi0/1\" sysname \"core01.local\" sysdesc \"FrameAssembly Switch\"",
            "lldp",
        ),
        ("l2_stp", "stp rstp", "stp"),
        ("l2_lacp", "lacp actorkey 10 partnerkey 10", "lacp"),
        ("l2_eapol", "eapol type start", "eapol"),
    ];

    for &(label, stmt, kw) in l2_cases {
        let src = format!(
            "host s1 {{ mac 00:11:22:33:44:01 }}\n\
             host s2 {{ mac 00:11:22:33:44:02 }}\n\
             flow f(a, b) {{ a -> b {stmt} }}\n\
             compile {{ f(s1, s2) }}\n"
        );
        assert_protocol_roundtrip(label, &src, kw);
    }
}

/// Verifies round-trip decompilation and byte-identical recompilation across all 20 Layer 3 protocols.
#[test]
fn test_roundtrip_all_20_l3_protocols() {
    let dual_stack_l3: &[(&str, &str, &str)] = &[
        (
            "l3_icmp",
            "icmp echorequest id 0x4321 seq 9 payload \"ping-data\"",
            "icmp echorequest",
        ),
        ("l3_gre", "gre grekey 1234 payload \"inner_ip\"", "gre"),
        ("l3_vxlan", "vxlan vni 50010", "vxlan"),
        ("l3_geneve", "geneve vni 60020", "geneve"),
        (
            "l3_ipsec",
            "ipsec spi 0x2000 seq 5 payload \"ciphertext\"",
            "esp spi 0x2000 seq 5",
        ),
        (
            "l3_esp",
            "esp spi 0x3000 seq 7 payload \"ciphertext\"",
            "esp spi 0x3000 seq 7",
        ),
        (
            "l3_ah",
            "ah spi 0x4000 seq 11 payload \"ah_payload\"",
            "ah spi 0x4000 seq 11",
        ),
        ("l3_ikev2", "ikev2 exchange sainit msgid 0", "ikev2"),
        (
            "l3_wireguard",
            "wireguard type initiation sender 0x01020304",
            "wireguard",
        ),
        (
            "l3_ospf",
            "ospf hello routerid 10.0.0.1 areaid 0",
            "ospf hello",
        ),
        (
            "l3_bgp",
            "bgp open asn 65001 holdtime 180 bgpid 10.0.0.1",
            "bgp open",
        ),
        (
            "l3_rip",
            "rip response prefix 10.0.0.0 metric 2",
            "rip reply",
        ),
        ("l3_vrrp", "vrrp vrid 10 priority 120", "vrrp"),
        (
            "l3_hsrp",
            "hsrp group 10 priority 110 vip 10.10.1.254",
            "hsrp",
        ),
        ("l3_pim", "pim hello", "pim hello"),
        ("l3_bfd", "bfd state 3 mydisc 100 yourdisc 200", "bfd"),
        ("l3_openflow", "openflow type hello xid 0x00000010", "openflow"),
    ];

    for &(label, stmt, kw) in dual_stack_l3 {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }

    let igmp_src = r#"
        host h1 { ip 10.10.1.1 mac 00:11:22:33:44:01 }
        host h2 { ip 10.10.1.2 mac 00:11:22:33:44:02 }
        flow f(a, b) {
            a -> b igmp query group 224.0.0.1
            a <- b igmp report group 239.1.2.3
        }
        compile { f(h1, h2) }
    "#;
    assert_protocol_roundtrip("l3_igmp_ipv4", igmp_src, "igmp query");

    let ndp_src = r#"
        host h1 { ip 2001:db8:10::1 mac 00:11:22:33:44:01 }
        host h2 { ip 2001:db8:10::2 mac 00:11:22:33:44:02 }
        flow f(a, b) {
            a -> b ndp neighborsolicit target 2001:db8:10::2
            a <- b ndp neighboradvert target 2001:db8:10::2
        }
        compile { f(h1, h2) }
    "#;
    assert_protocol_roundtrip("l3_ndp_ipv6", ndp_src, "ndp neighborsolicit");

    let mld_src = r#"
        host h1 { ip 2001:db8:10::1 mac 00:11:22:33:44:01 }
        host h2 { ip 2001:db8:10::2 mac 00:11:22:33:44:02 }
        flow f(a, b) {
            a -> b mld query multicastaddr ff02::1
            a <- b mld report multicastaddr ff02::1:ff00:1
        }
        compile { f(h1, h2) }
    "#;
    assert_protocol_roundtrip("l3_mld_ipv6", mld_src, "mld query");
}

/// Verifies round-trip decompilation and byte-identical recompilation across all 3 Layer 4 protocols.
#[test]
fn test_roundtrip_all_3_l4_protocols() {
    assert_dual_stack_roundtrip(
        "l4_tcp",
        "tcp syn seq 2500 srcport 54321 dstport 8080 win 65535 mss 1460 wscale 7 sackperm tsval 1000 tsecr 0",
        "tcp syn",
    );
    assert_dual_stack_roundtrip(
        "l4_udp",
        "udp srcport 53000 dstport 9999 payload \"udp-datagram\"",
        "udp",
    );
    assert_dual_stack_roundtrip(
        "l4_sctp",
        "sctp chunk data srcport 2905 dstport 2905 vtag 0x12345678 tsn 100 stream 1 ssn 0 ppid 60 payload \"sigtran\"",
        "sctp",
    );
}

/// Verifies round-trip decompilation across Layer 7 infrastructure, SNMP, naming, DHCP, time,
/// AAA, logging, and flow telemetry protocols (14 protocols).
#[test]
fn test_roundtrip_l7_infra_snmp_and_telemetry_protocols() {
    let dual_stack_infra: &[(&str, &str, &str)] = &[
        (
            "l7_snmp1",
            "snmp1 get community \"public\" reqid 10 oid 1.3.6.1.2.1.1.1.0",
            "snmp1 get",
        ),
        (
            "l7_snmp2",
            "snmp2 trap community \"public\" reqid 20 oid 1.3.6.1.6.3.1.1.5.3 varbind 1.3.6.1.2.1.1.5.0 string \"core-rtr\"",
            "snmp2 trap",
        ),
        (
            "l7_snmp3_cleartext",
            "snmp3 get user \"admin\" engineid \"8000000001\" engineboots 2 enginetime 500 reqid 30 oid 1.3.6.1.2.1.1.1.0",
            "snmp3 get",
        ),
        (
            "l7_dns_udp",
            "dns query txid 0x1a2b qname \"example.com\" qtype \"a\"",
            "dns query",
        ),
        (
            "l7_dns_tcp",
            "dns query transport tcp txid 0x2b3c qname \"example.com\" qtype \"aaaa\"",
            "dns query",
        ),
        (
            "l7_mdns",
            "mdns query qname \"printer.local\" qtype \"a\"",
            "mdns query",
        ),
        (
            "l7_ntp",
            "ntp vn 4 mode 3 stratum 2 poll 6 precision -20 refid \"GPS\"",
            "ntp",
        ),
        ("l7_ptp", "ptp sync domain 0 seqid 42", "ptp sync"),
        (
            "l7_radius",
            "radius accessrequest id 5 user \"alice\" servicetype 2",
            "radius accessrequest",
        ),
        (
            "l7_tacacs",
            "tacacs authen seq 1 sessionid 0x11223344 user \"netadmin\"",
            "tacacs",
        ),
        (
            "l7_syslog_udp",
            "syslog facility 4 severity 2 hostname \"fw01\" app \"sshd\" msg \"Accepted publickey\"",
            "syslog",
        ),
        (
            "l7_syslog_tcp",
            "syslog transport tcp facility 1 severity 6 hostname \"web01\" app \"nginx\" msg \"GET /ok\"",
            "syslog",
        ),
        (
            "l7_netflow",
            "netflow srcip 10.0.0.10 dstip 10.0.0.20 proto 6 packets 12 octets 1440",
            "netflow",
        ),
        (
            "l7_ipfix",
            "ipfix domainid 100 srcip 10.0.0.10 dstip 10.0.0.20 proto 6 packets 5 octets 500",
            "ipfix",
        ),
        (
            "l7_sflow",
            "sflow subagentid 1 seq 10 uptime 5000 samples 1",
            "sflow",
        ),
    ];

    for &(label, stmt, kw) in dual_stack_infra {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }

    let dhcpv4_src = r#"
        host client { ip 10.10.1.10 mac 00:11:22:33:44:01 }
        host server { ip 10.10.1.1  mac 00:11:22:33:44:02 }
        flow f(c, s) {
            c -> s dhcp discover xid 0x11223344 hostname "laptop01"
            c <- s dhcp offer xid 0x11223344 yiaddr 10.10.1.50 siaddr 10.10.1.1 subnetmask 255.255.255.0 router 10.10.1.1 dnsserver 8.8.8.8 leasetime 3600
        }
        compile { f(client, server) }
    "#;
    assert_protocol_roundtrip("l7_dhcp_ipv4", dhcpv4_src, "dhcp discover");

    let dhcpv6_src = r#"
        host client { ip 2001:db8:10::10 mac 00:11:22:33:44:01 }
        host server { ip 2001:db8:10::1  mac 00:11:22:33:44:02 }
        flow f(c, s) {
            c -> s dhcp solicit xid 0x123456
            c <- s dhcp advertise xid 0x123456
        }
        compile { f(client, server) }
    "#;
    assert_protocol_roundtrip("l7_dhcp_ipv6", dhcpv6_src, "dhcp solicit");
}

/// Verifies round-trip decompilation across Layer 7 web, cloud-native, transport security, VoIP,
/// and remote access protocols (16 protocols).
#[test]
fn test_roundtrip_l7_web_cloud_voip_and_access_protocols() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "l7_http",
            "http get uri \"/api/v1/status\" hosthdr \"example.local\" useragent \"FrameAssembly/2.0\"",
            "http get",
        ),
        ("l7_http2", "http2 settings", "http2"),
        (
            "l7_grpc",
            "grpc service \"OrderService\" method \"GetOrder\"",
            "grpc",
        ),
        (
            "l7_websocket",
            "websocket opcode text payload \"ping\"",
            "websocket",
        ),
        (
            "l7_tls",
            "tls clienthello sni \"secure.example.com\"",
            "tls clienthello",
        ),
        (
            "l7_quic",
            "quic initial dcid 0x01020304 scid 0x05060708",
            "quic initial",
        ),
        (
            "l7_tftp",
            "tftp rrq filename \"boot.img\" mode \"octet\"",
            "tftp rrq",
        ),
        ("l7_ftp", "ftp cmd \"USER\" arg \"anonymous\"", "ftp"),
        ("l7_ssh", "ssh banner \"SSH-2.0-OpenSSH_9.0\"", "ssh"),
        ("l7_telnet", "telnet do 1", "telnet"),
        ("l7_whois", "whois query domain \"example.com\"", "whois"),
        (
            "l7_sip_udp",
            "sip invite from \"sip:alice@pbx\" to \"sip:bob@pbx\" callid \"call123\"",
            "sip invite",
        ),
        (
            "l7_sip_tcp",
            "sip invite transport tcp from \"sip:alice@pbx\" to \"sip:bob@pbx\" callid \"call123\"",
            "sip invite",
        ),
        ("l7_rtp", "rtp pt 0 seq 100 ssrc 0x12345678", "rtp"),
        (
            "l7_rtsp",
            "rtsp options uri \"rtsp://cam/live\" cseq 1",
            "rtsp options",
        ),
        (
            "l7_stun",
            "stun bindingrequest txid 0x11223344",
            "stun",
        ),
        ("l7_ssdp", "ssdp msearch st \"upnp:rootdevice\"", "ssdp"),
    ];

    for &(label, stmt, kw) in cases {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }
}

/// Verifies round-trip decompilation across Layer 7 mail, auth, directory, storage, database,
/// cache, messaging, and industrial OT protocols (20 protocols).
#[test]
fn test_roundtrip_l7_data_storage_messaging_and_ot_protocols() {
    let cases: &[(&str, &str, &str)] = &[
        ("l7_smtp", "smtp ehlo \"mail.source.org\"", "smtp"),
        (
            "l7_imap",
            "imap tag \"A01\" cmd \"LOGIN\" arg \"user pass\"",
            "imap",
        ),
        ("l7_pop3", "pop3 cmd \"USER\" arg \"bob\"", "pop3"),
        ("l7_kerberos_udp", "kerberos asreq realm \"CORP.LOCAL\"", "kerberos"),
        (
            "l7_kerberos_tcp",
            "kerberos asreq transport tcp realm \"CORP.LOCAL\"",
            "kerberos",
        ),
        (
            "l7_ldap",
            "ldap bindreq msgid 1 basedn \"dc=corp,dc=local\"",
            "ldap",
        ),
        ("l7_smb", "smb command negotiate", "smb"),
        ("l7_nfs_tcp", "nfs proc lookup path \"/exports/data\"", "nfs"),
        (
            "l7_nfs_udp",
            "nfs transport udp proc lookup path \"/exports/data\"",
            "nfs",
        ),
        ("l7_redis", "redis cmd \"PING\"", "redis"),
        ("l7_memcached_tcp", "memcached get key \"session:123\"", "memcached"),
        (
            "l7_memcached_udp",
            "memcached get transport udp key \"session:123\"",
            "memcached",
        ),
        ("l7_mysql", "mysql query sql \"SELECT 1\"", "mysql"),
        (
            "l7_postgres",
            "postgres query sql \"SELECT version()\"",
            "postgres",
        ),
        ("l7_mqtt", "mqtt connect clientid \"sensor-01\"", "mqtt"),
        ("l7_coap", "coap con get uripath \"/telemetry\"", "coap"),
        ("l7_amqp", "amqp protocolheader", "amqp"),
        (
            "l7_modbus_tcp",
            "modbus func readholdingregisters addr 100 count 5",
            "modbus",
        ),
        (
            "l7_modbus_udp",
            "modbus transport udp func readholdingregisters addr 100 count 5",
            "modbus",
        ),
        ("l7_bacnet", "bacnet whois", "bacnet"),
        ("l7_dnp3_tcp", "dnp3 func read", "dnp3"),
        ("l7_dnp3_udp", "dnp3 transport udp func read", "dnp3"),
        ("l7_s7comm", "s7comm func readvar", "s7comm"),
        ("l7_ethernetip_tcp", "ethernetip cmd listidentity", "ethernetip"),
        (
            "l7_ethernetip_udp",
            "ethernetip transport udp cmd listidentity",
            "ethernetip",
        ),
        ("l7_opcua", "opcua msgtype hel", "opcua"),
    ];

    for &(label, stmt, kw) in cases {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }
}

/// Verifies shadow-state elision across a multi-packet TCP 3-way handshake + HTTP request/response
/// + FIN teardown using `host1`/`host2` and v3.0.0 `hosthdr`.
#[test]
fn test_shadow_state_elision_and_wait_quantization_tcp_http_session() {
    let session_src = r#"
        host client { ip 192.168.50.10 mac 00:11:22:33:44:10 }
        host server { ip 192.168.50.80 mac 00:11:22:33:44:80 }
        flow web_lifecycle(c, s) {
            c -> s tcp syn seq 5000 srcport 51234 dstport 80
            c <- s tcp syn ack seq 9000 wait 500ns
            c -> s tcp ack wait 250us
            c -> s http get uri "/api/status" hosthdr "status.local" wait 5ms
            c <- s http status 200 reason "OK" body "healthy" wait 2s
            c -> s tcp fin ack wait 1m
            c <- s tcp fin ack wait 10ms
        }
        compile { web_lifecycle(client, server) }
    "#;

    let fasm = assert_protocol_roundtrip("tcp_http_shadow_session", session_src, "http get");
    let stmt_lines: Vec<&str> = fasm
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("host1 "))
        .collect();
    assert_eq!(
        stmt_lines.len(),
        7,
        "all 7 statements must lock host1 on the left:\n{fasm}"
    );

    assert_eq!(
        stmt_lines[0],
        "host1 -> host2 tcp syn srcport 51234 seq 5000"
    );
    assert_eq!(
        stmt_lines[1],
        "host1 <- host2 tcp syn ack seq 9000 wait 500ns"
    );
    assert_eq!(stmt_lines[2], "host1 -> host2 tcp ack wait 250us");
    assert_eq!(
        stmt_lines[3],
        "host1 -> host2 http get uri \"/api/status\" hosthdr \"status.local\" wait 5ms"
    );
    assert_eq!(
        stmt_lines[4],
        "host1 <- host2 http status 200 body \"healthy\" wait 2s"
    );
    assert_eq!(stmt_lines[5], "host1 -> host2 tcp fin ack wait 1m");
    assert_eq!(stmt_lines[6], "host1 <- host2 tcp fin ack");
}

/// Verifies `reverse_pcap_reader` and `reverse_pcap_file` entry points with RAII temporary file cleanup.
#[test]
fn test_reverse_pcap_reader_and_file_entrypoints() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = std::env::temp_dir().join(format!(
        "frameassembly_rev_roundtrip_{}_{}.pcap",
        std::process::id(),
        id
    ));

    let src = r#"
        host a { ip 10.20.30.1 mac 00:11:22:33:44:01 }
        host b { ip 10.20.30.2 mac 00:11:22:33:44:02 }
        flow f(x, y) {
            x -> y dns query txid 0x1234 qname "example.org" qtype "a" wait 5ms
            x <- y dns response txid 0x1234 qname "example.org" qtype "a" rdata "93.184.216.34" wait 5ms
        }
        compile { f(a, b) }
    "#;
    let prog = parse_program(src).expect("parse program");
    let orig_frames = compile_program(&prog).expect("compile program");
    let pcap_bytes = frames_to_pcapng(&orig_frames);

    fs::write(&temp_path, &pcap_bytes).expect("write temp pcap");
    let file_res = reverse_pcap_file(&temp_path);
    let _ = fs::remove_file(&temp_path);

    let from_file = file_res.expect("reverse_pcap_file must succeed");
    let from_reader =
        reverse_pcap_reader(Cursor::new(&pcap_bytes)).expect("reverse_pcap_reader must succeed");
    let from_bytes = reverse_pcap_bytes(&pcap_bytes).expect("reverse_pcap_bytes must succeed");

    assert_eq!(from_file, from_reader);
    assert_eq!(from_reader, from_bytes);
    assert_eq!(from_file.packet_count, 2);
    assert_eq!(from_file.host_count, 2);
}
