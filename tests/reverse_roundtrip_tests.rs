//! Comprehensive end-to-end round-trip verification suite (`fasm -> pcap -> reverse -> fasm -> pcap`)
//! for FrameAssembly v3.3.0's 5-stage PCAP and PCAPNG to `.frasm` reverse decompiler across all 146
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

/// Verifies in one exhaustive pass that all 146 zero-keyword RFC-default protocol statements
/// round-trip through `reverse_pcap_bytes` emitting protocol-specific keywords rather than
/// stepping down to `hexpayload`.
#[test]
fn test_all_146_protocols_zero_keyword_roundtrip_without_hexpayload() {
    let ipv4_143: &[(&str, &str)] = &[
        // L2 (18 — note vlan/qinq/mpls over IP hosts carry default IPv4 ICMP/UDP or L2 ethertype)
        ("arp", "arp"),
        ("vlan 100 icmp", "vlan 100"),
        ("qinq 200 innervlan 50 icmp", "qinq 200 innervlan 50"),
        ("lldp", "lldp"),
        ("stp", "stp"),
        ("lacp", "lacp"),
        ("eapol", "eapol"),
        ("mpls 1000 icmp", "mpls 1000"),
        ("cdp", "cdp"),
        ("isis", "isis"),
        ("macsec", "macsec"),
        ("pfc", "pfc"),
        ("pppoe", "pppoe"),
        ("nsh", "nsh"),
        ("profinet", "profinet"),
        ("goose", "goose"),
        ("sv", "sv"),
        ("ethercat", "ethercat"),
        // L3 IPv4-capable (28 of 31; ndp, mld, and srv6 are IPv6-only)
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
        ("ipip", "ipip"),
        ("erspan", "erspan"),
        ("rsvp", "rsvp"),
        ("ldp", "ldp"),
        ("bmp", "bmp"),
        ("rpkirtr", "rpkirtr"),
        ("l2tp", "l2tp"),
        ("lisp", "lisp"),
        ("glbp", "glbp"),
        ("gtpu", "gtpu"),
        // L4 (3)
        ("tcp", "tcp"),
        ("udp", "udp"),
        ("sctp", "sctp"),
        // L7 (94)
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
        ("dcerpc", "dcerpc"),
        ("ntlm", "ntlm"),
        ("rdp", "rdp"),
        ("llmnr", "llmnr"),
        ("nbns", "nbns"),
        ("socks", "socks"),
        ("vnc", "vnc"),
        ("doh", "doh"),
        ("wsdiscovery", "wsdiscovery"),
        ("irc", "irc"),
        ("iec104", "iec104"),
        ("mms", "mms"),
        ("s7commplus", "s7commplus"),
        ("synchrophasor", "synchrophasor"),
        ("hartip", "hartip"),
        ("fins", "fins"),
        ("melsec", "melsec"),
        ("someip", "someip"),
        ("doip", "doip"),
        ("c1222", "c1222"),
        ("gesrtp", "gesrtp"),
        ("rocplus", "rocplus"),
        ("bsap", "bsap"),
        ("knxnetip", "knxnetip"),
        ("rocev2", "rocev2"),
        ("ipmi", "ipmi"),
        ("twamp", "twamp"),
        ("netconf", "netconf"),
        ("gtpc", "gtpc"),
        ("pfcp", "pfcp"),
        ("diameter", "diameter"),
        ("ngap", "ngap"),
        ("s1ap", "s1ap"),
        ("mssql", "mssql"),
        ("kafka", "kafka"),
        ("mongodb", "mongodb"),
        ("tns", "tns"),
        ("iscsi", "iscsi"),
        ("nvmetcp", "nvmetcp"),
        ("rtcp", "rtcp"),
        ("turn", "turn"),
        ("h323", "h323"),
        ("sccp", "sccp"),
        ("mgcp", "mgcp"),
    ];
    assert_eq!(ipv4_143.len(), 143);

    let mut stepped_down_or_hex = Vec::new();
    for &(stmt, expected_kw) in ipv4_143 {
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

    for &(stmt, expected_kw) in &[("ndp", "ndp"), ("mld", "mld"), ("srv6", "srv6")] {
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

/// Verifies rich modifier round-trip decompilation across all 10 new v3.3.0 Layer 2 protocols,
/// including MAC-only hosts and `profinet` / `ethercat` UDP Context Manager transports.
#[test]
fn test_roundtrip_10_new_l2_protocols() {
    let l2_cases: &[(&str, &str, &str)] = &[
        (
            "l2_cdp",
            "cdp version 2 ttl 120 deviceid \"core-rtr1\" portid \"Eth1/1\" capabilities 0x28 platform \"CSR1000v\" nativevlan 42",
            "cdp",
        ),
        (
            "l2_isis",
            "isis l2iih hostname \"edge01\" holdtime 45 priority 80",
            "isis l2iih",
        ),
        (
            "l2_macsec",
            "macsec an 2 sl 16 pn 42 icv \"0102030405060708090a0b0c0d0e0f10\"",
            "macsec",
        ),
        ("l2_pfc", "pfc enable 0x00ff quanta 200", "pfc"),
        (
            "l2_pppoe_pado",
            "pppoe pado servicename \"isp-fiber\" acname \"bng01\" hostuniq \"11223344\"",
            "pppoe pado",
        ),
        (
            "l2_pppoe_session",
            "pppoe session sessionid 99 pppproto 0x0021",
            "pppoe session",
        ),
        (
            "l2_nsh",
            "nsh oam ttl 16 spi 42 si 200 context \"00000001000000020000000300000004\"",
            "nsh oam",
        ),
        (
            "l2_profinet_rt",
            "profinet frameid 0x8001 cycle 500 datastatus 0x25",
            "profinet",
        ),
        (
            "l2_goose",
            "goose appid 0x0002 gocbref \"IED1/LLN0$GO$gcb01\" timetolive 4000 datset \"IED1/LLN0$ds01\" goid \"GO_TRIP\" stnum 5 sqnum 12",
            "goose",
        ),
        (
            "l2_sv",
            "sv appid 0x4005 svid \"MU01\" smpcnt 42 confrev 3 smpsynch 2",
            "sv",
        ),
        (
            "l2_ethercat",
            "ethercat write adp 0x0001 ado 0x1000 wkc 2",
            "ethercat",
        ),
    ];

    for &(label, stmt, kw) in l2_cases {
        let src = format!(
            "host s1 {{ mac 00:11:22:33:44:01 }}\n\
             host s2 {{ mac 00:11:22:33:44:02 }}\n\
             compile {{ s1 -> s2 {stmt} }}\n"
        );
        assert_protocol_roundtrip(label, &src, kw);
    }

    assert_dual_stack_roundtrip(
        "l2_profinet_udp",
        "profinet transport udp service \"connect\" xid 77",
        "profinet",
    );
    assert_dual_stack_roundtrip(
        "l2_ethercat_udp",
        "ethercat transport udp read adp 0x0002 ado 0x0120 wkc 1",
        "ethercat",
    );
}

/// Verifies rich modifier round-trip decompilation across all 11 new v3.3.0 Layer 3 protocols,
/// covering IPv6-only `srv6`, `ipip`, `l2tp` IP/UDP, and dual-stack tunneling/control protocols.
#[test]
fn test_roundtrip_11_new_l3_protocols() {
    let dual_stack_l3: &[(&str, &str, &str)] = &[
        (
            "l3_ipip",
            "ipip v4 srcip 198.51.100.10 dstip 198.51.100.20 innerttl 32 innerdscp 10 proto 17",
            "ipip",
        ),
        (
            "l3_erspan",
            "erspan v3 sessionid 12 vid 100 cos 5 greseq 77 timestamp 12345 direction 1",
            "erspan v3",
        ),
        (
            "l3_rsvp",
            "rsvp path tunnelid 42 lspid 7 label 1001 refresh 60000",
            "rsvp",
        ),
        (
            "l3_ldp_tcp",
            "ldp labelmapping lsrid 10.1.1.1 labelspace 0 msgid 99 label 500 prefix \"10.20.0.0/16\"",
            "ldp",
        ),
        (
            "l3_ldp_udp",
            "ldp transport udp hello holdtime 30",
            "ldp",
        ),
        (
            "l3_bmp",
            "bmp peerup peertype 1 peerip 192.0.2.10 asn 65100 bgpid 192.0.2.10",
            "bmp peerup",
        ),
        (
            "l3_rpkirtr",
            "rpkirtr ipv4prefix version 1 flags 1 prefix \"203.0.113.0/24\" maxlen 24 asn 64512",
            "rpkirtr ipv4prefix",
        ),
        (
            "l3_l2tp_ip",
            "l2tp v3 sccrq tunnelid 400 sessionid 800 ns 1 nr 2",
            "l2tp",
        ),
        (
            "l3_l2tp_udp",
            "l2tp transport udp v2 sccrq tunnelid 42 sessionid 7 ns 3 nr 1",
            "l2tp",
        ),
        (
            "l3_lisp",
            "lisp maprequest iid 100 nonce 0x0102030405060708 eid \"10.50.0.0/16\"",
            "lisp maprequest",
        ),
        (
            "l3_glbp",
            "glbp hello version 1 group 10 priority 150 hellotime 2000 holdtime 8000 auth \"cisco123\"",
            "glbp",
        ),
        (
            "l3_gtpu",
            "gtpu gpdu teid 0x11223344 seqnum 55 npdu 1 qfi 9",
            "gtpu",
        ),
    ];

    for &(label, stmt, kw) in dual_stack_l3 {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }

    let srv6_src = r#"
        host r1 { ip 2001:db8:20::1 mac 00:11:22:33:44:01 }
        host r2 { ip 2001:db8:20::2 mac 00:11:22:33:44:02 }
        compile {
            r1 -> r2 srv6 nextheader 58 segleft 1 tag 0x1234 sid 2001:db8:20::10 sid 2001:db8:20::20
        }
    "#;
    let srv6_fasm = assert_protocol_roundtrip("l3_srv6_ipv6", srv6_src, "srv6");
    assert!(srv6_fasm.contains("2001:db8:20::10") && srv6_fasm.contains("2001:db8:20::20"));
}

/// Verifies rich modifier round-trip decompilation across all 44 new v3.3.0 Layer 7 protocols.
#[test]
fn test_roundtrip_44_new_l7_protocols() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "l7_dcerpc",
            "dcerpc altercontext uuid \"4b324fc8-1670-01d3-1278-5a47bf6ee188\" vers \"3.0\" callid 42 ctxid 1",
            "dcerpc altercontext",
        ),
        (
            "l7_ntlm",
            "ntlm challenge domain \"CORP\" workstation \"DC01\" nonce \"0102030405060708\"",
            "ntlm challenge",
        ),
        (
            "l7_rdp",
            "rdp x224cr cookie \"mstshash=admin\" proto 2",
            "rdp",
        ),
        (
            "l7_llmnr_udp",
            "llmnr query txid 0x5566 qname \"filesrv\" qtype \"a\"",
            "llmnr",
        ),
        (
            "l7_llmnr_tcp",
            "llmnr transport tcp response txid 0x5567 qname \"filesrv\" qtype \"aaaa\" rdata \"2001:db8::9\"",
            "llmnr",
        ),
        (
            "l7_nbns",
            "nbns register txid 0x2233 qname \"SQL01\" rdata \"10.20.30.40\" ansttl 600",
            "nbns register",
        ),
        (
            "l7_socks",
            "socks connect addr \"93.184.216.34\" targetport 443",
            "socks connect",
        ),
        (
            "l7_vnc",
            "vnc msgtype \"serverinit\" width 1920 height 1080 desktop \"prod-vm\"",
            "vnc",
        ),
        (
            "l7_doh",
            "doh post uri \"/dns-query\" hosthdr \"dns.example\" txid 0x7788 qname \"api.example.com\" qtype \"a\"",
            "doh",
        ),
        (
            "l7_wsdiscovery",
            "wsdiscovery hello msgid \"urn:uuid:11111111-1111-1111-1111-111111111111\" xaddrs \"http://10.0.0.5:5357/ws\"",
            "wsdiscovery hello",
        ),
        (
            "l7_irc",
            "irc privmsg target \"#ops\" msg \"deploy ready\"",
            "irc privmsg",
        ),
        (
            "l7_iec104",
            "iec104 txseq 4 rxseq 2 typeid 45 cot 6 ca 1 ioa 1001 value 1",
            "iec104",
        ),
        (
            "l7_mms",
            "mms read invokeid 7 domain \"IED1\" item \"Measurements\"",
            "mms read",
        ),
        (
            "l7_s7commplus",
            "s7commplus opcode 0x31 seqnum 12 sessionid 0x10203040",
            "s7commplus",
        ),
        (
            "l7_synchrophasor",
            "synchrophasor msgtype \"cfg2\" id 10 station \"SUB_EAST\"",
            "synchrophasor",
        ),
        (
            "l7_hartip",
            "hartip msgtype \"publish\" txid 55 cmd 1 addr 2",
            "hartip",
        ),
        (
            "l7_fins",
            "fins read da1 10 sa1 20 sid 3 area \"dm\" addr 100 count 4",
            "fins",
        ),
        (
            "l7_melsec",
            "melsec read network 1 station 2 io 0x03ff device \"d\" addr 100 count 5",
            "melsec",
        ),
        (
            "l7_someip",
            "someip request serviceid 0x1234 methodid 0x0001 clientid 0x0010 sessionid 0x0002",
            "someip",
        ),
        (
            "l7_doip",
            "doip diagnostic src 0x0e80 dst 0x1001",
            "doip diagnostic",
        ),
        (
            "l7_c1222",
            "c1222 write callingap \"2.16.840.1.114416.3\" tableid 10 value 42",
            "c1222 write",
        ),
        (
            "l7_gesrtp",
            "gesrtp read seqnum 5 area \"r\" addr 100 count 4",
            "gesrtp",
        ),
        (
            "l7_rocplus",
            "rocplus read dst 2 group 1 src 1 type 98 param 0",
            "rocplus",
        ),
        (
            "l7_bsap",
            "bsap read dst 10 src 1 seqnum 7 addr 200 count 2",
            "bsap",
        ),
        (
            "l7_knxnetip",
            "knxnetip connect channel 3 seqnum 9",
            "knxnetip",
        ),
        (
            "l7_rocev2",
            "rocev2 read pkey 0xffff destqp 0x000100 seqnum 42 addr 0x10002000 key 0xabcdef01 count 64",
            "rocev2",
        ),
        (
            "l7_ipmi",
            "ipmi request version 2 netfn 6 cmd 1 rqseq 5 sessionid 0x11223344 seqnum 7",
            "ipmi",
        ),
        (
            "l7_twamp_udp",
            "twamp sender seqnum 15 senderttl 128 errorestimate 0x8001",
            "twamp",
        ),
        (
            "l7_twamp_tcp",
            "twamp transport tcp greeting mode 1 count 2048",
            "twamp",
        ),
        (
            "l7_netconf_rpc",
            "netconf rpc msgid \"105\" operation \"get-config\" chunked",
            "netconf",
        ),
        (
            "l7_netconf_hello",
            "netconf hello sessionid 42",
            "netconf",
        ),
        (
            "l7_gtpc",
            "gtpc createsessionrequest teid 0x12345678 seqnum 101 cause 16 imsi \"310410123456789\" apn \"internet\"",
            "gtpc createsessionrequest",
        ),
        (
            "l7_pfcp",
            "pfcp associationsetuprequest seid 0 seqnum 42 cause 1 nodeid 10.10.1.1 recovery 100",
            "pfcp associationsetuprequest",
        ),
        (
            "l7_diameter_tcp",
            "diameter ccr appid 4 hopid 0x11112222 endid 0x33334444 originhost \"hss1.example.com\" realm \"example.com\" sessionid \"hss1;1;2\"",
            "diameter ccr",
        ),
        (
            "l7_diameter_sctp",
            "diameter transport sctp dwa hopid 10 endid 20 resultcode 2001",
            "diameter dwa",
        ),
        (
            "l7_ngap",
            "ngap initialuemessage criticality \"ignore\" amfueid 101 ranueid 202 plmn \"310410\" tac 0x010203 ranname \"gnb-01\"",
            "ngap initialuemessage",
        ),
        (
            "l7_s1ap",
            "s1ap initialuemessage criticality \"ignore\" mmeueid 11 enbueid 22 plmn \"310410\" tac 0x1234 enbname \"enb-01\"",
            "s1ap initialuemessage",
        ),
        (
            "l7_mssql",
            "mssql query sql \"SELECT @@VERSION\" pktid 1",
            "mssql",
        ),
        (
            "l7_kafka",
            "kafka produce clientid \"producer-1\" correlationid 7 topic \"events\" partition 0",
            "kafka produce",
        ),
        (
            "l7_mongodb",
            "mongodb query db \"appdb\" collection \"users\" reqid 42",
            "mongodb query",
        ),
        (
            "l7_tns",
            "tns connect version 319 service \"ORCLPDB1\" sid \"ORCL\"",
            "tns",
        ),
        (
            "l7_iscsi",
            "iscsi login initiator \"iqn.2026-01.com.example:init1\" target \"iqn.2026-01.com.example:tgt1\" itt 0x10 cmdsn 2",
            "iscsi",
        ),
        (
            "l7_nvmetcp",
            "nvmetcp read nsid 1 qid 1 reqid 5 offset 0 count 4096",
            "nvmetcp read",
        ),
        (
            "l7_rtcp",
            "rtcp sr ssrc 0x11223344 packets 100 octets 64000 fraction 5",
            "rtcp sr",
        ),
        (
            "l7_turn",
            "turn allocate txid 0x10203040 lifetime 600 requestedtransport udp",
            "turn",
        ),
        (
            "l7_h323_tcp",
            "h323 connect callref 0x0042 callingparty \"1001\" calledparty \"2002\"",
            "h323 connect",
        ),
        (
            "l7_h323_udp",
            "h323 grq seqnum 12 rasaddr 10.10.1.1 1719",
            "h323 grq",
        ),
        (
            "l7_sccp",
            "sccp register devicename \"SEP001122334455\" addr 10.10.1.1 version 22",
            "sccp",
        ),
        (
            "l7_mgcp",
            "mgcp crcx txid 1001 endpoint \"aaln/1@gw1\" callid \"A1B2\" mode \"sendrecv\"",
            "mgcp",
        ),
    ];

    for &(label, stmt, kw) in cases {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }
}
