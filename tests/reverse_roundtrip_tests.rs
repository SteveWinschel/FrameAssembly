//! Comprehensive end-to-end round-trip verification suite (`fasm -> pcap -> reverse -> fasm -> pcap`)
//! for FrameAssembly's 5-stage PCAP and PCAPNG to `.fasm` reverse decompiler across all 81 native
//! Layer 2 through Layer 7 protocols.
//!
//! This integration test suite verifies that every protocol supported by FrameAssembly compiles to
//! binary PCAPNG frames, decompiles via [`frameassembly::reverse::reverse_pcap_bytes`],
//! [`frameassembly::reverse::reverse_pcap_reader`], and [`frameassembly::reverse::reverse_pcap_file`]
//! into canonical lowercase `.fasm` code (with zero `//` diagnostic comments, sequential `host_1` /
//! `host_2` topology discovery, and inline `compile { ... }` statements), and recompiles to
//! byte-for-byte identical Ethernet II wire frames with identical relative nanosecond timestamps.

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

/// Compiles `fasm_src`, decompiles the emitted PCAPNG via `reverse_pcap_bytes`, verifies canonical
/// formatting and presence of `expected_kw`, recompiles the decompiled `.fasm`, and asserts
/// byte-for-byte frame equality and relative timestamp preservation.
fn assert_protocol_roundtrip(label: &str, fasm_src: &str, expected_kw: &str) -> String {
    let prog = parse_program(fasm_src)
        .unwrap_or_else(|e| panic!("[{label}] failed to parse original .fasm: {e:?}"));
    validate_semantics(&prog, fasm_src)
        .unwrap_or_else(|e| panic!("[{label}] failed original semantic validation: {e:?}"));
    let orig_frames = compile_program(&prog)
        .unwrap_or_else(|e| panic!("[{label}] failed to compile original .fasm: {e}"));
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
        "[{label}] reversed .fasm must not contain comments:\n{}",
        rev.fasm
    );
    assert!(
        rev.fasm.contains("host host_1") && rev.fasm.contains("host host_2"),
        "[{label}] reversed .fasm must declare host_1 and host_2:\n{}",
        rev.fasm
    );
    assert!(
        !rev.fasm.contains("\nflow "),
        "[{label}] reversed .fasm must not emit flow blocks:\n{}",
        rev.fasm
    );
    assert!(
        rev.fasm.contains("compile {\n"),
        "[{label}] reversed .fasm must contain inline compile block:\n{}",
        rev.fasm
    );
    assert!(
        rev.fasm.contains(expected_kw),
        "[{label}] expected keyword '{expected_kw}' in reversed .fasm:\n{}",
        rev.fasm
    );

    let reprog = parse_program(&rev.fasm).unwrap_or_else(|e| {
        panic!(
            "[{label}] failed to re-parse decompiled .fasm: {e:?}\n--- FASM ---\n{}",
            rev.fasm
        )
    });
    validate_semantics(&reprog, &rev.fasm).unwrap_or_else(|e| {
        panic!(
            "[{label}] failed semantic validation on decompiled .fasm: {e:?}\n--- FASM ---\n{}",
            rev.fasm
        )
    });
    let reframes = compile_program(&reprog).unwrap_or_else(|e| {
        panic!(
            "[{label}] failed to re-compile decompiled .fasm: {e}\n--- FASM ---\n{}",
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
        "HOST h1 {{ IP 10.10.1.1 MAC 00:11:22:33:44:01 }}\n\
         HOST h2 {{ IP 10.10.1.2 MAC 00:11:22:33:44:02 }}\n\
         FLOW f(a, b) {{ a -> b {stmt_body} }}\n\
         COMPILE {{ f(h1, h2) }}\n"
    );
    assert_protocol_roundtrip(&format!("{label}_ipv4"), &v4_src, expected_kw);

    let v6_src = format!(
        "HOST h1 {{ IP 2001:db8:10::1 MAC 00:11:22:33:44:01 }}\n\
         HOST h2 {{ IP 2001:db8:10::2 MAC 00:11:22:33:44:02 }}\n\
         FLOW f(a, b) {{ a -> b {stmt_body} }}\n\
         COMPILE {{ f(h1, h2) }}\n"
    );
    assert_protocol_roundtrip(&format!("{label}_ipv6"), &v6_src, expected_kw);
}

/// Verifies round-trip decompilation and byte-identical recompilation across all 8 Layer 2 protocols
/// (`arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`).
#[test]
fn test_roundtrip_all_8_l2_protocols() {
    // 1. ARP (IPv4 Request + Reply, and Gratuitous ARP)
    let arp_v4 = r#"
        HOST a { IP 192.168.1.10 MAC 00:11:22:33:44:01 }
        HOST b { IP 192.168.1.20 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) {
            x -> y ARP REQUEST WAIT 5ms
            x <- y ARP REPLY WAIT 5ms
            x -> y ARP REQUEST GRATUITOUS WAIT 5ms
        }
        COMPILE { f(a, b) }
    "#;
    let fasm = assert_protocol_roundtrip("l2_arp_ipv4", arp_v4, "arp request");
    assert!(fasm.contains("arp reply") && fasm.contains("gratuitous"));

    // 2. Standalone pure-L2 protocols (`vlan`, `qinq`, `mpls`, `lldp`, `stp`, `lacp`, `eapol`)
    let l2_cases: &[(&str, &str, &str)] = &[
        (
            "l2_vlan",
            "VLAN 150 PCP 5 DEI 1 ETHERTYPE 0x88b5 PAYLOAD \"vlan-l2\"",
            "vlan 150",
        ),
        (
            "l2_qinq",
            "QINQ 200 INNER_VLAN 50 PCP 3 ETHERTYPE 0x88b5 PAYLOAD \"qinq-l2\"",
            "qinq 200 inner_vlan 50",
        ),
        (
            "l2_mpls",
            "MPLS 1048 EXP 4 BOS 1 MPLS_TTL 32 PAYLOAD \"mpls-l2\"",
            "mpls 1048",
        ),
        (
            "l2_lldp",
            "LLDP CHASSIS_ID \"core-01\" PORT_ID \"Gi0/1\" SYSNAME \"core01.local\" SYSDESC \"FrameAssembly Switch\"",
            "lldp",
        ),
        (
            "l2_stp",
            "STP RSTP",
            "stp",
        ),
        (
            "l2_lacp",
            "LACP ACTOR_KEY 10 PARTNER_KEY 10",
            "lacp",
        ),
        (
            "l2_eapol",
            "EAPOL TYPE START",
            "eapol",
        ),
    ];

    for &(label, stmt, kw) in l2_cases {
        let src = format!(
            "HOST s1 {{ MAC 00:11:22:33:44:01 }}\n\
             HOST s2 {{ MAC 00:11:22:33:44:02 }}\n\
             FLOW f(a, b) {{ a -> b {stmt} }}\n\
             COMPILE {{ f(s1, s2) }}\n"
        );
        assert_protocol_roundtrip(label, &src, kw);
    }
}

/// Verifies round-trip decompilation and byte-identical recompilation across all 20 Layer 3 protocols
/// (`icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`,
/// `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow`) over IPv4 and IPv6.
#[test]
fn test_roundtrip_all_20_l3_protocols() {
    // Dual-stack Layer 3 protocols (17 protocols working over both IPv4 and IPv6)
    let dual_stack_l3: &[(&str, &str, &str)] = &[
        (
            "l3_icmp",
            "ICMP ECHO_REQUEST ID 0x4321 SEQ 9 PAYLOAD \"ping-data\"",
            "icmp echo_request",
        ),
        ("l3_gre", "GRE GRE_KEY 1234 PAYLOAD \"inner_ip\"", "gre"),
        ("l3_vxlan", "VXLAN VNI 50010", "vxlan"),
        ("l3_geneve", "GENEVE VNI 60020", "geneve"),
        (
            "l3_ipsec",
            "IPSEC SPI 0x2000 SEQ 5 PAYLOAD \"ciphertext\"",
            "esp spi 0x2000 seq 5",
        ),
        (
            "l3_esp",
            "ESP SPI 0x3000 SEQ 7 PAYLOAD \"ciphertext\"",
            "esp spi 0x3000 seq 7",
        ),
        (
            "l3_ah",
            "AH SPI 0x4000 SEQ 11 PAYLOAD \"ah_payload\"",
            "ah spi 0x4000 seq 11",
        ),
        (
            "l3_ikev2",
            "IKEV2 EXCHANGE SA_INIT MSGID 0",
            "ikev2",
        ),
        (
            "l3_wireguard",
            "WIREGUARD TYPE INITIATION SENDER 0x01020304",
            "wireguard",
        ),
        (
            "l3_ospf",
            "OSPF HELLO ROUTER_ID 10.0.0.1 AREA_ID 0",
            "ospf hello",
        ),
        (
            "l3_bgp",
            "BGP OPEN ASN 65001 HOLDTIME 180 BGPID 10.0.0.1",
            "bgp open",
        ),
        (
            "l3_rip",
            "RIP RESPONSE PREFIX 10.0.0.0 METRIC 2",
            "rip reply",
        ),
        (
            "l3_vrrp",
            "VRRP VRID 10 PRIORITY 120",
            "vrrp",
        ),
        (
            "l3_hsrp",
            "HSRP GROUP 10 PRIORITY 110 VIP 10.10.1.254",
            "hsrp",
        ),
        ("l3_pim", "PIM HELLO", "pim hello"),
        (
            "l3_bfd",
            "BFD STATE 3 MY_DISC 100 YOUR_DISC 200",
            "bfd",
        ),
        (
            "l3_openflow",
            "OPENFLOW TYPE HELLO XID 0x00000010",
            "openflow",
        ),
    ];

    for &(label, stmt, kw) in dual_stack_l3 {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }

    // IPv4-specific L3 multicast protocol: IGMP
    let igmp_src = r#"
        HOST h1 { IP 10.10.1.1 MAC 00:11:22:33:44:01 }
        HOST h2 { IP 10.10.1.2 MAC 00:11:22:33:44:02 }
        FLOW f(a, b) {
            a -> b IGMP QUERY GROUP 224.0.0.1
            a <- b IGMP REPORT GROUP 239.1.2.3
        }
        COMPILE { f(h1, h2) }
    "#;
    assert_protocol_roundtrip("l3_igmp_ipv4", igmp_src, "igmp query");

    // IPv6-specific L3 control protocols: NDP and MLD
    let ndp_src = r#"
        HOST h1 { IP 2001:db8:10::1 MAC 00:11:22:33:44:01 }
        HOST h2 { IP 2001:db8:10::2 MAC 00:11:22:33:44:02 }
        FLOW f(a, b) {
            a -> b NDP NEIGHBOR_SOLICIT TARGET 2001:db8:10::2
            a <- b NDP NEIGHBOR_ADVERT TARGET 2001:db8:10::2
        }
        COMPILE { f(h1, h2) }
    "#;
    assert_protocol_roundtrip("l3_ndp_ipv6", ndp_src, "ndp neighbor_solicit");

    let mld_src = r#"
        HOST h1 { IP 2001:db8:10::1 MAC 00:11:22:33:44:01 }
        HOST h2 { IP 2001:db8:10::2 MAC 00:11:22:33:44:02 }
        FLOW f(a, b) {
            a -> b MLD QUERY MULTICAST_ADDR ff02::1
            a <- b MLD REPORT MULTICAST_ADDR ff02::1:ff00:1
        }
        COMPILE { f(h1, h2) }
    "#;
    assert_protocol_roundtrip("l3_mld_ipv6", mld_src, "mld query");
}

/// Verifies round-trip decompilation and byte-identical recompilation across all 3 Layer 4
/// transport protocols (`tcp`, `udp`, `sctp`) over both IPv4 and IPv6, including RFC 7323 TCP
/// options and SCTP chunk parameters.
#[test]
fn test_roundtrip_all_3_l4_protocols() {
    assert_dual_stack_roundtrip(
        "l4_tcp",
        "TCP SYN SEQ 2500 SRCPORT 54321 DSTPORT 8080 WIN 65535 MSS 1460 WSCALE 7 SACK_PERM TSVAL 1000 TSECR 0",
        "tcp syn",
    );
    assert_dual_stack_roundtrip(
        "l4_udp",
        "UDP SRCPORT 53000 DSTPORT 9999 PAYLOAD \"udp-datagram\"",
        "udp",
    );
    assert_dual_stack_roundtrip(
        "l4_sctp",
        "SCTP CHUNK DATA SRCPORT 2905 DSTPORT 2905 VTAG 0x12345678 TSN 100 STREAM 1 SSN 0 PPID 60 PAYLOAD \"sigtran\"",
        "sctp",
    );
}

/// Verifies round-trip decompilation and byte-identical recompilation across Layer 7
/// infrastructure, SNMP (`snmp1`, `snmp2`, `snmp3`), naming (`dns`, `mdns`), configuration
/// (`dhcp`), time (`ntp`, `ptp`), AAA (`radius`, `tacacs`), logging (`syslog`), and flow telemetry
/// (`netflow`, `ipfix`, `sflow`) protocols (14 protocols).
#[test]
fn test_roundtrip_l7_infra_snmp_and_telemetry_protocols() {
    let dual_stack_infra: &[(&str, &str, &str)] = &[
        (
            "l7_snmp1",
            "SNMP1 GET COMMUNITY \"public\" REQID 10 OID 1.3.6.1.2.1.1.1.0",
            "snmp1 get",
        ),
        (
            "l7_snmp2",
            "SNMP2 TRAP COMMUNITY \"public\" REQID 20 OID 1.3.6.1.6.3.1.1.5.3 VARBIND 1.3.6.1.2.1.1.5.0 STRING \"core-rtr\"",
            "snmp2 trap",
        ),
        (
            "l7_snmp3_cleartext",
            "SNMP3 GET USER \"admin\" ENGINEID \"8000000001\" ENGINEBOOTS 2 ENGINETIME 500 REQID 30 OID 1.3.6.1.2.1.1.1.0",
            "snmp3 get",
        ),
        (
            "l7_dns_udp",
            "DNS QUERY TXID 0x1a2b QNAME \"example.com\" QTYPE \"A\"",
            "dns query",
        ),
        (
            "l7_dns_tcp",
            "DNS QUERY TRANSPORT TCP TXID 0x2b3c QNAME \"example.com\" QTYPE \"AAAA\"",
            "dns query",
        ),
        (
            "l7_mdns",
            "MDNS QUERY QNAME \"printer.local\" QTYPE \"A\"",
            "mdns query",
        ),
        (
            "l7_ntp",
            "NTP VN 4 MODE 3 STRATUM 2 POLL 6 PRECISION -20 REFID \"GPS\"",
            "ntp",
        ),
        (
            "l7_ptp",
            "PTP SYNC DOMAIN 0 SEQ_ID 42",
            "ptp sync",
        ),
        (
            "l7_radius",
            "RADIUS ACCESS_REQUEST ID 5 USER \"alice\" SERVICE_TYPE 2",
            "radius access_request",
        ),
        (
            "l7_tacacs",
            "TACACS AUTHEN SEQ 1 SESSION_ID 0x11223344 USER \"netadmin\"",
            "tacacs",
        ),
        (
            "l7_syslog_udp",
            "SYSLOG FACILITY 4 SEVERITY 2 HOSTNAME \"fw01\" APP \"sshd\" MSG \"Accepted publickey\"",
            "syslog",
        ),
        (
            "l7_syslog_tcp",
            "SYSLOG TRANSPORT TCP FACILITY 1 SEVERITY 6 HOSTNAME \"web01\" APP \"nginx\" MSG \"GET /ok\"",
            "syslog",
        ),
        (
            "l7_netflow",
            "NETFLOW SRCIP 10.0.0.10 DSTIP 10.0.0.20 PROTO 6 PACKETS 12 OCTETS 1440",
            "netflow",
        ),
        (
            "l7_ipfix",
            "IPFIX DOMAIN_ID 100 SRCIP 10.0.0.10 DSTIP 10.0.0.20 PROTO 6 PACKETS 5 OCTETS 500",
            "ipfix",
        ),
        (
            "l7_sflow",
            "SFLOW SUB_AGENT_ID 1 SEQ 10 UPTIME 5000 SAMPLES 1",
            "sflow",
        ),
    ];

    for &(label, stmt, kw) in dual_stack_infra {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }

    // DHCPv4 (DISCOVER + OFFER) and DHCPv6 (SOLICIT + ADVERTISE)
    let dhcpv4_src = r#"
        HOST client { IP 10.10.1.10 MAC 00:11:22:33:44:01 }
        HOST server { IP 10.10.1.1  MAC 00:11:22:33:44:02 }
        FLOW f(c, s) {
            c -> s DHCP DISCOVER XID 0x11223344 HOSTNAME "laptop01"
            c <- s DHCP OFFER XID 0x11223344 YIADDR 10.10.1.50 SIADDR 10.10.1.1 SUBNET_MASK 255.255.255.0 ROUTER 10.10.1.1 DNS_SERVER 8.8.8.8 LEASE_TIME 3600
        }
        COMPILE { f(client, server) }
    "#;
    assert_protocol_roundtrip("l7_dhcp_ipv4", dhcpv4_src, "dhcp discover");

    let dhcpv6_src = r#"
        HOST client { IP 2001:db8:10::10 MAC 00:11:22:33:44:01 }
        HOST server { IP 2001:db8:10::1  MAC 00:11:22:33:44:02 }
        FLOW f(c, s) {
            c -> s DHCP SOLICIT XID 0x123456
            c <- s DHCP ADVERTISE XID 0x123456
        }
        COMPILE { f(client, server) }
    "#;
    assert_protocol_roundtrip("l7_dhcp_ipv6", dhcpv6_src, "dhcp solicit");
}

/// Verifies round-trip decompilation and byte-identical recompilation across Layer 7 web,
/// cloud-native, transport security, VoIP, and remote access protocols (`http`, `http2`, `grpc`,
/// `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`,
/// `stun`, `ssdp` — 16 protocols) over IPv4 and IPv6.
#[test]
fn test_roundtrip_l7_web_cloud_voip_and_access_protocols() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "l7_http",
            "HTTP GET URI \"/api/v1/status\" HOST_HDR \"example.local\" USER_AGENT \"FrameAssembly/1.5\"",
            "http get",
        ),
        (
            "l7_http2",
            "HTTP2 SETTINGS",
            "http2",
        ),
        (
            "l7_grpc",
            "GRPC SERVICE \"OrderService\" METHOD \"GetOrder\"",
            "grpc",
        ),
        (
            "l7_websocket",
            "WEBSOCKET OPCODE TEXT PAYLOAD \"ping\"",
            "websocket",
        ),
        (
            "l7_tls",
            "TLS CLIENT_HELLO SNI \"secure.example.com\"",
            "tls client_hello",
        ),
        (
            "l7_quic",
            "QUIC INITIAL DCID 0x01020304 SCID 0x05060708",
            "quic initial",
        ),
        (
            "l7_tftp",
            "TFTP RRQ FILENAME \"boot.img\" MODE \"octet\"",
            "tftp rrq",
        ),
        (
            "l7_ftp",
            "FTP CMD \"USER\" ARG \"anonymous\"",
            "ftp",
        ),
        (
            "l7_ssh",
            "SSH BANNER \"SSH-2.0-OpenSSH_9.0\"",
            "ssh",
        ),
        (
            "l7_telnet",
            "TELNET DO 1",
            "telnet",
        ),
        (
            "l7_whois",
            "WHOIS QUERY DOMAIN \"example.com\"",
            "whois",
        ),
        (
            "l7_sip_udp",
            "SIP INVITE FROM \"sip:alice@pbx\" TO \"sip:bob@pbx\" CALL_ID \"call123\"",
            "sip invite",
        ),
        (
            "l7_sip_tcp",
            "SIP INVITE TRANSPORT TCP FROM \"sip:alice@pbx\" TO \"sip:bob@pbx\" CALL_ID \"call123\"",
            "sip invite",
        ),
        (
            "l7_rtp",
            "RTP PT 0 SEQ 100 SSRC 0x12345678",
            "rtp",
        ),
        (
            "l7_rtsp",
            "RTSP OPTIONS URI \"rtsp://cam/live\" CSEQ 1",
            "rtsp options",
        ),
        (
            "l7_stun",
            "STUN BINDING_REQUEST TXID 0x11223344",
            "stun",
        ),
        (
            "l7_ssdp",
            "SSDP MSEARCH ST \"upnp:rootdevice\"",
            "ssdp",
        ),
    ];

    for &(label, stmt, kw) in cases {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }
}

/// Verifies round-trip decompilation and byte-identical recompilation across Layer 7 mail,
/// authentication, directory, storage, database, cache, messaging, and industrial OT protocols
/// (`smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`,
/// `postgres`, `mqtt`, `coap`, `amqp`, `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`,
/// `opcua` — 20 protocols) over IPv4 and IPv6.
#[test]
fn test_roundtrip_l7_data_storage_messaging_and_ot_protocols() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "l7_smtp",
            "SMTP EHLO \"mail.source.org\"",
            "smtp",
        ),
        (
            "l7_imap",
            "IMAP TAG \"A01\" CMD \"LOGIN\" ARG \"user pass\"",
            "imap",
        ),
        (
            "l7_pop3",
            "POP3 CMD \"USER\" ARG \"bob\"",
            "pop3",
        ),
        (
            "l7_kerberos_udp",
            "KERBEROS AS_REQ REALM \"CORP.LOCAL\"",
            "kerberos",
        ),
        (
            "l7_kerberos_tcp",
            "KERBEROS AS_REQ TRANSPORT TCP REALM \"CORP.LOCAL\"",
            "kerberos",
        ),
        (
            "l7_ldap",
            "LDAP BIND_REQ MSGID 1 BASE_DN \"dc=corp,dc=local\"",
            "ldap",
        ),
        (
            "l7_smb",
            "SMB COMMAND NEGOTIATE",
            "smb",
        ),
        (
            "l7_nfs_tcp",
            "NFS PROC LOOKUP PATH \"/exports/data\"",
            "nfs",
        ),
        (
            "l7_nfs_udp",
            "NFS TRANSPORT UDP PROC LOOKUP PATH \"/exports/data\"",
            "nfs",
        ),
        (
            "l7_redis",
            "REDIS CMD \"PING\"",
            "redis",
        ),
        (
            "l7_memcached_tcp",
            "MEMCACHED GET KEY \"session:123\"",
            "memcached",
        ),
        (
            "l7_memcached_udp",
            "MEMCACHED GET TRANSPORT UDP KEY \"session:123\"",
            "memcached",
        ),
        (
            "l7_mysql",
            "MYSQL QUERY SQL \"SELECT 1\"",
            "mysql",
        ),
        (
            "l7_postgres",
            "POSTGRES QUERY SQL \"SELECT version()\"",
            "postgres",
        ),
        (
            "l7_mqtt",
            "MQTT CONNECT CLIENT_ID \"sensor-01\"",
            "mqtt",
        ),
        (
            "l7_coap",
            "COAP CON GET URI_PATH \"/telemetry\"",
            "coap",
        ),
        (
            "l7_amqp",
            "AMQP PROTOCOL_HEADER",
            "amqp",
        ),
        (
            "l7_modbus_tcp",
            "MODBUS FUNC READ_HOLDING_REGISTERS ADDR 100 COUNT 5",
            "modbus",
        ),
        (
            "l7_modbus_udp",
            "MODBUS TRANSPORT UDP FUNC READ_HOLDING_REGISTERS ADDR 100 COUNT 5",
            "modbus",
        ),
        (
            "l7_bacnet",
            "BACNET WHO_IS",
            "bacnet",
        ),
        (
            "l7_dnp3_tcp",
            "DNP3 FUNC READ",
            "dnp3",
        ),
        (
            "l7_dnp3_udp",
            "DNP3 TRANSPORT UDP FUNC READ",
            "dnp3",
        ),
        (
            "l7_s7comm",
            "S7COMM FUNC READ_VAR",
            "s7comm",
        ),
        (
            "l7_ethernetip_tcp",
            "ETHERNETIP CMD LIST_IDENTITY",
            "ethernetip",
        ),
        (
            "l7_ethernetip_udp",
            "ETHERNETIP TRANSPORT UDP CMD LIST_IDENTITY",
            "ethernetip",
        ),
        (
            "l7_opcua",
            "OPCUA MSG_TYPE HEL",
            "opcua",
        ),
    ];

    for &(label, stmt, kw) in cases {
        assert_dual_stack_roundtrip(label, stmt, kw);
    }
}

/// Verifies shadow-state elision across a multi-packet TCP 3-way handshake + HTTP request/response
/// + FIN teardown, checking:
/// 1. Explicit `seq` emission on initial `syn` and `syn ack` when non-default ISNs are used.
/// 2. Elision of redundant `seq`, `acknum`, `srcport`, `dstport`, `ttl`, and `win` on subsequent
///    handshake, L7 HTTP, and teardown packets.
/// 3. Directional arrow locking (`host_1 -> host_2` vs `host_1 <- host_2`).
/// 4. Exact quantization of `wait` units (`ns`, `us`, `ms`, `s`, `m`) and elision of default `10ms`.
#[test]
fn test_shadow_state_elision_and_wait_quantization_tcp_http_session() {
    let session_src = r#"
        HOST client { IP 192.168.50.10 MAC 00:11:22:33:44:10 }
        HOST server { IP 192.168.50.80 MAC 00:11:22:33:44:80 }
        FLOW web_lifecycle(c, s) {
            c -> s TCP SYN SEQ 5000 SRCPORT 51234 DSTPORT 80
            c <- s TCP SYN ACK SEQ 9000 WAIT 500ns
            c -> s TCP ACK WAIT 250us
            c -> s HTTP GET URI "/api/status" HOST_HDR "status.local" WAIT 5ms
            c <- s HTTP STATUS 200 REASON "OK" BODY "healthy" WAIT 2s
            c -> s TCP FIN ACK WAIT 1m
            c <- s TCP FIN ACK WAIT 10ms
        }
        COMPILE { web_lifecycle(client, server) }
    "#;

    let fasm = assert_protocol_roundtrip("tcp_http_shadow_session", session_src, "http get");
    let stmt_lines: Vec<&str> = fasm
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("host_1 "))
        .collect();
    assert_eq!(
        stmt_lines.len(),
        7,
        "all 7 statements must lock host_1 on the left:\n{fasm}"
    );

    // Frame 1: Initial SYN emits explicit `seq 5000` and `srcport 51234` (dstport 80 is default)
    assert_eq!(
        stmt_lines[0],
        "host_1 -> host_2 tcp syn srcport 51234 seq 5000"
    );
    // Frame 2: SYN ACK uses `<-`, emits explicit `seq 9000`, elides `acknum 5001` & ports, quantizes `wait 500ns`
    assert_eq!(
        stmt_lines[1],
        "host_1 <- host_2 tcp syn ack seq 9000 wait 500ns"
    );
    // Frame 3: Third-leg ACK elides `seq`, `acknum`, `srcport`, `dstport`, `ttl`, `win`, quantizes `wait 250us`
    assert_eq!(stmt_lines[2], "host_1 -> host_2 tcp ack wait 250us");
    // Frame 4: HTTP GET elides `psh ack`, `seq`, `acknum`, `srcport`, `dstport`, quantizes `wait 5ms`
    assert_eq!(
        stmt_lines[3],
        "host_1 -> host_2 http get uri \"/api/status\" host_hdr \"status.local\" wait 5ms"
    );
    // Frame 5: HTTP 200 response uses `<-`, elides `seq`/`acknum`/ports, quantizes `wait 2s`
    assert_eq!(
        stmt_lines[4],
        "host_1 <- host_2 http status 200 body \"healthy\" wait 2s"
    );
    // Frame 6: Client FIN ACK elides `seq`/`acknum`/ports, quantizes `wait 1m`
    assert_eq!(stmt_lines[5], "host_1 -> host_2 tcp fin ack wait 1m");
    // Frame 7: Server FIN ACK elides `seq`/`acknum`/ports and elides default `10ms` wait!
    assert_eq!(stmt_lines[6], "host_1 <- host_2 tcp fin ack");
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
        HOST a { IP 10.20.30.1 MAC 00:11:22:33:44:01 }
        HOST b { IP 10.20.30.2 MAC 00:11:22:33:44:02 }
        FLOW f(x, y) {
            x -> y DNS QUERY TXID 0x1234 QNAME "example.org" QTYPE "A" WAIT 5ms
            x <- y DNS RESPONSE TXID 0x1234 QNAME "example.org" QTYPE "A" RDATA "93.184.216.34" WAIT 5ms
        }
        COMPILE { f(a, b) }
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

