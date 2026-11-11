//! Wave 1 wire-level regression test suite verifying deep RFC protocol header encoding,
//! dynamic L7 builder return-tuple preservation (`DHCP` / `DHCPv6`, `MDNS`, `PTP`, and `RADIUS`),
//! sequential statement port disambiguation on shared host pairs, default Hop Limit / TTL `255`
//! enforcement (`NDP`, `VRRP`, and IPv6 `ARP`), RFC 1071 and RFC 5798 pseudo-header checksums,
//! minimum tunnel envelopes (`GENEVE` and `WIREGUARD`), ASN.1 BER / ONC-RPC XDR framing (`LDAP`,
//! `KERBEROS`, `NFS`, and `SNMP`), and complete AST `*Spec` field-to-wire synthesis across L2, L3,
//! and L7 builders.

use frameassembly::backend::compile_program;
use frameassembly::packet::internet_checksum;
use frameassembly::parser::parse_program;

/// Parses and compiles a FrameAssembly `.fasm` source string into raw wire frames.
fn compile_frames(fasm: &str) -> Vec<Vec<u8>> {
    let program = parse_program(fasm).expect("FASM program should parse cleanly");
    compile_program(&program)
        .expect("FASM program should compile cleanly")
        .into_iter()
        .map(|(bytes, _ts)| bytes)
        .collect()
}

/// Extracts `(sport, dport, payload)` from an Ethernet II + IPv4 (20B) + UDP (8B) frame.
fn ipv4_udp_parts(pkt: &[u8]) -> (u16, u16, &[u8]) {
    assert_eq!(&pkt[12..14], &[0x08, 0x00], "expected IPv4 EtherType");
    assert_eq!(pkt[23], 17, "expected IPv4 UDP protocol 17");
    (u16::from_be_bytes([pkt[34], pkt[35]]), u16::from_be_bytes([pkt[36], pkt[37]]), &pkt[42..])
}

/// Extracts `(sport, dport, payload)` from an Ethernet II + IPv6 (40B) + UDP (8B) frame.
fn ipv6_udp_parts(pkt: &[u8]) -> (u16, u16, &[u8]) {
    assert_eq!(&pkt[12..14], &[0x86, 0xDD], "expected IPv6 EtherType");
    assert_eq!(pkt[20], 17, "expected IPv6 Next Header 17 (UDP)");
    (u16::from_be_bytes([pkt[54], pkt[55]]), u16::from_be_bytes([pkt[56], pkt[57]]), &pkt[62..])
}

/// Extracts `(sport, dport, payload)` from an Ethernet II + IPv4 (20B) + TCP (20B) frame.
fn ipv4_tcp_parts(pkt: &[u8]) -> (u16, u16, &[u8]) {
    assert_eq!(&pkt[12..14], &[0x08, 0x00], "expected IPv4 EtherType for TCP");
    assert_eq!(pkt[23], 6, "expected IPv4 TCP protocol 6");
    (u16::from_be_bytes([pkt[34], pkt[35]]), u16::from_be_bytes([pkt[36], pkt[37]]), &pkt[54..])
}

/// Checks whether `haystack` contains the contiguous byte slice `needle`.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// --- Category 1: l7_dispatch.rs Return-Tuple & Sequential Port Preservation ---

/// Verifies DHCPv6 (`546 <-> 547` + Option 1 DUID-LL from `CHADDR`) and DHCPv4 (`68 <-> 67`) ports.
#[test]
fn test_dhcpv6_solicit_advertise_ports_and_duid_ll() {
    let dhcp_frames = compile_frames(r#"
        host v6_cli { ip 2001:db8:10::c1 mac 00:11:22:33:44:55 }
        host v6_srv { ip 2001:db8:10::a1 mac 00:11:22:33:44:66 }
        host v4_cli { ip 10.10.1.50 mac 00:aa:bb:cc:dd:01 }
        host v4_srv { ip 10.10.1.1  mac 00:aa:bb:cc:dd:02 }
        flow dhcp6_exchange(c, s) {
            c -> s dhcp solicit xid 0x112233 chaddr 00:11:22:33:44:55 wait 1ms
            c <- s dhcp advertise xid 0x112233 wait 1ms
        }
        flow dhcp4_exchange(c, s) {
            c -> s dhcp discover xid 0x44556677 chaddr 00:aa:bb:cc:dd:01 wait 1ms
            c <- s dhcp offer xid 0x44556677 yiaddr 10.10.1.50 wait 1ms
        }
        compile {
            dhcp6_exchange(v6_cli, v6_srv)
            dhcp4_exchange(v4_cli, v4_srv)
        }
    "#);
    assert_eq!(dhcp_frames.len(), 4, "expected 4 DHCP frames");
    let (s0, d0, l7_0) = ipv6_udp_parts(&dhcp_frames[0]);
    assert_eq!((s0, d0), (546, 547));
    assert_eq!(l7_0[0], 1); // Msg-Type 1 = SOLICIT
    assert_eq!(&l7_0[1..4], &[0x11, 0x22, 0x33]);
    // Option 1 (Client ID = 0x0001), len 10 (0x000a), DUID-LL (0x0003), HW Ethernet (0x0001), MAC
    assert_eq!(&l7_0[4..18], &[0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let (s1, d1, l7_1) = ipv6_udp_parts(&dhcp_frames[1]);
    assert_eq!((s1, d1), (547, 546));
    assert_eq!(l7_1[0], 2); // Msg-Type 2 = ADVERTISE
    let (s2, d2, _) = ipv4_udp_parts(&dhcp_frames[2]);
    assert_eq!((s2, d2), (68, 67));
    let (s3, d3, _) = ipv4_udp_parts(&dhcp_frames[3]);
    assert_eq!((s3, d3), (67, 68));
}

/// Verifies `MDNS` auto-routes to multicast IPs (`224.0.0.251` and `ff02::fb`), multicast MACs, and UDP `5353`.
#[test]
fn test_mdns_multicast_ipv4_and_ipv6_dest_and_mac() {
    let mdns_frames = compile_frames(r#"
        host apple_v4 { ip 192.168.50.10 mac 00:1c:42:aa:bb:01 }
        host peer_v4  { ip 192.168.50.20 mac 00:1c:42:aa:bb:02 }
        host apple_v6 { ip fe80::10      mac 00:1c:42:aa:bb:03 }
        host peer_v6  { ip fe80::20      mac 00:1c:42:aa:bb:04 }
        flow mdns_cast(a, b) {
            a -> b mdns query qname "_http._tcp.local" wait 1ms
            a <- b mdns response qname "_http._tcp.local" rdata "192.168.50.10" wait 1ms
        }
        compile {
            mdns_cast(apple_v4, peer_v4)
            mdns_cast(apple_v6, peer_v6)
        }
    "#);
    assert_eq!(mdns_frames.len(), 4, "expected 4 mDNS frames");
    // IPv4 mDNS: dst MAC = 01:00:5e:00:00:fb, dst IP = 224.0.0.251, UDP dport = 5353
    assert_eq!(&mdns_frames[0][0..6], &[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    assert_eq!(&mdns_frames[0][30..34], &[224, 0, 0, 251]);
    let (_, dport_v4, l7_v4_q) = ipv4_udp_parts(&mdns_frames[0]);
    assert_eq!(dport_v4, 5353);
    assert_eq!(u16::from_be_bytes([l7_v4_q[2], l7_v4_q[3]]) & 0x8000, 0x0000);
    let (_, dport_v4_r, l7_v4_r) = ipv4_udp_parts(&mdns_frames[1]);
    assert_eq!(dport_v4_r, 5353);
    assert_eq!(u16::from_be_bytes([l7_v4_r[2], l7_v4_r[3]]) & 0x8000, 0x8000);
    // IPv6 mDNS: dst MAC = 33:33:00:00:00:fb, dst IP = ff02::fb, UDP dport = 5353
    assert_eq!(&mdns_frames[2][0..6], &[0x33, 0x33, 0x00, 0x00, 0x00, 0xfb]);
    assert_eq!(&mdns_frames[2][38..54], &[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0xfb]);
    let (_, dport_v6, _) = ipv6_udp_parts(&mdns_frames[2]);
    assert_eq!(dport_v6, 5353);
}

/// Verifies sequential `PTP` Event (`319`) vs General (`320`) ports on the same host pair and `messageLength`.
#[test]
fn test_ptp_event_vs_general_sequential_port_routing_and_payload_len() {
    let ptp_frames = compile_frames(r#"
        host gm_clock    { ip 172.16.80.1 mac 00:50:c2:11:22:01 }
        host slave_clock { ip 172.16.80.2 mac 00:50:c2:11:22:02 }
        flow ptp_sync_cycle(m, s) {
            m -> s ptp sync domain 1 seqid 10 wait 1ms
            m -> s ptp followup domain 1 seqid 10 wait 1ms
            s -> m ptp delayreq domain 1 seqid 11 wait 1ms
            m -> s ptp delayresp domain 1 seqid 11 wait 1ms
            m -> s ptp announce domain 1 seqid 12 payload "ptp_ext" wait 1ms
        }
        compile { ptp_sync_cycle(gm_clock, slave_clock) }
    "#);
    assert_eq!(ptp_frames.len(), 5, "expected 5 PTP frames");
    let (_, dport0, l7_0) = ipv4_udp_parts(&ptp_frames[0]);
    assert_eq!((dport0, l7_0[0] & 0x0F), (319, 0x00)); // SYNC
    let (_, dport1, l7_1) = ipv4_udp_parts(&ptp_frames[1]);
    assert_eq!((dport1, l7_1[0] & 0x0F), (320, 0x08)); // FOLLOW_UP
    let (_, dport2, l7_2) = ipv4_udp_parts(&ptp_frames[2]);
    assert_eq!((dport2, l7_2[0] & 0x0F), (319, 0x01)); // DELAY_REQ
    let (_, dport3, l7_3) = ipv4_udp_parts(&ptp_frames[3]);
    assert_eq!((dport3, l7_3[0] & 0x0F), (320, 0x09)); // DELAY_RESP
    let (_, dport4, l7_4) = ipv4_udp_parts(&ptp_frames[4]);
    assert_eq!((dport4, l7_4[0] & 0x0F), (320, 0x0B)); // ANNOUNCE
    assert_eq!(u16::from_be_bytes([l7_4[2], l7_4[3]]), 51); // 44B PTP body + 7B "ptp_ext"
    assert_eq!(l7_4.len(), 51);
}

/// Verifies sequential `RADIUS` Auth (`1812`) vs Accounting (`1813`) ports and IPv6 AVPs (`95` and `168`).
#[test]
fn test_radius_auth_vs_accounting_sequential_ports_and_ipv6_avps() {
    let rad_frames = compile_frames(r#"
        host nas_v4 { ip 10.200.1.10 mac 00:21:55:00:01:01 }
        host aaa_v4 { ip 10.200.1.20 mac 00:21:55:00:01:02 }
        host nas_v6 { ip 2001:db8:aaa::10 mac 00:21:55:00:02:01 }
        host aaa_v6 { ip 2001:db8:aaa::20 mac 00:21:55:00:02:02 }
        flow radius_v4_flow(c, s) {
            c -> s radius accessrequest id 10 user "alice" wait 1ms
            c <- s radius accessaccept id 10 wait 1ms
            c -> s radius accountingrequest id 11 user "alice" wait 1ms
            c <- s radius accountingresponse id 11 wait 1ms
        }
        flow radius_v6_flow(c, s) {
            c -> s radius accessrequest id 20 user "bob" nasip 2001:db8::1 framedip 2001:db8::2 wait 1ms
        }
        compile {
            radius_v4_flow(nas_v4, aaa_v4)
            radius_v6_flow(nas_v6, aaa_v6)
        }
    "#);
    assert_eq!(rad_frames.len(), 5, "expected 5 RADIUS frames");
    let (_, d0, l7_0) = ipv4_udp_parts(&rad_frames[0]);
    assert_eq!((d0, l7_0[0]), (1812, 1)); // Access-Request
    let (s1, _, l7_1) = ipv4_udp_parts(&rad_frames[1]);
    assert_eq!((s1, l7_1[0]), (1812, 2)); // Access-Accept
    let (_, d2, l7_2) = ipv4_udp_parts(&rad_frames[2]);
    assert_eq!((d2, l7_2[0]), (1813, 4)); // Accounting-Request
    let (s3, _, l7_3) = ipv4_udp_parts(&rad_frames[3]);
    assert_eq!((s3, l7_3[0]), (1813, 5)); // Accounting-Response
    let (_, d4, l7_4) = ipv6_udp_parts(&rad_frames[4]);
    assert_eq!(d4, 1812);
    // AVP 95 (NAS-IPv6-Address, len 18) and AVP 168 (Framed-IPv6-Address, len 18)
    let mut expected_nas_v6 = vec![95u8, 18u8];
    expected_nas_v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mut expected_framed_v6 = vec![168u8, 18u8];
    expected_framed_v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    assert!(contains_subslice(l7_4, &expected_nas_v6));
    assert!(contains_subslice(l7_4, &expected_framed_v6));
}

// --- Category 2: Default RFC TTL / Hop Limit = 255 ---

/// Verifies default Hop Limit / TTL `255` on `NDP`, `VRRP` (IPv4 and IPv6), and IPv6 `ARP`.
#[test]
fn test_default_hop_limit_and_ttl_255_for_ndp_vrrp_and_ipv6_arp() {
    let hop_frames = compile_frames(r#"
        host rtr_v6_a { ip fe80::a1 mac 00:10:94:00:01:01 }
        host rtr_v6_b { ip fe80::b2 mac 00:10:94:00:01:02 }
        host rtr_v4_a { ip 192.168.100.2 mac 00:10:94:00:02:01 }
        host rtr_v4_b { ip 192.168.100.3 mac 00:10:94:00:02:02 }
        flow l3_hop255_v6(a, b) {
            a -> b ndp neighborsolicit target fe80::b2 wait 1ms
            a -> b vrrp vrid 10 priority 150 vip fe80::1 wait 1ms
            a -> b arp request wait 1ms
            a <- b arp reply wait 1ms
        }
        flow l3_ttl255_v4(a, b) {
            a -> b vrrp vrid 10 priority 150 vip 192.168.100.1 wait 1ms
        }
        compile {
            l3_hop255_v6(rtr_v6_a, rtr_v6_b)
            l3_ttl255_v4(rtr_v4_a, rtr_v4_b)
        }
    "#);
    assert_eq!(hop_frames.len(), 5, "expected 5 TTL/HopLimit=255 frames");
    assert_eq!((hop_frames[0][21], hop_frames[0][54]), (255, 135)); // NDP NS
    assert_eq!(hop_frames[1][21], 255); // VRRP over IPv6
    assert_eq!((hop_frames[2][21], hop_frames[2][54]), (255, 135)); // IPv6 ARP REQUEST -> NDP NS
    assert_eq!((hop_frames[3][21], hop_frames[3][54]), (255, 136)); // IPv6 ARP REPLY -> NDP NA
    assert_eq!(hop_frames[4][22], 255); // VRRP over IPv4 TTL
}

// --- Category 3: Broken RFC Wire Headers, Checksums, Lengths & 1-Arc OID Rejection ---

/// Verifies `GRE CHECKSUM` and `GRE_SEQ` / `SEQ` wire encoding and RFC 1071 checksum validity.
#[test]
fn test_gre_checksum_and_sequence_number_wire_encoding() {
    let gre_frames = compile_frames(r#"
        host tun_left  { ip 172.31.0.1 mac 00:16:3e:10:01:01 }
        host tun_right { ip 172.31.0.2 mac 00:16:3e:10:01:02 }
        flow gre_tunnel(a, b) {
            a -> b gre checksum greseq 99 payload "inner1" wait 1ms
            b -> a gre checksum key 0xAABBCCDD seq 77 payload "inner2" wait 1ms
        }
        compile { gre_tunnel(tun_left, tun_right) }
    "#);
    assert_eq!(gre_frames.len(), 2, "expected 2 GRE frames");
    // Frame 0: C (0x8000) | S (0x1000) => 0x9000, proto 0x0800, 4B checksum+res1, 4B seq=99
    assert_eq!(gre_frames[0][23], 47);
    let gre0 = &gre_frames[0][34..];
    assert_eq!(&gre0[0..4], &[0x90, 0x00, 0x08, 0x00]);
    assert_ne!(u16::from_be_bytes([gre0[4], gre0[5]]), 0);
    assert_eq!(internet_checksum(&[gre0]), 0);
    assert_eq!(u32::from_be_bytes([gre0[8], gre0[9], gre0[10], gre0[11]]), 99);
    // Frame 1: C (0x8000) | K (0x2000) | S (0x1000) => 0xB000, 4B checksum+res1, 4B key, 4B seq=77
    let gre1 = &gre_frames[1][34..];
    assert_eq!(&gre1[0..4], &[0xB0, 0x00, 0x08, 0x00]);
    assert_ne!(u16::from_be_bytes([gre1[4], gre1[5]]), 0);
    assert_eq!(internet_checksum(&[gre1]), 0);
    assert_eq!(u32::from_be_bytes([gre1[8], gre1[9], gre1[10], gre1[11]]), 0xAABB_CCDD);
    assert_eq!(u32::from_be_bytes([gre1[12], gre1[13], gre1[14], gre1[15]]), 77);
}

/// Verifies `VRRP` v3 RFC 5798 pseudo-header checksums (IPv4 and IPv6) vs `VRRP` v2 RFC 3768 checksum.
#[test]
fn test_vrrp_v3_and_v2_checksums_and_multicast_headers() {
    let vrrp_frames = compile_frames(r#"
        host gw4_pri { ip 10.55.0.2 mac 00:00:5e:00:01:05 }
        host gw4_bak { ip 10.55.0.3 mac 00:00:5e:00:01:06 }
        host gw6_pri { ip fe80::55:2 mac 00:00:5e:00:02:05 }
        host gw6_bak { ip fe80::55:3 mac 00:00:5e:00:02:06 }
        flow vrrp4_flow(a, b) {
            a -> b vrrp version 3 vrid 5 priority 120 vip 10.55.0.1 wait 1ms
            a -> b vrrp version 2 vrid 5 priority 120 vip 10.55.0.1 wait 1ms
        }
        flow vrrp6_flow(a, b) {
            a -> b vrrp version 3 vrid 5 priority 120 vip fe80::55:1 wait 1ms
        }
        compile {
            vrrp4_flow(gw4_pri, gw4_bak)
            vrrp6_flow(gw6_pri, gw6_bak)
        }
    "#);
    assert_eq!(vrrp_frames.len(), 3, "expected 3 VRRP frames");
    // Frame 0: VRRPv3 over IPv4 (dst 224.0.0.18, proto 112), RFC 5798 pseudo-header checksum
    assert_eq!(&vrrp_frames[0][30..34], &[224, 0, 0, 18]);
    let vrrp_v3_4 = &vrrp_frames[0][34..];
    assert_eq!(vrrp_v3_4[0], 0x31);
    let mut pseudo4 = Vec::with_capacity(12);
    pseudo4.extend_from_slice(&vrrp_frames[0][26..34]);
    pseudo4.extend_from_slice(&[0x00, 112]);
    pseudo4.extend_from_slice(&u16::try_from(vrrp_v3_4.len()).unwrap().to_be_bytes());
    assert_eq!(internet_checksum(&[&pseudo4, vrrp_v3_4]), 0);
    // Frame 1: VRRPv2 over IPv4 (20 bytes including 8B zero auth data), RFC 3768 direct checksum
    let vrrp_v2_4 = &vrrp_frames[1][34..];
    assert_eq!((vrrp_v2_4[0], vrrp_v2_4.len()), (0x21, 20));
    assert_eq!(&vrrp_v2_4[12..20], &[0u8; 8]);
    assert_eq!(internet_checksum(&[vrrp_v2_4]), 0);
    // Frame 2: VRRPv3 over IPv6 (dst ff02::12, next header 112), RFC 5798 IPv6 pseudo-header checksum
    let vrrp_v3_6 = &vrrp_frames[2][54..];
    assert_eq!(vrrp_v3_6[0], 0x31);
    let mut pseudo6 = Vec::with_capacity(40);
    pseudo6.extend_from_slice(&vrrp_frames[2][22..54]);
    pseudo6.extend_from_slice(&u32::try_from(vrrp_v3_6.len()).unwrap().to_be_bytes());
    pseudo6.extend_from_slice(&[0x00, 0x00, 0x00, 112]);
    assert_eq!(internet_checksum(&[&pseudo6, vrrp_v3_6]), 0);
}

/// Verifies `GENEVE` minimum 50-byte inner frame encapsulation and `WIREGUARD` 32-byte Type 4 AEAD envelope.
#[test]
fn test_geneve_and_wireguard_minimum_wire_envelopes() {
    let tun_frames = compile_frames(r#"
        host nve_a { ip 10.77.0.1 mac 00:1b:21:77:00:01 }
        host nve_b { ip 10.77.0.2 mac 00:1b:21:77:00:02 }
        flow overlay_flow(a, b) {
            a -> b geneve vni 5000 wait 1ms
            a -> b wireguard data receiver 7 counter 42 wait 1ms
        }
        compile { overlay_flow(nve_a, nve_b) }
    "#);
    assert_eq!(tun_frames.len(), 2, "expected 2 overlay frames");
    // GENEVE: 8B GENEVE header (proto 0x6558, VNI 5000) + 42B inner frame = 50 bytes
    let (_, dport_gen, geneve) = ipv4_udp_parts(&tun_frames[0]);
    assert_eq!((dport_gen, geneve.len()), (6081, 50));
    assert_eq!(&geneve[2..4], &[0x65, 0x58]);
    assert_eq!(u32::from_be_bytes([0, geneve[4], geneve[5], geneve[6]]), 5000);
    // WIREGUARD DATA: Type 4 (16B header) + 16B Poly1305 AEAD tag = 32 bytes
    let (_, dport_wg, wg) = ipv4_udp_parts(&tun_frames[1]);
    assert_eq!((dport_wg, wg[0]), (51820, 4));
    assert!(wg.len() >= 32);
    assert_eq!(u32::from_le_bytes([wg[4], wg[5], wg[6], wg[7]]), 7);
    assert_eq!(u64::from_le_bytes([wg[8], wg[9], wg[10], wg[11], wg[12], wg[13], wg[14], wg[15]]), 42);
}

/// Verifies `STP RSTP` emits a 36-byte BPDU (`Version 1 Length = 0`) and parses `"<priority>/<mac>"` IDs.
#[test]
fn test_stp_rstp_36_byte_bpdu_and_bridge_id_parsing() {
    let rstp_frames = compile_frames(r#"
        host sw_root { ip 10.88.0.1 mac 00:11:22:33:44:55 }
        host sw_edge { ip 10.88.0.2 mac 00:aa:bb:cc:dd:ee }
        flow rstp_flow(a, b) {
            a -> b stp rstp rootid "4096/00:11:22:33:44:55" bridgeid "32768/00:aa:bb:cc:dd:ee" portid 0x8002 cost 2000 wait 1ms
        }
        compile { rstp_flow(sw_root, sw_edge) }
    "#);
    let pkt = &rstp_frames[0];
    assert_eq!(&pkt[0..6], &[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
    assert_eq!(u16::from_be_bytes([pkt[12], pkt[13]]), 39);
    assert_eq!(&pkt[14..17], &[0x42, 0x42, 0x03]); // LLC DSAP/SSAP/Control
    let bpdu = &pkt[17..];
    assert_eq!((bpdu.len(), bpdu[2], bpdu[3], bpdu[35]), (36, 2, 2, 0x00));
    assert_eq!(&bpdu[5..13], &[0x10, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // 4096 + root MAC
    assert_eq!(&bpdu[17..25], &[0x80, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]); // 32768 + bridge MAC
}

/// Verifies `EAPOL` EAP-Success (`3`) and EAP-Failure (`4`) emit a strict 4-byte EAP body (`0x0004`).
#[test]
fn test_eapol_success_and_failure_4_byte_eap_body() {
    let eapol_frames = compile_frames(r#"
        host auth_sw { ip 10.89.0.1 mac 00:1d:71:00:01:01 }
        host supp_pc { ip 10.89.0.2 mac 00:1d:71:00:01:02 }
        flow dot1x_result(s, c) {
            s -> c eapol eapcode 3 eapid 7 wait 1ms
            s -> c eapol eapcode 4 eapid 8 wait 1ms
        }
        compile { dot1x_result(auth_sw, supp_pc) }
    "#);
    for (idx, (code, id)) in [(3u8, 7u8), (4u8, 8u8)].into_iter().enumerate() {
        assert_eq!(&eapol_frames[idx][12..14], &[0x88, 0x8e]);
        let eapol = &eapol_frames[idx][14..];
        assert_eq!(eapol.len(), 8); // 4B EAPOL header + 4B EAP packet
        assert_eq!(&eapol[2..8], &[0x00, 0x04, code, id, 0x00, 0x04]);
    }
}

/// Verifies `QUIC` `INITIAL` token + RFC 9000 §16 2-byte varint length (`01` prefix) and all header forms.
#[test]
fn test_quic_long_and_short_headers_token_and_2byte_varint_len() {
    let quic_frames = compile_frames(r#"
        host q_cli { ip 10.90.0.10 mac 00:22:44:66:88:01 }
        host q_srv { ip 10.90.0.20 mac 00:22:44:66:88:02 }
        flow quic_all(c, s) {
            c -> s quic initial version 1 dcid 0x11223344 scid 0x55667788 token "retry_tok" pktnum 5 payload "hello" wait 1ms
            c -> s quic zerortt version 1 dcid 0x11223344 scid 0x55667788 pktnum 6 payload "early" wait 1ms
            s -> c quic handshake version 1 dcid 0x55667788 scid 0x11223344 pktnum 7 payload "hs" wait 1ms
            s -> c quic retry version 1 dcid 0x55667788 scid 0x11223344 token "srv_tok" wait 1ms
            c -> s quic short dcid 0x11223344 pktnum 8 payload "1rtt" wait 1ms
        }
        compile { quic_all(q_cli, q_srv) }
    "#);
    assert_eq!(quic_frames.len(), 5, "expected 5 QUIC frames");
    let (_, d0, q_init) = ipv4_udp_parts(&quic_frames[0]);
    assert_eq!((d0, q_init[0]), (443, 0xC0)); // Long Header Initial
    assert!(contains_subslice(q_init, b"retry_tok"));
    // Offset 25: 2-byte varint length with 01 prefix (0x40), value = 6 (1B pkt_num + 5B "hello")
    assert_eq!(q_init[25] & 0xC0, 0x40);
    assert_eq!(u16::from_be_bytes([q_init[25] & 0x3F, q_init[26]]), 6);
    assert_eq!(q_init[27], 5);
    assert_eq!(ipv4_udp_parts(&quic_frames[1]).2[0], 0xD0); // ZERO_RTT
    assert_eq!(ipv4_udp_parts(&quic_frames[2]).2[0], 0xE0); // HANDSHAKE
    let (_, _, q_retry) = ipv4_udp_parts(&quic_frames[3]);
    assert_eq!(q_retry[0], 0xF0);
    assert!(contains_subslice(q_retry, b"srv_tok"));
    assert_eq!(ipv4_udp_parts(&quic_frames[4]).2[0], 0x40); // SHORT
}

/// Verifies `IPFIX` payload length inclusion in `total_len`/`set_len` and `SFLOW` 68-byte v5 sample header.
#[test]
fn test_ipfix_and_sflow_datagram_lengths_and_headers() {
    let tel_frames = compile_frames(r#"
        host exporter  { ip 10.91.0.1 mac 00:25:90:01:01:01 }
        host collector { ip 10.91.0.2 mac 00:25:90:01:01:02 }
        flow telemetry_flow(e, c) {
            e -> c ipfix domainid 100 packets 5 octets 500 payload "extra_ie" wait 1ms
            e -> c sflow agentip 10.20.30.40 subagentid 3 seq 12 uptime 9000 samples 1 wait 1ms
        }
        compile { telemetry_flow(exporter, collector) }
    "#);
    let (_, dport_ipfix, ipfix) = ipv4_udp_parts(&tel_frames[0]);
    assert_eq!((dport_ipfix, u16::from_be_bytes([ipfix[0], ipfix[1]])), (4739, 10));
    let total_len = u16::from_be_bytes([ipfix[2], ipfix[3]]);
    let set_len = u16::from_be_bytes([ipfix[18], ipfix[19]]);
    assert_eq!(usize::from(total_len), ipfix.len());
    assert_eq!((total_len, set_len), (16 + set_len, 41)); // 4B set hdr + 29B record + 8B "extra_ie"
    // SFLOW: 28B datagram header + 8B sample T/L (len=32) + 32B (8 u32 fields) Flow Sample = 68B
    let (_, dport_sflow, sflow) = ipv4_udp_parts(&tel_frames[1]);
    assert_eq!((dport_sflow, sflow.len()), (6343, 68));
    assert_eq!(&sflow[8..12], &[10, 20, 30, 40]);
    assert_eq!(u32::from_be_bytes([sflow[12], sflow[13], sflow[14], sflow[15]]), 3);
    assert_eq!(u32::from_be_bytes([sflow[32], sflow[33], sflow[34], sflow[35]]), 32);
}

/// Verifies `LDAP` 8-element `SearchRequest`, `KERBEROS` `till`/`nonce` tags, `NFS` XDR `TAG`/`PATH`, and `S7COMM` 12B `ACK_DATA`.
#[test]
fn test_ldap_kerberos_nfs_and_s7comm_wire_structures() {
    let ent_frames = compile_frames(r#"
        host app_cli { ip 10.92.0.10 mac 00:30:48:11:01:01 }
        host app_srv { ip 10.92.0.20 mac 00:30:48:11:01:02 }
        flow enterprise_flow(c, s) {
            c -> s ldap msgid 2 searchreq basedn "dc=example,dc=org" filter "(cn=*)" wait 1ms
            c -> s ldap msgid 3 bindreq basedn "cn=admin" wait 1ms
            s -> c ldap msgid 3 bindres resultcode 49 wait 1ms
            s -> c ldap msgid 2 searchentry basedn "cn=alice,dc=example,dc=org" wait 1ms
            s -> c ldap msgid 2 searchdone resultcode 0 wait 1ms
            c -> s ldap msgid 4 unbindreq wait 1ms
            c -> s kerberos asreq realm "ATHENA.MIT.EDU" cname "alice" sname "krbtgt" etype 18 wait 1ms
            s -> c kerberos asrep realm "ATHENA.MIT.EDU" cname "alice" etype 18 wait 1ms
            c -> s kerberos tgsreq realm "ATHENA.MIT.EDU" cname "alice" sname "ldap" etype 18 wait 1ms
            s -> c kerberos tgsrep realm "ATHENA.MIT.EDU" cname "alice" etype 18 wait 1ms
            s -> c kerberos krberror realm "ATHENA.MIT.EDU" sname "krbtgt" wait 1ms
            c -> s nfs compound xid 0x11223344 vers 4 tag "nfs_tag" path "/export/vol" wait 1ms
            c -> s s7comm rosctr "job" pduref 4 wait 1ms
            s -> c s7comm rosctr "ack" pduref 5 wait 1ms
            s -> c s7comm rosctr "ackdata" pduref 6 wait 1ms
        }
        compile { enterprise_flow(app_cli, app_srv) }
    "#);
    assert_eq!(ent_frames.len(), 15, "expected 15 enterprise frames");
    let (_, d_ldap, ldap_sr) = ipv4_tcp_parts(&ent_frames[0]);
    assert_eq!((d_ldap, ldap_sr[0], ldap_sr[5]), (389, 0x30, 0x63));
    assert!(contains_subslice(ldap_sr, b"dc=example,dc=org"));
    assert!(contains_subslice(ldap_sr, &[0x0a, 0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x02, b'c', b'n', 0x30, 0x00]));
    assert_eq!(ipv4_tcp_parts(&ent_frames[1]).2[5], 0x60);
    assert_eq!(ipv4_tcp_parts(&ent_frames[2]).2[5], 0x61);
    assert_eq!(ipv4_tcp_parts(&ent_frames[3]).2[5], 0x64);
    assert_eq!(ipv4_tcp_parts(&ent_frames[4]).2[5], 0x65);
    assert_eq!(ipv4_tcp_parts(&ent_frames[5]).2[5], 0x42);
    // KERBEROS AS-REQ (0x6A): contains [7] till (0xA7 -> 0x18 GeneralizedTime) and [8] nonce (0xA8 -> 0x02)
    let (_, d_krb, krb_as_req) = ipv4_udp_parts(&ent_frames[6]);
    assert_eq!((d_krb, krb_as_req[0]), (88, 0x6A));
    assert!(contains_subslice(krb_as_req, b"\xa7\x11\x18\x0f20370913024805Z"));
    assert!(contains_subslice(krb_as_req, &[0xa8, 0x06, 0x02, 0x04]));
    assert_eq!(ipv4_udp_parts(&ent_frames[7]).2[0], 0x6B);
    assert_eq!(ipv4_udp_parts(&ent_frames[8]).2[0], 0x6C);
    assert_eq!(ipv4_udp_parts(&ent_frames[9]).2[0], 0x6D);
    assert_eq!(ipv4_udp_parts(&ent_frames[10]).2[0], 0x7E);
    // NFS COMPOUND: 4B record marker + 40B RPC header + XDR "nfs_tag" + XDR "/export/vol"
    let (_, d_nfs, nfs) = ipv4_tcp_parts(&ent_frames[11]);
    assert_eq!(d_nfs, 2049);
    assert_eq!(&nfs[44..56], b"\x00\x00\x00\x07nfs_tag\x00");
    assert_eq!(&nfs[56..72], b"\x00\x00\x00\x0b/export/vol\x00");
    // S7COMM: JOB (0x01) is 25B; ACK (0x02) and ACK_DATA (0x03) have 12B S7 header (27B total)
    let (_, d_s7, s7_job) = ipv4_tcp_parts(&ent_frames[12]);
    assert_eq!((d_s7, s7_job.len(), s7_job[8]), (102, 25, 0x01));
    let (_, _, s7_ack) = ipv4_tcp_parts(&ent_frames[13]);
    assert_eq!((s7_ack.len(), s7_ack[8], s7_ack[17], s7_ack[18]), (27, 0x02, 0x00, 0x00));
    let (_, _, s7_ack_data) = ipv4_tcp_parts(&ent_frames[14]);
    assert_eq!((s7_ack_data.len(), s7_ack_data[8]), (27, 0x03));
}

/// Verifies `SNMP` rejects 1-arc OIDs (`OID 1`) and out-of-range root/second arcs (`OID 3.1`, `OID 1.45`) with `Err`.
#[test]
fn test_snmp_rejects_invalid_single_arc_and_bad_root_oids() {
    for bad_oid in ["1", "3.1", "1.45"] {
        let fasm = format!(
            "host mgr {{ ip 10.93.0.1 mac 00:11:22:00:93:01 }}\nhost agt {{ ip 10.93.0.2 mac 00:11:22:00:93:02 }}\nflow bad_snmp(a, b) {{ a -> b snmp2 get oid {bad_oid} wait 1ms }}\ncompile {{ bad_snmp(mgr, agt) }}"
        );
        let rejected = parse_program(&fasm).map_or(true, |prog| compile_program(&prog).is_err());
        assert!(rejected, "OID {bad_oid} must be rejected without panicking");
    }
}

// --- Category 4: All Remaining Wired-Up AST *Spec Fields Across L2/L3/L7 Builders ---

/// Verifies L3 wired AST fields across `BGP`, `IGMP`, `IPSEC`/`ESP`/`AH`, `OPENFLOW`, `OSPF`, and `PIM`.
#[test]
fn test_l3_routing_multicast_ipsec_and_openflow_wired_fields() {
    let l3_frames = compile_frames(r#"
        host r_left  { ip 10.94.0.1 mac 00:1e:67:94:00:01 }
        host r_right { ip 10.94.0.2 mac 00:1e:67:94:00:02 }
        flow l3_matrix(a, b) {
            a -> b bgp update asn 65010 nexthop 10.0.0.254 prefix "192.168.10.0/24" wait 1ms
            a -> b igmp report v1 group 239.1.1.1 wait 1ms
            a -> b igmp report v2 group 239.2.2.2 wait 1ms
            a -> b igmp report v3 group 239.3.3.3 wait 1ms
            a -> b ipsec spi 0x11112222 seq 5 iv "0102030405060708" icv "aabbccddeeff001122334455" nextheader 6 wait 1ms
            a -> b esp spi 0x33334444 seq 6 wait 1ms
            a -> b ah spi 0x55556666 seq 7 icv "11223344556677889900aabb" nextheader 17 wait 1ms
            a -> b openflow featuresreply dpid 0x0000000000000099 tableid 128 priority 50 wait 1ms
            a -> b openflow flowmod dpid 0x1234 tableid 3 priority 500 wait 1ms
            a -> b ospf hello area 0.0.0.1 routerid 1.1.1.1 wait 1ms
            a -> b ospf dbd area 0.0.0.1 routerid 1.1.1.1 wait 1ms
            a -> b ospf lsr area 0.0.0.1 routerid 1.1.1.1 wait 1ms
            a -> b ospf lsu area 0.0.0.1 routerid 1.1.1.1 wait 1ms
            a -> b ospf lsack area 0.0.0.1 routerid 1.1.1.1 wait 1ms
            a -> b pim hello holdtime 90 drpriority 10 wait 1ms
            a -> b pim joinprune group 239.5.5.5 source 10.5.5.1 rp 10.5.5.254 wait 1ms
            a -> b pim register group 239.6.6.6 source 10.6.6.1 rp 10.6.6.254 wait 1ms
        }
        compile { l3_matrix(r_left, r_right) }
    "#);
    assert_eq!(l3_frames.len(), 17, "expected 17 L3 protocol frames");
    let (_, d_bgp, bgp) = ipv4_tcp_parts(&l3_frames[0]);
    assert_eq!((d_bgp, bgp[18]), (179, 2));
    assert!(contains_subslice(bgp, &[10, 0, 0, 254]));
    assert!(contains_subslice(bgp, &[24, 192, 168, 10]));
    assert_eq!((l3_frames[1][34], l3_frames[2][34], l3_frames[3][34]), (0x12, 0x16, 0x22));
    // IPSEC (ESP proto 50): SPI 0x11112222, SEQ 5, IV 01..08, NextHeader 6, ICV aa..55
    assert_eq!(l3_frames[4][23], 50);
    let esp0 = &l3_frames[4][34..];
    assert_eq!(&esp0[0..16], &[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(esp0[esp0.len() - 13], 6);
    assert_eq!(&esp0[esp0.len() - 12..], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&l3_frames[5][34..38], &[0x33, 0x33, 0x44, 0x44]);
    // AH (proto 51): NextHeader 17, SPI 0x55556666, SEQ 7
    assert_eq!(l3_frames[6][23], 51);
    assert_eq!(&l3_frames[6][34..46], &[17, 4, 0, 0, 0x55, 0x55, 0x66, 0x66, 0, 0, 0, 7]);
    // OPENFLOW: FEATURES_REPLY and FLOW_MOD
    let (_, d_of, of_feat) = ipv4_tcp_parts(&l3_frames[7]);
    assert_eq!((d_of, of_feat[1], of_feat.len(), of_feat[15], of_feat[20]), (6653, 6, 32, 0x99, 128));
    let (_, _, of_mod) = ipv4_tcp_parts(&l3_frames[8]);
    assert_eq!((of_mod[1], of_mod.len(), of_mod[24], u16::from_be_bytes([of_mod[30], of_mod[31]])), (14, 56, 3, 500));
    for (idx, code) in (1u8..=5u8).enumerate() {
        assert_eq!((l3_frames[9 + idx][23], l3_frames[9 + idx][35]), (89, code));
    }
    assert_eq!((l3_frames[14][23], l3_frames[14][34]), (103, 0x20));
    assert_eq!(&l3_frames[14][42..44], &90u16.to_be_bytes());
    assert_eq!(l3_frames[15][34], 0x23);
    assert!(contains_subslice(&l3_frames[15][34..], &[239, 5, 5, 5]));
    assert_eq!(l3_frames[16][34], 0x21);
    assert!(contains_subslice(&l3_frames[16][34..], &[10, 6, 6, 1]));
}

/// Verifies L7 web, VoIP, security, and remote access wired fields (`DNS`, `GRPC`, `HTTP2`, `SIP`, `SSDP`, `SSH`, `STUN`, `TELNET`, `TLS`, `WHOIS`).
#[test]
fn test_l7_web_voip_remote_and_security_wired_fields() {
    let web_frames = compile_frames(r#"
        host web_c { ip 10.95.0.10 mac 00:50:56:95:00:01 }
        host web_s { ip 10.95.0.20 mac 00:50:56:95:00:02 }
        flow web_sec_flow(c, s) {
            c -> s dns query txid 0x1111 qname "api.example.com" wait 1ms
            s -> c dns response txid 0x1111 qname "api.example.com" rdata "93.184.216.34" wait 1ms
            c -> s grpc service "pkg.Health" method "Check" grpcstatus 0 wait 1ms
            c -> s http2 settings streamid 0 wait 1ms
            c -> s sip invite uri "sip:bob@example.com" contact "sip:alice@10.0.0.1" contenttype "application/sdp" wait 1ms
            c -> s ssdp msearch hosthdr "239.255.255.250:1900" man "\"ssdp:discover\"" mx 5 st "urn:schemas-upnp-org:device:Basic:1" usn "uuid:dev-1" location "http://10.0.0.1:8080/desc.xml" wait 1ms
            s -> c ssdp notify nt "upnp:rootdevice" nts "ssdp:alive" usn "uuid:dev-2" location "http://10.0.0.1:8080/root.xml" wait 1ms
            c -> s ssh kexinit cookie "00112233445566778899aabbccddeeff" wait 1ms
            c -> s ssh newkeys wait 1ms
            c -> s ssh msgcode 50 wait 1ms
            c -> s stun bindingrequest txid 0x12345678 software "FrameAssembly-STUN" wait 1ms
            c -> s telnet option 31 wait 1ms
            c -> s tls clienthello handshakeversion 0x0303 ciphersuite 0x1302 sni "tls.example.com" alpn "h2" wait 1ms
            s -> c tls serverhello ciphersuite 0x1302 alpn "h2" wait 1ms
            s -> c tls certificate wait 1ms
            s -> c tls finished wait 1ms
            c -> s tls appdata payload "enc_app" wait 1ms
            s -> c tls alert wait 1ms
            c -> s whois query domain "example.org" wait 1ms
            s -> c whois response domain "example.org" registrar "ICANN-Reg" wait 1ms
        }
        compile { web_sec_flow(web_c, web_s) }
    "#);
    assert_eq!(web_frames.len(), 20, "expected 20 web/VoIP/security frames");
    assert_eq!(&ipv4_udp_parts(&web_frames[0]).2[2..4], &[0x01, 0x00]);
    let (_, _, dns_r) = ipv4_udp_parts(&web_frames[1]);
    assert_eq!(&dns_r[2..4], &[0x81, 0x80]);
    assert!(contains_subslice(dns_r, &[93, 184, 216, 34]));
    assert_eq!(&ipv4_tcp_parts(&web_frames[2]).2[5..], b"pkg.Health/Check grpc-status:0");
    assert_eq!(ipv4_tcp_parts(&web_frames[3]).2[3], 4); // HTTP2 SETTINGS
    let (_, _, sip) = ipv4_udp_parts(&web_frames[4]);
    assert!(contains_subslice(sip, b"Contact: <sip:alice@10.0.0.1>\r\n"));
    assert!(contains_subslice(sip, b"Content-Type: application/sdp\r\n"));
    let (_, _, ssdp_m) = ipv4_udp_parts(&web_frames[5]);
    assert!(contains_subslice(ssdp_m, b"MX: 5\r\n") && contains_subslice(ssdp_m, b"USN: uuid:dev-1\r\n"));
    assert!(contains_subslice(ssdp_m, b"LOCATION: http://10.0.0.1:8080/desc.xml\r\n"));
    let (_, _, ssdp_n) = ipv4_udp_parts(&web_frames[6]);
    assert!(contains_subslice(ssdp_n, b"NT: upnp:rootdevice\r\n") && contains_subslice(ssdp_n, b"NTS: ssdp:alive\r\n"));
    let (_, _, ssh_kex) = ipv4_tcp_parts(&web_frames[7]);
    assert_eq!(ssh_kex[5], 20);
    assert_eq!(&ssh_kex[6..22], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!((ipv4_tcp_parts(&web_frames[8]).2[5], ipv4_tcp_parts(&web_frames[9]).2[5]), (21, 50));
    let (_, _, stun) = ipv4_udp_parts(&web_frames[10]);
    assert_eq!(&stun[20..24], &[0x80, 0x22, 0x00, 18]);
    assert!(contains_subslice(stun, b"FrameAssembly-STUN"));
    assert_eq!(ipv4_tcp_parts(&web_frames[11]).2, &[0xFF, 0xFD, 31]);
    let (_, _, tls_ch) = ipv4_tcp_parts(&web_frames[12]);
    assert_eq!((tls_ch[0], tls_ch[5]), (22, 1));
    assert!(contains_subslice(tls_ch, b"tls.example.com") && contains_subslice(tls_ch, b"h2"));
    let (_, _, tls_sh) = ipv4_tcp_parts(&web_frames[13]);
    assert_eq!(tls_sh[5], 2);
    assert!(contains_subslice(tls_sh, b"h2"));
    assert_eq!((ipv4_tcp_parts(&web_frames[14]).2[5], ipv4_tcp_parts(&web_frames[15]).2[5]), (11, 20));
    assert_eq!((ipv4_tcp_parts(&web_frames[16]).2[0], ipv4_tcp_parts(&web_frames[17]).2[0]), (23, 21));
    assert_eq!(ipv4_tcp_parts(&web_frames[18]).2, b"example.org\r\n");
    let (_, _, whois_r) = ipv4_tcp_parts(&web_frames[19]);
    assert!(contains_subslice(whois_r, b"Domain Name: example.org\r\n") && contains_subslice(whois_r, b"Registrar: ICANN-Reg\r\n"));
}

/// Verifies L7 messaging, industrial OT, and database wired fields (`AMQP`, `BACNET`, `COAP`, `DNP3`, `ETHERNETIP`, `MEMCACHED`, `MQTT`, `MYSQL`, `OPCUA`, `POSTGRES`, `REDIS`, `SMB`).
#[test]
fn test_l7_messaging_industrial_and_database_wired_fields() {
    let ot_frames = compile_frames(r#"
        host ot_cli { ip 10.96.0.10 mac 00:60:52:96:00:01 }
        host ot_srv { ip 10.96.0.20 mac 00:60:52:96:00:02 }
        flow ot_db_flow(c, s) {
            c -> s amqp protocolheader wait 1ms
            s -> c amqp connectionstart wait 1ms
            c -> s amqp channelopen channel 2 wait 1ms
            c -> s amqp basicpublish channel 3 exchange "logs" routingkey "info" wait 1ms
            s -> c amqp basicdeliver channel 4 exchange "logs" routingkey "warn" wait 1ms
            c -> s amqp heartbeat channel 0 wait 1ms
            c -> s bacnet writeproperty objecttype 2 objectinstance 10 propertyid 85 value 420 wait 1ms
            c -> s bacnet whois value 100 wait 1ms
            c -> s coap con code "2.05" msgid 0x2222 token 0xAABBCCDD uripath "sensors/temp" contentformat 50 wait 1ms
            c -> s dnp3 read src 1 dst 2 group 30 variation 1 crc 0xBEEF wait 1ms
            c -> s ethernetip sendrrdata sessionhandle 0x100 cipservice 0x0E cipclass 0x04 cipinstance 0x64 cipattr 0x03 wait 1ms
            c -> s memcached set key "k_ascii" flags 11 exptime 3600 value "val_ascii" wait 1ms
            c -> s memcached set key "k_bin" flags 22 exptime 1800 value "val_bin" opaque 0x12345678 cas 987654321 wait 1ms
            c -> s mqtt publish topic "factory/temp" qos 1 retain pktid 42 payload "23.5" wait 1ms
            s -> c mysql greeting serverversion "8.4.0" wait 1ms
            c -> s mysql login user "dbadmin" db "prod" wait 1ms
            c -> s mysql query sql "SELECT 42" wait 1ms
            s -> c mysql ok wait 1ms
            s -> c mysql err errcode 1062 wait 1ms
            s -> c mysql eof wait 1ms
            c -> s opcua msgtype "hel" endpointurl "opc.tcp://plc.local:4840" wait 1ms
            c -> s opcua msgtype "msg" nodeid "ns=2;s=Temperature" wait 1ms
            c -> s postgres startup user "pgadmin" db "analytics" wait 1ms
            c -> s postgres query sql "SELECT 1" wait 1ms
            s -> c postgres readyforquery wait 1ms
            s -> c postgres commandcomplete sql "INSERT 0 1" wait 1ms
            s -> c postgres errorresponse sql "syntax error" wait 1ms
            s -> c postgres authok wait 1ms
            s -> c redis replytype "simple" value "PONG" wait 1ms
            s -> c redis replytype "bulk" value "hello" wait 1ms
            c -> s redis cmd "SET" key "mykey" value "myval" wait 1ms
            c -> s smb status 0xC0000022 share "\\\\filesrv\\public" wait 1ms
            c -> s smb status 0 filename "report.pdf" wait 1ms
        }
        compile { ot_db_flow(ot_cli, ot_srv) }
    "#);
    assert_eq!(ot_frames.len(), 33, "expected 33 OT/DB frames");
    assert_eq!(ipv4_tcp_parts(&ot_frames[0]).2, b"AMQP\x00\x00\x09\x01");
    assert_eq!(&ipv4_tcp_parts(&ot_frames[1]).2[7..11], &[0x00, 0x0A, 0x00, 0x0A]);
    assert_eq!(&ipv4_tcp_parts(&ot_frames[2]).2[7..11], &[0x00, 0x14, 0x00, 0x0A]);
    let (_, _, amqp_pub) = ipv4_tcp_parts(&ot_frames[3]);
    assert_eq!(&amqp_pub[7..11], &[0x00, 0x3C, 0x00, 0x28]);
    assert!(contains_subslice(amqp_pub, b"logs") && contains_subslice(amqp_pub, b"info"));
    assert_eq!(&ipv4_tcp_parts(&ot_frames[4]).2[7..11], &[0x00, 0x3C, 0x00, 0x3C]);
    assert_eq!(ipv4_tcp_parts(&ot_frames[5]).2[0], 8);
    assert!(contains_subslice(ipv4_udp_parts(&ot_frames[6]).2, &[0x3e, 0x24, 0x00, 0x00, 0x01, 0xa4, 0x3f]));
    assert!(contains_subslice(ipv4_udp_parts(&ot_frames[7]).2, &[0x24, 0x00, 0x00, 0x00, 100]));
    let (_, _, coap) = ipv4_udp_parts(&ot_frames[8]);
    assert_eq!((coap[1], &coap[4..8]), (0x45, &[0xAA, 0xBB, 0xCC, 0xDD][..]));
    assert!(contains_subslice(coap, b"sensors") && contains_subslice(coap, b"temp") && contains_subslice(coap, &[0x11, 50]));
    let (_, _, dnp3) = ipv4_tcp_parts(&ot_frames[9]);
    assert_eq!((&dnp3[8..10], &dnp3[13..15]), (&[0xEF, 0xBE][..], &[30, 1][..]));
    assert!(contains_subslice(ipv4_tcp_parts(&ot_frames[10]).2, &[0x0E, 0x03, 0x20, 0x04, 0x24, 0x64, 0x30, 0x03]));
    assert_eq!(ipv4_tcp_parts(&ot_frames[11]).2, b"set k_ascii 11 3600 9\r\nval_ascii\r\n");
    let (_, _, mc_bin) = ipv4_tcp_parts(&ot_frames[12]);
    assert_eq!((mc_bin[0], mc_bin[1]), (0x80, 0x01));
    assert_eq!(&mc_bin[12..16], &0x1234_5678u32.to_be_bytes());
    assert_eq!(&mc_bin[16..24], &987_654_321u64.to_be_bytes());
    let mc_opcode_frames = compile_frames(
        "host mc_c { ip 10.96.1.1 }\nhost mc_s { ip 10.96.1.2 }\nflow mc_f(a, b) { a -> b memcached opcode 2 key \"k_op\" }\ncompile { mc_f(mc_c, mc_s) }",
    );
    assert_eq!(&ipv4_tcp_parts(&mc_opcode_frames[0]).2[0..2], &[0x80, 0x02]);
    let (_, _, mqtt) = ipv4_tcp_parts(&ot_frames[13]);
    assert_eq!(mqtt[0], 0x33);
    assert!(contains_subslice(mqtt, b"factory/temp") && contains_subslice(mqtt, &42u16.to_be_bytes()));
    assert!(contains_subslice(ipv4_tcp_parts(&ot_frames[14]).2, b"8.4.0\0"));
    assert!(contains_subslice(ipv4_tcp_parts(&ot_frames[15]).2, b"dbadmin\0"));
    assert!(contains_subslice(ipv4_tcp_parts(&ot_frames[16]).2, b"\x03SELECT 42"));
    assert_eq!((ipv4_tcp_parts(&ot_frames[17]).2[4], ipv4_tcp_parts(&ot_frames[18]).2[4], ipv4_tcp_parts(&ot_frames[19]).2[4]), (0x00, 0xFF, 0xFE));
    assert_eq!(&ipv4_tcp_parts(&ot_frames[18]).2[5..7], &1062u16.to_le_bytes());
    let (_, _, opc_hel) = ipv4_tcp_parts(&ot_frames[20]);
    assert!(opc_hel.starts_with(b"HELF") && contains_subslice(opc_hel, b"opc.tcp://plc.local:4840"));
    let (_, _, opc_msg) = ipv4_tcp_parts(&ot_frames[21]);
    assert!(opc_msg.starts_with(b"MSGF") && contains_subslice(opc_msg, b"ns=2;s=Temperature"));
    assert!(contains_subslice(ipv4_tcp_parts(&ot_frames[22]).2, b"user\0pgadmin\0database\0analytics\0"));
    assert_eq!(ipv4_tcp_parts(&ot_frames[23]).2[0], b'Q');
    assert_eq!(ipv4_tcp_parts(&ot_frames[24]).2, b"Z\x00\x00\x00\x05I");
    assert_eq!((ipv4_tcp_parts(&ot_frames[25]).2[0], ipv4_tcp_parts(&ot_frames[26]).2[0]), (b'C', b'E'));
    assert_eq!(ipv4_tcp_parts(&ot_frames[27]).2, b"R\x00\x00\x00\x08\x00\x00\x00\x00");
    assert_eq!(ipv4_tcp_parts(&ot_frames[28]).2, b"+PONG\r\n");
    assert_eq!(ipv4_tcp_parts(&ot_frames[29]).2, b"$5\r\nhello\r\n");
    assert_eq!(ipv4_tcp_parts(&ot_frames[30]).2, b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$5\r\nmyval\r\n");
    let (_, _, smb_share) = ipv4_tcp_parts(&ot_frames[31]);
    assert_eq!((&smb_share[4..8], &smb_share[12..16]), (&b"\xFESMB"[..], &0xC000_0022u32.to_le_bytes()[..]));
    let utf16_share: Vec<u8> = r"\\\\filesrv\\public".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(contains_subslice(smb_share, &utf16_share));
    let utf16_file: Vec<u8> = "report.pdf".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(contains_subslice(ipv4_tcp_parts(&ot_frames[32]).2, &utf16_file));
}
