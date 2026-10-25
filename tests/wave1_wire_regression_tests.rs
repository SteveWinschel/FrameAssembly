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
        HOST v6_cli { IP 2001:db8:10::c1 MAC 00:11:22:33:44:55 }
        HOST v6_srv { IP 2001:db8:10::a1 MAC 00:11:22:33:44:66 }
        HOST v4_cli { IP 10.10.1.50 MAC 00:aa:bb:cc:dd:01 }
        HOST v4_srv { IP 10.10.1.1  MAC 00:aa:bb:cc:dd:02 }
        FLOW dhcp6_exchange(c, s) {
            c -> s DHCP SOLICIT XID 0x112233 CHADDR 00:11:22:33:44:55 WAIT 1ms
            c <- s DHCP ADVERTISE XID 0x112233 WAIT 1ms
        }
        FLOW dhcp4_exchange(c, s) {
            c -> s DHCP DISCOVER XID 0x44556677 CHADDR 00:aa:bb:cc:dd:01 WAIT 1ms
            c <- s DHCP OFFER XID 0x44556677 YIADDR 10.10.1.50 WAIT 1ms
        }
        COMPILE {
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
        HOST apple_v4 { IP 192.168.50.10 MAC 00:1c:42:aa:bb:01 }
        HOST peer_v4  { IP 192.168.50.20 MAC 00:1c:42:aa:bb:02 }
        HOST apple_v6 { IP fe80::10      MAC 00:1c:42:aa:bb:03 }
        HOST peer_v6  { IP fe80::20      MAC 00:1c:42:aa:bb:04 }
        FLOW mdns_cast(a, b) {
            a -> b MDNS QUERY QNAME "_http._tcp.local" WAIT 1ms
            a <- b MDNS RESPONSE QNAME "_http._tcp.local" RDATA "192.168.50.10" WAIT 1ms
        }
        COMPILE {
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
        HOST gm_clock    { IP 172.16.80.1 MAC 00:50:c2:11:22:01 }
        HOST slave_clock { IP 172.16.80.2 MAC 00:50:c2:11:22:02 }
        FLOW ptp_sync_cycle(m, s) {
            m -> s PTP SYNC DOMAIN 1 SEQ_ID 10 WAIT 1ms
            m -> s PTP FOLLOW_UP DOMAIN 1 SEQ_ID 10 WAIT 1ms
            s -> m PTP DELAY_REQ DOMAIN 1 SEQ_ID 11 WAIT 1ms
            m -> s PTP DELAY_RESP DOMAIN 1 SEQ_ID 11 WAIT 1ms
            m -> s PTP ANNOUNCE DOMAIN 1 SEQ_ID 12 PAYLOAD "ptp_ext" WAIT 1ms
        }
        COMPILE { ptp_sync_cycle(gm_clock, slave_clock) }
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
        HOST nas_v4 { IP 10.200.1.10 MAC 00:21:55:00:01:01 }
        HOST aaa_v4 { IP 10.200.1.20 MAC 00:21:55:00:01:02 }
        HOST nas_v6 { IP 2001:db8:aaa::10 MAC 00:21:55:00:02:01 }
        HOST aaa_v6 { IP 2001:db8:aaa::20 MAC 00:21:55:00:02:02 }
        FLOW radius_v4_flow(c, s) {
            c -> s RADIUS ACCESS_REQUEST ID 10 USER "alice" WAIT 1ms
            c <- s RADIUS ACCESS_ACCEPT ID 10 WAIT 1ms
            c -> s RADIUS ACCOUNTING_REQUEST ID 11 USER "alice" WAIT 1ms
            c <- s RADIUS ACCOUNTING_RESPONSE ID 11 WAIT 1ms
        }
        FLOW radius_v6_flow(c, s) {
            c -> s RADIUS ACCESS_REQUEST ID 20 USER "bob" NAS_IP 2001:db8::1 FRAMED_IP 2001:db8::2 WAIT 1ms
        }
        COMPILE {
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
        HOST rtr_v6_a { IP fe80::a1 MAC 00:10:94:00:01:01 }
        HOST rtr_v6_b { IP fe80::b2 MAC 00:10:94:00:01:02 }
        HOST rtr_v4_a { IP 192.168.100.2 MAC 00:10:94:00:02:01 }
        HOST rtr_v4_b { IP 192.168.100.3 MAC 00:10:94:00:02:02 }
        FLOW l3_hop255_v6(a, b) {
            a -> b NDP NEIGHBOR_SOLICIT TARGET fe80::b2 WAIT 1ms
            a -> b VRRP VRID 10 PRIORITY 150 VIP fe80::1 WAIT 1ms
            a -> b ARP REQUEST WAIT 1ms
            a <- b ARP REPLY WAIT 1ms
        }
        FLOW l3_ttl255_v4(a, b) {
            a -> b VRRP VRID 10 PRIORITY 150 VIP 192.168.100.1 WAIT 1ms
        }
        COMPILE {
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
        HOST tun_left  { IP 172.31.0.1 MAC 00:16:3e:10:01:01 }
        HOST tun_right { IP 172.31.0.2 MAC 00:16:3e:10:01:02 }
        FLOW gre_tunnel(a, b) {
            a -> b GRE CHECKSUM GRE_SEQ 99 PAYLOAD "inner1" WAIT 1ms
            b -> a GRE CHECKSUM KEY 0xAABBCCDD SEQ 77 PAYLOAD "inner2" WAIT 1ms
        }
        COMPILE { gre_tunnel(tun_left, tun_right) }
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
        HOST gw4_pri { IP 10.55.0.2 MAC 00:00:5e:00:01:05 }
        HOST gw4_bak { IP 10.55.0.3 MAC 00:00:5e:00:01:06 }
        HOST gw6_pri { IP fe80::55:2 MAC 00:00:5e:00:02:05 }
        HOST gw6_bak { IP fe80::55:3 MAC 00:00:5e:00:02:06 }
        FLOW vrrp4_flow(a, b) {
            a -> b VRRP VERSION 3 VRID 5 PRIORITY 120 VIP 10.55.0.1 WAIT 1ms
            a -> b VRRP VERSION 2 VRID 5 PRIORITY 120 VIP 10.55.0.1 WAIT 1ms
        }
        FLOW vrrp6_flow(a, b) {
            a -> b VRRP VERSION 3 VRID 5 PRIORITY 120 VIP fe80::55:1 WAIT 1ms
        }
        COMPILE {
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
        HOST nve_a { IP 10.77.0.1 MAC 00:1b:21:77:00:01 }
        HOST nve_b { IP 10.77.0.2 MAC 00:1b:21:77:00:02 }
        FLOW overlay_flow(a, b) {
            a -> b GENEVE VNI 5000 WAIT 1ms
            a -> b WIREGUARD DATA RECEIVER 7 COUNTER 42 WAIT 1ms
        }
        COMPILE { overlay_flow(nve_a, nve_b) }
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
        HOST sw_root { IP 10.88.0.1 MAC 00:11:22:33:44:55 }
        HOST sw_edge { IP 10.88.0.2 MAC 00:aa:bb:cc:dd:ee }
        FLOW rstp_flow(a, b) {
            a -> b STP RSTP ROOT_ID "4096/00:11:22:33:44:55" BRIDGE_ID "32768/00:aa:bb:cc:dd:ee" PORT_ID 0x8002 COST 2000 WAIT 1ms
        }
        COMPILE { rstp_flow(sw_root, sw_edge) }
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
        HOST auth_sw { IP 10.89.0.1 MAC 00:1d:71:00:01:01 }
        HOST supp_pc { IP 10.89.0.2 MAC 00:1d:71:00:01:02 }
        FLOW dot1x_result(s, c) {
            s -> c EAPOL EAP_CODE 3 EAP_ID 7 WAIT 1ms
            s -> c EAPOL EAP_CODE 4 EAP_ID 8 WAIT 1ms
        }
        COMPILE { dot1x_result(auth_sw, supp_pc) }
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
        HOST q_cli { IP 10.90.0.10 MAC 00:22:44:66:88:01 }
        HOST q_srv { IP 10.90.0.20 MAC 00:22:44:66:88:02 }
        FLOW quic_all(c, s) {
            c -> s QUIC INITIAL VERSION 1 DCID 0x11223344 SCID 0x55667788 TOKEN "retry_tok" PKT_NUM 5 PAYLOAD "hello" WAIT 1ms
            c -> s QUIC ZERO_RTT VERSION 1 DCID 0x11223344 SCID 0x55667788 PKT_NUM 6 PAYLOAD "early" WAIT 1ms
            s -> c QUIC HANDSHAKE VERSION 1 DCID 0x55667788 SCID 0x11223344 PKT_NUM 7 PAYLOAD "hs" WAIT 1ms
            s -> c QUIC RETRY VERSION 1 DCID 0x55667788 SCID 0x11223344 TOKEN "srv_tok" WAIT 1ms
            c -> s QUIC SHORT DCID 0x11223344 PKT_NUM 8 PAYLOAD "1rtt" WAIT 1ms
        }
        COMPILE { quic_all(q_cli, q_srv) }
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
        HOST exporter  { IP 10.91.0.1 MAC 00:25:90:01:01:01 }
        HOST collector { IP 10.91.0.2 MAC 00:25:90:01:01:02 }
        FLOW telemetry_flow(e, c) {
            e -> c IPFIX DOMAIN_ID 100 PACKETS 5 OCTETS 500 PAYLOAD "extra_ie" WAIT 1ms
            e -> c SFLOW AGENT_IP 10.20.30.40 SUB_AGENT_ID 3 SEQ 12 UPTIME 9000 SAMPLES 1 WAIT 1ms
        }
        COMPILE { telemetry_flow(exporter, collector) }
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
        HOST app_cli { IP 10.92.0.10 MAC 00:30:48:11:01:01 }
        HOST app_srv { IP 10.92.0.20 MAC 00:30:48:11:01:02 }
        FLOW enterprise_flow(c, s) {
            c -> s LDAP MSGID 2 SEARCH_REQ BASE_DN "dc=example,dc=org" FILTER "(cn=*)" WAIT 1ms
            c -> s LDAP MSGID 3 BIND_REQ BASE_DN "cn=admin" WAIT 1ms
            s -> c LDAP MSGID 3 BIND_RES RESULT_CODE 49 WAIT 1ms
            s -> c LDAP MSGID 2 SEARCH_ENTRY BASE_DN "cn=alice,dc=example,dc=org" WAIT 1ms
            s -> c LDAP MSGID 2 SEARCH_DONE RESULT_CODE 0 WAIT 1ms
            c -> s LDAP MSGID 4 UNBIND_REQ WAIT 1ms
            c -> s KERBEROS AS_REQ REALM "ATHENA.MIT.EDU" CNAME "alice" SNAME "krbtgt" ETYPE 18 WAIT 1ms
            s -> c KERBEROS AS_REP REALM "ATHENA.MIT.EDU" CNAME "alice" ETYPE 18 WAIT 1ms
            c -> s KERBEROS TGS_REQ REALM "ATHENA.MIT.EDU" CNAME "alice" SNAME "ldap" ETYPE 18 WAIT 1ms
            s -> c KERBEROS TGS_REP REALM "ATHENA.MIT.EDU" CNAME "alice" ETYPE 18 WAIT 1ms
            s -> c KERBEROS KRB_ERROR REALM "ATHENA.MIT.EDU" SNAME "krbtgt" WAIT 1ms
            c -> s NFS COMPOUND XID 0x11223344 VERS 4 TAG "nfs_tag" PATH "/export/vol" WAIT 1ms
            c -> s S7COMM ROSCTR "JOB" PDU_REF 4 WAIT 1ms
            s -> c S7COMM ROSCTR "ACK" PDU_REF 5 WAIT 1ms
            s -> c S7COMM ROSCTR "ACK_DATA" PDU_REF 6 WAIT 1ms
        }
        COMPILE { enterprise_flow(app_cli, app_srv) }
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
            "HOST mgr {{ IP 10.93.0.1 MAC 00:11:22:00:93:01 }}\nHOST agt {{ IP 10.93.0.2 MAC 00:11:22:00:93:02 }}\nFLOW bad_snmp(a, b) {{ a -> b SNMP2 GET OID {bad_oid} WAIT 1ms }}\nCOMPILE {{ bad_snmp(mgr, agt) }}"
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
        HOST r_left  { IP 10.94.0.1 MAC 00:1e:67:94:00:01 }
        HOST r_right { IP 10.94.0.2 MAC 00:1e:67:94:00:02 }
        FLOW l3_matrix(a, b) {
            a -> b BGP UPDATE ASN 65010 NEXTHOP 10.0.0.254 PREFIX "192.168.10.0/24" WAIT 1ms
            a -> b IGMP REPORT V1 GROUP 239.1.1.1 WAIT 1ms
            a -> b IGMP REPORT V2 GROUP 239.2.2.2 WAIT 1ms
            a -> b IGMP REPORT V3 GROUP 239.3.3.3 WAIT 1ms
            a -> b IPSEC SPI 0x11112222 SEQ 5 IV "0102030405060708" ICV "aabbccddeeff001122334455" NEXT_HEADER 6 WAIT 1ms
            a -> b ESP SPI 0x33334444 SEQ 6 WAIT 1ms
            a -> b AH SPI 0x55556666 SEQ 7 ICV "11223344556677889900aabb" NEXT_HEADER 17 WAIT 1ms
            a -> b OPENFLOW FEATURES_REPLY DPID 0x0000000000000099 TABLE_ID 128 PRIORITY 50 WAIT 1ms
            a -> b OPENFLOW FLOW_MOD DPID 0x1234 TABLE_ID 3 PRIORITY 500 WAIT 1ms
            a -> b OSPF HELLO AREA 0.0.0.1 ROUTER_ID 1.1.1.1 WAIT 1ms
            a -> b OSPF DBD AREA 0.0.0.1 ROUTER_ID 1.1.1.1 WAIT 1ms
            a -> b OSPF LSR AREA 0.0.0.1 ROUTER_ID 1.1.1.1 WAIT 1ms
            a -> b OSPF LSU AREA 0.0.0.1 ROUTER_ID 1.1.1.1 WAIT 1ms
            a -> b OSPF LSACK AREA 0.0.0.1 ROUTER_ID 1.1.1.1 WAIT 1ms
            a -> b PIM HELLO HOLDTIME 90 DR_PRIORITY 10 WAIT 1ms
            a -> b PIM JOIN_PRUNE GROUP 239.5.5.5 SOURCE 10.5.5.1 RP 10.5.5.254 WAIT 1ms
            a -> b PIM REGISTER GROUP 239.6.6.6 SOURCE 10.6.6.1 RP 10.6.6.254 WAIT 1ms
        }
        COMPILE { l3_matrix(r_left, r_right) }
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
        HOST web_c { IP 10.95.0.10 MAC 00:50:56:95:00:01 }
        HOST web_s { IP 10.95.0.20 MAC 00:50:56:95:00:02 }
        FLOW web_sec_flow(c, s) {
            c -> s DNS QUERY TXID 0x1111 QNAME "api.example.com" WAIT 1ms
            s -> c DNS RESPONSE TXID 0x1111 QNAME "api.example.com" RDATA "93.184.216.34" WAIT 1ms
            c -> s GRPC SERVICE "pkg.Health" METHOD "Check" GRPC_STATUS 0 WAIT 1ms
            c -> s HTTP2 SETTINGS STREAM_ID 0 WAIT 1ms
            c -> s SIP INVITE URI "sip:bob@example.com" CONTACT "sip:alice@10.0.0.1" CONTENT_TYPE "application/sdp" WAIT 1ms
            c -> s SSDP MSEARCH HOST_HDR "239.255.255.250:1900" MAN "\"ssdp:discover\"" MX 5 ST "urn:schemas-upnp-org:device:Basic:1" USN "uuid:dev-1" LOCATION "http://10.0.0.1:8080/desc.xml" WAIT 1ms
            s -> c SSDP NOTIFY NT "upnp:rootdevice" NTS "ssdp:alive" USN "uuid:dev-2" LOCATION "http://10.0.0.1:8080/root.xml" WAIT 1ms
            c -> s SSH KEXINIT COOKIE "00112233445566778899aabbccddeeff" WAIT 1ms
            c -> s SSH NEWKEYS WAIT 1ms
            c -> s SSH MSG_CODE 50 WAIT 1ms
            c -> s STUN BINDING_REQUEST TXID 0x12345678 SOFTWARE "FrameAssembly-STUN" WAIT 1ms
            c -> s TELNET OPTION 31 WAIT 1ms
            c -> s TLS CLIENT_HELLO HANDSHAKE_VERSION 0x0303 CIPHERSUITE 0x1302 SNI "tls.example.com" ALPN "h2" WAIT 1ms
            s -> c TLS SERVER_HELLO CIPHERSUITE 0x1302 ALPN "h2" WAIT 1ms
            s -> c TLS CERTIFICATE WAIT 1ms
            s -> c TLS FINISHED WAIT 1ms
            c -> s TLS APP_DATA PAYLOAD "enc_app" WAIT 1ms
            s -> c TLS ALERT WAIT 1ms
            c -> s WHOIS QUERY DOMAIN "example.org" WAIT 1ms
            s -> c WHOIS RESPONSE DOMAIN "example.org" REGISTRAR "ICANN-Reg" WAIT 1ms
        }
        COMPILE { web_sec_flow(web_c, web_s) }
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
        HOST ot_cli { IP 10.96.0.10 MAC 00:60:52:96:00:01 }
        HOST ot_srv { IP 10.96.0.20 MAC 00:60:52:96:00:02 }
        FLOW ot_db_flow(c, s) {
            c -> s AMQP PROTOCOL_HEADER WAIT 1ms
            s -> c AMQP CONNECTION_START WAIT 1ms
            c -> s AMQP CHANNEL_OPEN CHANNEL 2 WAIT 1ms
            c -> s AMQP BASIC_PUBLISH CHANNEL 3 EXCHANGE "logs" ROUTING_KEY "info" WAIT 1ms
            s -> c AMQP BASIC_DELIVER CHANNEL 4 EXCHANGE "logs" ROUTING_KEY "warn" WAIT 1ms
            c -> s AMQP HEARTBEAT CHANNEL 0 WAIT 1ms
            c -> s BACNET WRITE_PROPERTY OBJECT_TYPE 2 OBJECT_INSTANCE 10 PROPERTY_ID 85 VALUE 420 WAIT 1ms
            c -> s BACNET WHO_IS VALUE 100 WAIT 1ms
            c -> s COAP CON CODE "2.05" MSGID 0x2222 TOKEN 0xAABBCCDD URI_PATH "sensors/temp" CONTENT_FORMAT 50 WAIT 1ms
            c -> s DNP3 READ SRC 1 DST 2 GROUP 30 VARIATION 1 CRC 0xBEEF WAIT 1ms
            c -> s ETHERNETIP SEND_RR_DATA SESSION_HANDLE 0x100 CIP_SERVICE 0x0E CIP_CLASS 0x04 CIP_INSTANCE 0x64 CIP_ATTR 0x03 WAIT 1ms
            c -> s MEMCACHED SET KEY "k_ascii" FLAGS 11 EXPTIME 3600 VALUE "val_ascii" WAIT 1ms
            c -> s MEMCACHED SET KEY "k_bin" FLAGS 22 EXPTIME 1800 VALUE "val_bin" OPAQUE 0x12345678 CAS 987654321 WAIT 1ms
            c -> s MQTT PUBLISH TOPIC "factory/temp" QOS 1 RETAIN PKT_ID 42 PAYLOAD "23.5" WAIT 1ms
            s -> c MYSQL GREETING SERVER_VERSION "8.4.0" WAIT 1ms
            c -> s MYSQL LOGIN USER "dbadmin" DB "prod" WAIT 1ms
            c -> s MYSQL QUERY SQL "SELECT 42" WAIT 1ms
            s -> c MYSQL OK WAIT 1ms
            s -> c MYSQL ERR ERRCODE 1062 WAIT 1ms
            s -> c MYSQL EOF WAIT 1ms
            c -> s OPCUA MSG_TYPE "HEL" ENDPOINT_URL "opc.tcp://plc.local:4840" WAIT 1ms
            c -> s OPCUA MSG_TYPE "MSG" NODE_ID "ns=2;s=Temperature" WAIT 1ms
            c -> s POSTGRES STARTUP USER "pgadmin" DB "analytics" WAIT 1ms
            c -> s POSTGRES QUERY SQL "SELECT 1" WAIT 1ms
            s -> c POSTGRES READY_FOR_QUERY WAIT 1ms
            s -> c POSTGRES COMMAND_COMPLETE SQL "INSERT 0 1" WAIT 1ms
            s -> c POSTGRES ERROR_RESPONSE SQL "syntax error" WAIT 1ms
            s -> c POSTGRES AUTH_OK WAIT 1ms
            s -> c REDIS REPLY_TYPE "SIMPLE" VALUE "PONG" WAIT 1ms
            s -> c REDIS REPLY_TYPE "BULK" VALUE "hello" WAIT 1ms
            c -> s REDIS CMD "SET" KEY "mykey" VALUE "myval" WAIT 1ms
            c -> s SMB STATUS 0xC0000022 SHARE "\\\\filesrv\\public" WAIT 1ms
            c -> s SMB STATUS 0 FILENAME "report.pdf" WAIT 1ms
        }
        COMPILE { ot_db_flow(ot_cli, ot_srv) }
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
        "HOST mc_c { IP 10.96.1.1 }\nHOST mc_s { IP 10.96.1.2 }\nFLOW mc_f(a, b) { a -> b MEMCACHED OPCODE 2 KEY \"k_op\" }\nCOMPILE { mc_f(mc_c, mc_s) }",
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
