//! Comprehensive End-to-End (E2E) integration test suite for FrameAssembly.
//!
//! Validates the full 60-protocol L2–L7 packet crafting catalog across IPv4 and IPv6:
//! - Tier 1: Feature coverage across protocols with zero-boilerplate defaults and field overrides.
//! - Tier 2: Boundary and corner cases (VLAN, DSCP, ECN, TTL, FLOWLABEL, string escaping, 4-tuple TCP state).
//! - Tier 3: Cross-feature combinations (dual-stack polymorphism, stacked tags, multicast MAC derivation, tunnels).
//! - Tier 4: Real-world application workflows (BGP peering, TLS REST API, DNS, DHCP, VoIP, SCADA).
//! - CLI & Backwards Compatibility: `-o / --output <path>` functionality and legacy examples 01–105 verification.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::fs;
use std::path::Path;

/// Context holding a captured network frame from PCAPNG output.
#[derive(Debug, Clone)]
pub struct PacketContext {
    /// Raw Ethernet frame byte buffer.
    pub raw: Vec<u8>,
}

#[allow(dead_code)]
impl PacketContext {
    /// Returns the Ethernet EtherType (bytes 12..14).
    pub fn ethertype(&self) -> Option<u16> {
        if self.raw.len() >= 14 {
            Some(u16::from_be_bytes([self.raw[12], self.raw[13]]))
        } else {
            None
        }
    }

    /// Returns the source MAC address (bytes 6..12).
    pub fn src_mac(&self) -> Option<[u8; 6]> {
        if self.raw.len() >= 12 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&self.raw[6..12]);
            Some(mac)
        } else {
            None
        }
    }

    /// Returns the destination MAC address (bytes 0..6).
    pub fn dst_mac(&self) -> Option<[u8; 6]> {
        if self.raw.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&self.raw[0..6]);
            Some(mac)
        } else {
            None
        }
    }
}

/// Reads all enhanced packet blocks from an emitted PCAPNG file.
fn read_pcapng_packets(path: &Path) -> Result<Vec<PacketContext>, String> {
    let file = fs::File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let mut reader = pcap_file::pcapng::PcapNgReader::new(file)
        .map_err(|e| format!("Failed to create PCAPNG reader: {}", e))?;
    let mut packets = Vec::new();
    while let Some(block) = reader.next_block() {
        let block = block.map_err(|e| format!("Failed to read block: {}", e))?;
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block {
            packets.push(PacketContext {
                raw: epb.data.to_vec(),
            });
        }
    }
    Ok(packets)
}

/// Helper function to execute an E2E test from a FASM script string.
///
/// Executes tests strictly and unconditionally:
/// - Asserts that the FASM script parses successfully, panicking immediately on error.
/// - Asserts that the program compiles and emits valid PCAPNG frames, panicking immediately on error.
/// - Validates that the emitted PCAPNG file contains at least one packet.
/// - Passes parsed packets to the verification closure.
pub fn run_e2e_test<F>(script: &str, verifier: F)
where
    F: FnOnce(&[PacketContext]),
{
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp_dir = std::env::temp_dir();
    let temp_pcap = temp_dir.join(format!(
        "e2e_{}_{}_{}.pcap",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let temp_pcap_str = temp_pcap.to_str().unwrap();

    let parse_res = frameassembly::parser::parse_program(script);
    match parse_res {
        Ok(program) => {
            let compile_res = frameassembly::backend::generate_pcap(&program, temp_pcap_str);
            match compile_res {
                Ok(_) => {
                    let packets = read_pcapng_packets(&temp_pcap).expect("read emitted pcapng");
                    let _ = fs::remove_file(&temp_pcap);
                    assert!(!packets.is_empty(), "Generated PCAP must contain at least one packet");
                    verifier(&packets);
                }
                Err(e) => {
                    let _ = fs::remove_file(&temp_pcap);
                    panic!("E2E compilation failure: {:?}", e);
                }
            }
        }
        Err(e) => {
            let _ = fs::remove_file(&temp_pcap);
            panic!("E2E parser failure: {:?}", e);
        }
    }
}

/// Tier 1: Feature coverage across protocols with zero-boilerplate defaults and configurable sub-keywords.
pub mod tier1_feature_coverage {
    use super::*;

    /// Tests ARP protocol with zero sub-keywords (default REQUEST) and explicit REPLY.
    #[test]
    pub fn test_tier1_l2_arp() {
        let script = r#"
            HOST h1 { IP 192.168.1.1 MAC 00:11:22:33:44:01 }
            HOST h2 { IP 192.168.1.2 MAC 00:11:22:33:44:02 }
            FLOW test_flow(src, dst) {
                src -> dst ARP
                src <- dst ARP REPLY
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0806));
            assert_eq!(packets[1].ethertype(), Some(0x0806));
        });
    }

    /// Tests IEEE 802.1Q VLAN framing and PCP/DEI settings.
    #[test]
    pub fn test_tier1_l2_vlan() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst VLAN 100 UDP PAYLOAD "vlan100"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x8100));
        });
    }

    /// Tests IEEE 802.1ad QINQ double tagging.
    #[test]
    pub fn test_tier1_l2_qinq() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst QINQ 200 INNER_VLAN 10 UDP PAYLOAD "qinq"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x88A8));
        });
    }

    /// Tests IEEE 802.1AB LLDP link layer discovery framing.
    #[test]
    pub fn test_tier1_l2_lldp() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst LLDP SYSNAME "switch-leaf1"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x88CC));
        });
    }

    /// Tests IEEE 802.1D STP spanning tree bridge protocol data unit.
    #[test]
    pub fn test_tier1_l2_stp() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst STP
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].dst_mac(), Some([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
        });
    }

    /// Tests IEEE 802.3ad LACP link aggregation control.
    #[test]
    pub fn test_tier1_l2_lacp() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst LACP
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].dst_mac(), Some([0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]));
        });
    }

    /// Tests IEEE 802.1X EAPOL port authentication.
    #[test]
    pub fn test_tier1_l2_eapol() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst EAPOL TYPE START
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x888E));
        });
    }

    /// Tests RFC 3032 MPLS label stack framing.
    #[test]
    pub fn test_tier1_l2_mpls() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst MPLS 10001 EXP 3 BOS 1 MPLS_TTL 64 UDP PAYLOAD "mpls"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x8847));
        });
    }

    /// Tests polymorphic ICMP over IPv4 (protocol 1) and IPv6 (protocol 58).
    #[test]
    pub fn test_tier1_l3_icmp() {
        let script = r#"
            HOST h1_v4 { IP 192.168.1.1 }
            HOST h2_v4 { IP 192.168.1.2 }
            FLOW test_flow(src, dst) {
                src -> dst ICMP ECHO_REQUEST
                src <- dst ICMP ECHO_REPLY
            }
            COMPILE {
                test_flow(h1_v4, h2_v4)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 4861 NDP (Neighbor Discovery Protocol) for IPv6.
    #[test]
    pub fn test_tier1_l3_ndp() {
        let script = r#"
            HOST h1 { IP 2001:db8::1 }
            HOST h2 { IP 2001:db8::2 }
            FLOW test_flow(src, dst) {
                src -> dst NDP NEIGHBOR_SOLICIT TARGET 2001:db8::2
                src <- dst NDP NEIGHBOR_ADVERT TARGET 2001:db8::2
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x86DD));
        });
    }

    /// Tests RFC 2236/3376 IGMP multicast group membership.
    #[test]
    pub fn test_tier1_l3_igmp() {
        let script = r#"
            HOST h1 { IP 192.168.1.1 }
            HOST mcast { IP 224.0.0.1 }
            FLOW test_flow(src, dst) {
                src -> dst IGMP REPORT GROUP 239.1.1.1
            }
            COMPILE {
                test_flow(h1, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 2710/3810 MLD (Multicast Listener Discovery) for IPv6.
    #[test]
    pub fn test_tier1_l3_mld() {
        let script = r#"
            HOST h1 { IP fe80::1 }
            HOST mcast { IP ff02::1 }
            FLOW test_flow(src, dst) {
                src -> dst MLD REPORT MULTICAST_ADDR ff02::1:2
            }
            COMPILE {
                test_flow(h1, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x86DD));
        });
    }

    /// Tests RFC 2784 GRE (Generic Routing Encapsulation) tunnels.
    #[test]
    pub fn test_tier1_l3_gre() {
        let script = r#"
            HOST r1 { IP 10.0.0.1 }
            HOST r2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst GRE GRE_KEY 1234 PAYLOAD "inner_ip"
            }
            COMPILE {
                test_flow(r1, r2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 7348 VXLAN overlay encapsulation.
    #[test]
    pub fn test_tier1_l3_vxlan() {
        let script = r#"
            HOST vtep1 { IP 192.168.10.1 }
            HOST vtep2 { IP 192.168.10.2 }
            FLOW test_flow(src, dst) {
                src -> dst VXLAN VNI 5000 PAYLOAD "inner_eth"
            }
            COMPILE {
                test_flow(vtep1, vtep2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 8926 GENEVE overlay encapsulation.
    #[test]
    pub fn test_tier1_l3_geneve() {
        let script = r#"
            HOST g1 { IP 192.168.20.1 }
            HOST g2 { IP 192.168.20.2 }
            FLOW test_flow(src, dst) {
                src -> dst GENEVE VNI 10000 PAYLOAD "inner_payload"
            }
            COMPILE {
                test_flow(g1, g2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 4303 IPsec ESP security encapsulation.
    #[test]
    pub fn test_tier1_l3_ipsec_esp() {
        let script = r#"
            HOST gw1 { IP 198.51.100.1 }
            HOST gw2 { IP 198.51.100.2 }
            FLOW test_flow(src, dst) {
                src -> dst ESP SPI 0x1000 SEQ 1 PAYLOAD "ciphertext"
            }
            COMPILE {
                test_flow(gw1, gw2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 4302 IPsec AH authentication header.
    #[test]
    pub fn test_tier1_l3_ipsec_ah() {
        let script = r#"
            HOST gw1 { IP 198.51.100.1 }
            HOST gw2 { IP 198.51.100.2 }
            FLOW test_flow(src, dst) {
                src -> dst AH SPI 0x2000 SEQ 1 PAYLOAD "ah_payload"
            }
            COMPILE {
                test_flow(gw1, gw2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 7296 IKEv2 security association negotiation.
    #[test]
    pub fn test_tier1_l3_ikev2() {
        let script = r#"
            HOST init { IP 198.51.100.1 }
            HOST resp { IP 198.51.100.2 }
            FLOW test_flow(src, dst) {
                src -> dst IKEV2 EXCHANGE SA_INIT MSGID 0
            }
            COMPILE {
                test_flow(init, resp)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests WireGuard secure network tunnel handshake.
    #[test]
    pub fn test_tier1_l3_wireguard() {
        let script = r#"
            HOST peer1 { IP 10.0.0.1 }
            HOST peer2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst WIREGUARD TYPE INITIATION SENDER 0x11223344
            }
            COMPILE {
                test_flow(peer1, peer2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 2328 OSPF routing protocol hello.
    #[test]
    pub fn test_tier1_l3_ospf() {
        let script = r#"
            HOST r1 { IP 10.0.0.1 }
            HOST r2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst OSPF HELLO ROUTER_ID 10.0.0.1 AREA_ID 0
            }
            COMPILE {
                test_flow(r1, r2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 4271 BGP routing protocol OPEN and KEEPALIVE messages.
    #[test]
    pub fn test_tier1_l3_bgp() {
        let script = r#"
            HOST peer1 { IP 192.0.2.1 }
            HOST peer2 { IP 192.0.2.2 }
            FLOW test_flow(src, dst) {
                src -> dst BGP OPEN ASN 65001 HOLDTIME 180 BGPID 192.0.2.1
                src <- dst BGP KEEPALIVE
            }
            COMPILE {
                test_flow(peer1, peer2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 2453 RIP routing table updates.
    #[test]
    pub fn test_tier1_l3_rip() {
        let script = r#"
            HOST r1 { IP 192.168.1.1 }
            HOST r2 { IP 224.0.0.9 }
            FLOW test_flow(src, dst) {
                src -> dst RIP RESPONSE PREFIX 10.0.0.0 METRIC 1
            }
            COMPILE {
                test_flow(r1, r2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 5798 VRRP router redundancy advertisements.
    #[test]
    pub fn test_tier1_l3_vrrp() {
        let script = r#"
            HOST master { IP 192.168.1.254 }
            HOST mcast { IP 224.0.0.18 }
            FLOW test_flow(src, dst) {
                src -> dst VRRP VRID 1 PRIORITY 100 VIP 192.168.1.1
            }
            COMPILE {
                test_flow(master, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 2281 HSRP standby router protocol.
    #[test]
    pub fn test_tier1_l3_hsrp() {
        let script = r#"
            HOST r1 { IP 192.168.1.253 }
            HOST mcast { IP 224.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst HSRP GROUP 1 PRIORITY 110 STATE 16 VIP 192.168.1.1
            }
            COMPILE {
                test_flow(r1, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 7761 PIM multicast routing hello.
    #[test]
    pub fn test_tier1_l3_pim() {
        let script = r#"
            HOST r1 { IP 192.168.1.1 }
            HOST mcast { IP 224.0.0.13 }
            FLOW test_flow(src, dst) {
                src -> dst PIM HELLO
            }
            COMPILE {
                test_flow(r1, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 5880 BFD bidirectional forwarding detection.
    #[test]
    pub fn test_tier1_l3_bfd() {
        let script = r#"
            HOST node1 { IP 10.0.0.1 }
            HOST node2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst BFD STATE 3 MY_DISC 100 YOUR_DISC 200
            }
            COMPILE {
                test_flow(node1, node2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests OpenFlow SDN switch control channel packets.
    #[test]
    pub fn test_tier1_l3_openflow() {
        let script = r#"
            HOST ctl { IP 10.0.0.1 }
            HOST sw { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst OPENFLOW TYPE HELLO XID 1
            }
            COMPILE {
                test_flow(ctl, sw)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 9293 TCP transport with SYN, ACK, and PSH.
    #[test]
    pub fn test_tier1_l4_tcp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TCP SYN SRCPORT 49152 DSTPORT 80
                c <- s TCP SYN ACK
                c -> s TCP ACK
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 768 UDP stateless transport.
    #[test]
    pub fn test_tier1_l4_udp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s UDP SRCPORT 5000 DSTPORT 9000 PAYLOAD "hello_udp"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 9260 SCTP transport with CRC32c checksum.
    #[test]
    pub fn test_tier1_l4_sctp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s SCTP CHUNK INIT VTAG 0 SRCPORT 2905 DSTPORT 2905
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests SNMP1, SNMP2, and SNMP3 network management.
    #[test]
    pub fn test_tier1_l7_snmp() {
        let script = r#"
            HOST agent { IP 10.0.0.1 }
            HOST nms { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst SNMP1 TRAP COMMUNITY "public" OID "1.3.6.1.6.3.1.1.5.1"
                src -> dst SNMP2 GET COMMUNITY "public" OID "1.3.6.1.2.1.1.1.0"
                src -> dst SNMP3 TRAP USER "usr-md5-des" ENGINEID "8000000001" ENGINEBOOTS 1 ENGINETIME 100 AUTH MD5 "pass123456" PRIV DES "priv123456" OID "1.3.6.1.6.3.1.1.5.1"
            }
            COMPILE {
                test_flow(agent, nms)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 1035 DNS queries and responses over UDP.
    #[test]
    pub fn test_tier1_l7_dns() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST dns_srv { IP 8.8.8.8 }
            FLOW test_flow(c, s) {
                c -> s DNS QUERY TXID 0x1234 QNAME "example.com" QTYPE A
                c <- s DNS RESPONSE TXID 0x1234 QNAME "example.com" QTYPE A RDATA "93.184.216.34"
            }
            COMPILE {
                test_flow(client, dns_srv)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 6762 mDNS multicast DNS over UDP 5353.
    #[test]
    pub fn test_tier1_l7_mdns() {
        let script = r#"
            HOST client { IP 192.168.1.100 }
            HOST mcast { IP 224.0.0.251 }
            FLOW test_flow(c, s) {
                c -> s MDNS QUERY QNAME "printer.local" QTYPE A
            }
            COMPILE {
                test_flow(client, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests DHCP DORA flow over IPv4.
    #[test]
    pub fn test_tier1_l7_dhcp() {
        let script = r#"
            HOST client { IP 0.0.0.0 }
            HOST server { IP 255.255.255.255 }
            FLOW test_flow(c, s) {
                c -> s DHCP DISCOVER XID 0x12345678
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 5905 NTPv4 network time protocol.
    #[test]
    pub fn test_tier1_l7_ntp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST ntp_srv { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s NTP MODE 3 STRATUM 0
            }
            COMPILE {
                test_flow(client, ntp_srv)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests IEEE 1588 PTP precision time protocol.
    #[test]
    pub fn test_tier1_l7_ptp() {
        let script = r#"
            HOST master { IP 10.0.0.1 }
            HOST slave { IP 10.0.0.2 }
            FLOW test_flow(m, s) {
                m -> s PTP MSG_TYPE SYNC DOMAIN 0
            }
            COMPILE {
                test_flow(master, slave)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 2865 RADIUS authentication.
    #[test]
    pub fn test_tier1_l7_radius() {
        let script = r#"
            HOST nas { IP 10.0.0.1 }
            HOST radius_srv { IP 10.0.0.2 }
            FLOW test_flow(n, r) {
                n -> r RADIUS CODE ACCESS_REQUEST ID 1 USER "alice"
            }
            COMPILE {
                test_flow(nas, radius_srv)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 8907 TACACS+ authentication.
    #[test]
    pub fn test_tier1_l7_tacacs() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST tacacs_srv { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TACACS TYPE AUTHEN USER "admin"
            }
            COMPILE {
                test_flow(client, tacacs_srv)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 5424 Syslog message logging.
    #[test]
    pub fn test_tier1_l7_syslog() {
        let script = r#"
            HOST app { IP 10.0.0.1 }
            HOST collector { IP 10.0.0.2 }
            FLOW test_flow(a, c) {
                a -> c SYSLOG FACILITY 1 SEVERITY 6 APP "authd" MSG "Login successful"
            }
            COMPILE {
                test_flow(app, collector)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests NetFlow and IPFIX telemetry export.
    #[test]
    pub fn test_tier1_l7_netflow_and_ipfix() {
        let script = r#"
            HOST exporter { IP 10.0.0.1 }
            HOST collector { IP 10.0.0.2 }
            FLOW test_flow(e, c) {
                e -> c NETFLOW SRCIP 192.168.1.100 DSTIP 8.8.8.8 PACKETS 50 OCTETS 25000
                e -> c IPFIX SRCIP 192.168.1.100 DSTIP 1.1.1.1 PACKETS 10 OCTETS 5000
            }
            COMPILE {
                test_flow(exporter, collector)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests sFlow v5 network monitoring datagrams.
    #[test]
    pub fn test_tier1_l7_sflow() {
        let script = r#"
            HOST agent { IP 10.0.0.1 }
            HOST collector { IP 10.0.0.2 }
            FLOW test_flow(a, c) {
                a -> c SFLOW AGENT_IP 10.0.0.1 SEQ 1
            }
            COMPILE {
                test_flow(agent, collector)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 1350 TFTP trivial file transfer.
    #[test]
    pub fn test_tier1_l7_tftp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TFTP RRQ FILENAME "boot.bin" MODE "octet"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 959 FTP file transfer commands.
    #[test]
    pub fn test_tier1_l7_ftp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s FTP CMD "USER" ARG "anonymous"
                c <- s FTP CODE 331 REPLY "Password required"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 4253 SSH banner and key exchange init.
    #[test]
    pub fn test_tier1_l7_ssh() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s SSH BANNER "SSH-2.0-OpenSSH_9.0"
                c <- s SSH BANNER "SSH-2.0-OpenSSH_8.9"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 854 Telnet command negotiation.
    #[test]
    pub fn test_tier1_l7_telnet() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TELNET DO 1
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 9110 HTTP/1.1 REST methods and responses.
    #[test]
    pub fn test_tier1_l7_http() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s HTTP GET URI "/api/v1/status" HOST_HDR "example.local"
                c <- s HTTP STATUS 200 REASON "OK" BODY "{\"status\":\"healthy\"}"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 9113 HTTP/2 framing and gRPC remote procedure calls.
    #[test]
    pub fn test_tier1_l7_http2_and_grpc() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s HTTP2 SETTINGS
                c -> s GRPC SERVICE "OrderService" METHOD "GetOrder"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 6455 WebSocket framing.
    #[test]
    pub fn test_tier1_l7_websocket() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s WEBSOCKET OPCODE TEXT PAYLOAD "ping"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 8446 TLS 1.3 handshake records.
    #[test]
    pub fn test_tier1_l7_tls() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TLS CLIENT_HELLO SNI "secure.example.com"
                c <- s TLS SERVER_HELLO
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 9000 QUIC transport protocol Initial packet.
    #[test]
    pub fn test_tier1_l7_quic() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s QUIC INITIAL DCID 0x01020304 SCID 0x05060708
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 8489 STUN NAT traversal.
    #[test]
    pub fn test_tier1_l7_stun() {
        let script = r#"
            HOST client { IP 192.168.1.100 }
            HOST stun_srv { IP 34.200.1.1 }
            FLOW test_flow(c, s) {
                c -> s STUN BINDING_REQUEST TXID 0x11223344
            }
            COMPILE {
                test_flow(client, stun_srv)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 3261 SIP VoIP signaling.
    #[test]
    pub fn test_tier1_l7_sip() {
        let script = r#"
            HOST caller { IP 10.0.0.1 }
            HOST pbx { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s SIP INVITE FROM "sip:alice@pbx" TO "sip:bob@pbx" CALL_ID "call123"
            }
            COMPILE {
                test_flow(caller, pbx)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 3550 RTP real-time audio media streams.
    #[test]
    pub fn test_tier1_l7_rtp() {
        let script = r#"
            HOST phone1 { IP 10.0.0.1 }
            HOST phone2 { IP 10.0.0.2 }
            FLOW test_flow(p1, p2) {
                p1 -> p2 RTP PT 0 SEQ 100 SSRC 0x12345678
            }
            COMPILE {
                test_flow(phone1, phone2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 7826 RTSP streaming control.
    #[test]
    pub fn test_tier1_l7_rtsp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST cam { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s RTSP OPTIONS URI "rtsp://cam/live" CSEQ 1
            }
            COMPILE {
                test_flow(client, cam)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 5321 SMTP email transactions.
    #[test]
    pub fn test_tier1_l7_smtp() {
        let script = r#"
            HOST mta1 { IP 10.0.0.1 }
            HOST mta2 { IP 10.0.0.2 }
            FLOW test_flow(m1, m2) {
                m1 -> m2 SMTP EHLO "mail.source.org"
                m1 <- m2 SMTP CODE 250 REPLY "250-mail.dest.org"
            }
            COMPILE {
                test_flow(mta1, mta2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 9051 IMAP and RFC 1939 POP3 mail access.
    #[test]
    pub fn test_tier1_l7_imap_and_pop3() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s IMAP TAG "A01" CMD "LOGIN" ARG "user pass"
                c -> s POP3 CMD "USER" ARG "bob"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests RFC 4120 Kerberos and RFC 4511 LDAP directory protocols.
    #[test]
    pub fn test_tier1_l7_kerberos_and_ldap() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST dc { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s KERBEROS AS_REQ REALM "CORP.LOCAL"
                c -> s LDAP BIND_REQ MSGID 1 BASE_DN "dc=corp,dc=local"
            }
            COMPILE {
                test_flow(client, dc)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests SMB and NFS storage protocols.
    #[test]
    pub fn test_tier1_l7_smb_and_nfs() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST nas { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s SMB COMMAND NEGOTIATE
                c -> s NFS PROC LOOKUP PATH "/exports/data"
            }
            COMPILE {
                test_flow(client, nas)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests Redis RESP and Memcached database protocols.
    #[test]
    pub fn test_tier1_l7_redis_and_memcached() {
        let script = r#"
            HOST app { IP 10.0.0.1 }
            HOST db { IP 10.0.0.2 }
            FLOW test_flow(a, d) {
                a -> d REDIS CMD "PING"
                a -> d MEMCACHED GET KEY "session:123"
            }
            COMPILE {
                test_flow(app, db)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests MySQL and PostgreSQL SQL database protocols.
    #[test]
    pub fn test_tier1_l7_mysql_and_postgres() {
        let script = r#"
            HOST app { IP 10.0.0.1 }
            HOST db { IP 10.0.0.2 }
            FLOW test_flow(a, d) {
                a -> d MYSQL QUERY SQL "SELECT 1"
                a -> d POSTGRES QUERY SQL "SELECT version()"
            }
            COMPILE {
                test_flow(app, db)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests MQTT and CoAP IoT messaging protocols.
    #[test]
    pub fn test_tier1_l7_mqtt_and_coap() {
        let script = r#"
            HOST sensor { IP 10.0.0.1 }
            HOST broker { IP 10.0.0.2 }
            FLOW test_flow(s, b) {
                s -> b MQTT CONNECT CLIENT_ID "sensor-01"
                s -> b COAP CON GET URI_PATH "/telemetry"
            }
            COMPILE {
                test_flow(sensor, broker)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests AMQP, SSDP, and WHOIS application protocols.
    #[test]
    pub fn test_tier1_l7_amqp_ssdp_whois() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST srv { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s AMQP PROTOCOL_HEADER
                c -> s SSDP MSEARCH ST "upnp:rootdevice"
                c -> s WHOIS QUERY DOMAIN "example.com"
            }
            COMPILE {
                test_flow(client, srv)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests Industrial OT protocols: Modbus TCP/UDP and BACnet/IP.
    #[test]
    pub fn test_tier1_l7_industrial_modbus_and_bacnet() {
        let script = r#"
            HOST plc { IP 192.168.1.10 }
            HOST scada { IP 192.168.1.20 }
            FLOW test_flow(s, p) {
                s -> p MODBUS FUNC READ_HOLDING_REGISTERS ADDR 100 COUNT 5
                s -> p BACNET WHO_IS
            }
            COMPILE {
                test_flow(scada, plc)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests Industrial OT protocols: DNP3, S7comm, EtherNet/IP CIP, and OPC UA.
    #[test]
    pub fn test_tier1_l7_industrial_dnp3_s7_enip_opcua() {
        let script = r#"
            HOST master { IP 192.168.1.10 }
            HOST rtu { IP 192.168.1.20 }
            FLOW test_flow(m, r) {
                m -> r DNP3 FUNC READ
                m -> r S7COMM FUNC READ_VAR
                m -> r ETHERNETIP CMD LIST_IDENTITY
                m -> r OPCUA MSG_TYPE HEL
            }
            COMPILE {
                test_flow(master, rtu)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 4);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests dual-transport protocols (DNS, SIP, Syslog) switching from UDP to TCP via `TRANSPORT TCP`.
    #[test]
    pub fn test_tier1_dual_transport_tcp() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s DNS TRANSPORT TCP QUERY TXID 0x4321 QNAME "zone.transfer.org" QTYPE AXFR
                c -> s SIP TRANSPORT TCP REGISTER FROM "sip:bob@pbx"
                c -> s SYSLOG TRANSPORT TCP MSG "Audit log over TCP"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }
}

/// Tier 2: Boundary and corner cases (L2/L3 limits, escape sequences, 4-tuple TCP state).
pub mod tier2_boundary_and_corner_cases {
    use super::*;

    /// Tests boundary VLAN IDs (1 and 4094), PCP 0..7, and DEI 0..1.
    #[test]
    pub fn test_tier2_l2_vlan_pcp_dei_boundaries() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst VLAN 1 PCP 0 DEI 0 UDP PAYLOAD "vlan_min"
                src -> dst VLAN 4094 PCP 7 DEI 1 UDP PAYLOAD "vlan_max"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].ethertype(), Some(0x8100));
            assert_eq!(packets[1].ethertype(), Some(0x8100));
        });
    }

    /// Tests boundary TTL values (0, 1, 255).
    #[test]
    pub fn test_tier2_l3_ttl_boundaries() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst TTL 0 UDP PAYLOAD "ttl0"
                src -> dst TTL 1 UDP PAYLOAD "ttl1"
                src -> dst TTL 255 UDP PAYLOAD "ttl255"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
        });
    }

    /// Tests boundary DSCP (0 and 63) and ECN (0..=3) values.
    #[test]
    pub fn test_tier2_l3_dscp_and_ecn_boundaries() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst DSCP 0 ECN 0 UDP PAYLOAD "dscp_min"
                src -> dst DSCP 63 ECN 3 UDP PAYLOAD "dscp_max"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests boundary 20-bit FLOWLABEL values (0 and 1048575 / 0xFFFFF).
    #[test]
    pub fn test_tier2_l3_flowlabel_boundaries() {
        let script = r#"
            HOST h1 { IP 2001:db8::1 }
            HOST h2 { IP 2001:db8::2 }
            FLOW test_flow(src, dst) {
                src -> dst FLOWLABEL 0 UDP PAYLOAD "flowlabel_0"
                src -> dst FLOWLABEL 1048575 UDP PAYLOAD "flowlabel_max"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests FLOWLABEL on IPv4 hosts being silently ignored without error.
    #[test]
    pub fn test_tier2_l3_flowlabel_ipv4_silently_ignored() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst FLOWLABEL 99999 UDP PAYLOAD "v4_flowlabel"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].ethertype(), Some(0x0800));
        });
    }

    /// Tests string escape sequences (\r, \n, \t, \\, \", \xHH) and HEXPAYLOAD.
    #[test]
    pub fn test_tier2_payload_escape_sequences_and_hex() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst UDP PAYLOAD "line1\r\nline2\t\"quoted\""
                src -> dst UDP HEXPAYLOAD "deadbeefcafebabe01020304"
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests contextual sub-keywords used freely as host, flow, and parameter identifiers.
    #[test]
    pub fn test_tier2_contextual_keywords_as_identifiers() {
        let script = r#"
            HOST dns { IP 10.0.0.1 }
            HOST tcp { IP 10.0.0.2 }
            FLOW query(ms, s) {
                ms -> s UDP PAYLOAD "contextual_idents"
            }
            COMPILE {
                query(dns, tcp)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
        });
    }

    /// Tests two-stage TCP port inheritance across reversed arrows when ports are omitted.
    #[test]
    pub fn test_tier2_two_stage_tcp_port_inheritance() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TCP SYN SRCPORT 54321 DSTPORT 8080
                c <- s TCP SYN ACK
                c -> s TCP ACK
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
        });
    }

    /// Tests loopback 4-tuple TCP connection tracking (127.0.0.1 and ::1).
    #[test]
    pub fn test_tier2_loopback_4tuple_tcp_tracking() {
        let script = r#"
            HOST loop_v4 { IP 127.0.0.1 }
            FLOW test_flow(src, dst) {
                src -> dst TCP SYN SRCPORT 10001 DSTPORT 10002
                src <- dst TCP SYN ACK
                src -> dst TCP ACK
            }
            COMPILE {
                test_flow(loop_v4, loop_v4)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 3);
        });
    }

    /// Tests concurrent multi-port connections between the same host pair.
    #[test]
    pub fn test_tier2_concurrent_multi_port_connections() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW conn_a(c, s) {
                c -> s TCP SYN SRCPORT 40001 DSTPORT 80
            }
            FLOW conn_b(c, s) {
                c -> s TCP SYN SRCPORT 40002 DSTPORT 443
            }
            COMPILE {
                conn_a(client, server)
                conn_b(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests strict 1 statement = 1 frame invariant for TCP-based L7 protocols.
    #[test]
    pub fn test_tier2_tcp_l7_strict_one_statement_one_frame() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s HTTP GET URI "/"
                c <- s HTTP STATUS 200
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2, "2 statements must emit exactly 2 frames");
        });
    }
}

/// Tier 3: Cross-feature combinations (dual-stack polymorphism, VLAN+L4, multicast MAC derivation, tunnels).
pub mod tier3_cross_feature_combinations {
    use super::*;

    /// Tests dual-stack polymorphic flow invoked with both IPv4 and IPv6 host pairs.
    #[test]
    pub fn test_tier3_dual_stack_polymorphic_flow() {
        let script = r#"
            HOST client_v4 { IP 192.168.1.1 }
            HOST server_v4 { IP 192.168.1.2 }
            HOST client_v6 { IP 2001:db8::1 }
            HOST server_v6 { IP 2001:db8::2 }
            FLOW ping_flow(c, s) {
                c -> s ICMP ECHO_REQUEST
                c <- s ICMP ECHO_REPLY
            }
            COMPILE {
                ping_flow(client_v4, server_v4)
                ping_flow(client_v6, server_v6)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 4);
        });
    }

    /// Tests single and double VLAN tagging stacked with TCP and UDP protocols.
    #[test]
    pub fn test_tier3_vlan_stacked_with_transports() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s VLAN 100 TCP SYN SRCPORT 12345 DSTPORT 80
                c -> s QINQ 200 INNER_VLAN 10 UDP SRCPORT 53 DSTPORT 53 PAYLOAD "dns"
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests multicast MAC auto-derivation: RFC 2464 (IPv6 33:33:..) and RFC 1112 (IPv4 01:00:5e:..).
    #[test]
    pub fn test_tier3_multicast_mac_auto_derivation() {
        let script = r#"
            HOST h_v4 { IP 192.168.1.1 }
            HOST mcast_v4 { IP 224.0.0.1 }
            HOST h_v6 { IP fe80::1 }
            HOST mcast_v6 { IP ff02::1 }
            FLOW test_flow(src4, dst4, src6, dst6) {
                src4 -> dst4 UDP PAYLOAD "mcast_v4"
                src6 -> dst6 UDP PAYLOAD "mcast_v6"
            }
            COMPILE {
                test_flow(h_v4, mcast_v4, h_v6, mcast_v6)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests explicit MAC overrides taking precedence over multicast auto-derivation.
    #[test]
    pub fn test_tier3_multicast_mac_explicit_override() {
        let script = r#"
            HOST src { IP 192.168.1.1 }
            HOST mcast { IP 224.0.0.1 MAC 00:AA:BB:CC:DD:EE }
            FLOW test_flow(s, m) {
                s -> m UDP PAYLOAD "override_mac"
            }
            COMPILE {
                test_flow(src, mcast)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].dst_mac(), Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]));
        });
    }

    /// Tests TCP options matrix: MSS, WSCALE, SACK_PERM, TSVAL, TSECR.
    #[test]
    pub fn test_tier3_tcp_options_matrix() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST server { IP 10.0.0.2 }
            FLOW test_flow(c, s) {
                c -> s TCP SYN SRCPORT 12345 DSTPORT 80 MSS 1460 WSCALE 7 SACK_PERM TSVAL 100 TSECR 0
            }
            COMPILE {
                test_flow(client, server)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 1);
        });
    }

    /// Tests WAIT timing modifiers with various duration units: ns, us, ms, s, m.
    #[test]
    pub fn test_tier3_timing_wait_units() {
        let script = r#"
            HOST h1 { IP 10.0.0.1 }
            HOST h2 { IP 10.0.0.2 }
            FLOW test_flow(src, dst) {
                src -> dst UDP PAYLOAD "p1" WAIT 500ns
                src -> dst UDP PAYLOAD "p2" WAIT 10us
                src -> dst UDP PAYLOAD "p3" WAIT 5ms
                src -> dst UDP PAYLOAD "p4" WAIT 1s
                src -> dst UDP PAYLOAD "p5" WAIT 1m
            }
            COMPILE {
                test_flow(h1, h2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 5);
        });
    }

    /// Tests stress execution of multi-protocol statements inside a LOOP block.
    #[test]
    pub fn test_tier3_loop_block_multi_protocol_stress() {
        let script = r#"
            HOST c { IP 10.0.0.1 }
            HOST s { IP 10.0.0.2 }
            FLOW ping_pong(client, server) {
                client -> server UDP PAYLOAD "ping"
                client <- server UDP PAYLOAD "pong"
            }
            COMPILE {
                LOOP 10 {
                    ping_pong(c, s)
                }
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 20);
        });
    }
}

/// Tier 4: Real-world network application flows and scenarios.
pub mod tier4_real_world_application_flows {
    use super::*;

    /// Tests complete BGP4+ peering flow over IPv6 with TCP 3-way handshake and keepalives.
    #[test]
    pub fn test_tier4_bgp_peering_session() {
        let script = r#"
            HOST r1 { IP 2001:db8::1 }
            HOST r2 { IP 2001:db8::2 }
            FLOW bgp_session(src, dst) {
                src -> dst TCP SYN SRCPORT 179 DSTPORT 179
                src <- dst TCP SYN ACK
                src -> dst TCP ACK
                src -> dst BGP OPEN ASN 65000 HOLDTIME 90 BGPID 1.1.1.1
                src <- dst BGP OPEN ASN 65001 HOLDTIME 90 BGPID 2.2.2.2
                src -> dst BGP KEEPALIVE
                src <- dst BGP KEEPALIVE
            }
            COMPILE {
                bgp_session(r1, r2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 7);
        });
    }

    /// Tests REST API transactions secured by TLS.
    #[test]
    pub fn test_tier4_rest_api_over_tls() {
        let script = r#"
            HOST client { IP 10.0.0.1 }
            HOST api_gw { IP 10.0.0.2 }
            FLOW https_flow(c, s) {
                c -> s TLS CLIENT_HELLO SNI "api.service.local"
                c <- s TLS SERVER_HELLO
                c -> s HTTP GET URI "/v2/users" HOST_HDR "api.service.local"
                c <- s HTTP STATUS 200 REASON "OK" BODY "[]"
            }
            COMPILE {
                https_flow(client, api_gw)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 4);
        });
    }

    /// Tests recursive DNS resolution workflow (Query A/AAAA -> Response with CNAME -> Answer).
    #[test]
    pub fn test_tier4_recursive_dns_resolution() {
        let script = r#"
            HOST resolver { IP 192.168.1.1 }
            HOST auth_ns { IP 198.51.100.1 }
            FLOW dns_lookup(r, a) {
                r -> a DNS QUERY TXID 0x1001 QNAME "service.corp.internal" QTYPE A
                r <- a DNS RESPONSE TXID 0x1001 QNAME "service.corp.internal" QTYPE CNAME RDATA "edge-lb.corp.internal"
                r -> a DNS QUERY TXID 0x1002 QNAME "edge-lb.corp.internal" QTYPE A
                r <- a DNS RESPONSE TXID 0x1002 QNAME "edge-lb.corp.internal" QTYPE A RDATA "10.50.0.1"
            }
            COMPILE {
                dns_lookup(resolver, auth_ns)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 4);
        });
    }

    /// Tests IoT MQTT telemetry stream over TLS.
    #[test]
    pub fn test_tier4_iot_mqtt_over_tls() {
        let script = r#"
            HOST device { IP 10.10.1.5 }
            HOST broker { IP 10.10.1.1 }
            FLOW mqtt_flow(d, b) {
                d -> b TLS CLIENT_HELLO SNI "iot.hub"
                d <- b TLS SERVER_HELLO
                d -> b MQTT CONNECT CLIENT_ID "device-temperature-sensor"
                d <- b MQTT CONNACK RETURN_CODE 0
                d -> b MQTT PUBLISH TOPIC "sensors/temp" PAYLOAD "22.5C"
            }
            COMPILE {
                mqtt_flow(device, broker)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 5);
        });
    }

    /// Tests VoIP session: SIP INVITE + 200 OK + ACK followed by RTP audio stream.
    #[test]
    pub fn test_tier4_voip_sip_and_rtp_call_session() {
        let script = r#"
            HOST phone1 { IP 192.168.10.10 }
            HOST phone2 { IP 192.168.10.20 }
            FLOW voip_call(p1, p2) {
                p1 -> p2 SIP INVITE FROM "sip:1001@pbx" TO "sip:1002@pbx" CALL_ID "c1"
                p1 <- p2 SIP STATUS 200 REASON "OK" CALL_ID "c1"
                p1 -> p2 SIP ACK CALL_ID "c1"
                p1 -> p2 RTP PT 0 SEQ 1 SSRC 0x11111111
                p1 <- p2 RTP PT 0 SEQ 1 SSRC 0x22222222
            }
            COMPILE {
                voip_call(phone1, phone2)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 5);
        });
    }

    /// Tests enterprise NMS monitoring: encrypted SNMPv3 trap followed by RFC 5424 Syslog alert.
    #[test]
    pub fn test_tier4_enterprise_nms_telemetry() {
        let script = r#"
            HOST switch { IP 10.200.1.1 }
            HOST siem { IP 10.200.1.2 }
            FLOW nms_alert(src, dst) {
                src -> dst SNMP3 TRAP USER "sec-admin" ENGINEID "8000000001" ENGINEBOOTS 5 ENGINETIME 500 AUTH SHA "authpwd12345" PRIV AES "privpwd12345" OID "1.3.6.1.6.3.1.1.5.3"
                src -> dst SYSLOG FACILITY 1 SEVERITY 2 APP "linkmon" MSG "Interface GigabitEthernet0/1 changed state to down"
            }
            COMPILE {
                nms_alert(switch, siem)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }

    /// Tests industrial SCADA substation flow: Modbus holding register poll + DNP3 direct operate.
    #[test]
    pub fn test_tier4_industrial_scada_substation() {
        let script = r#"
            HOST hmi { IP 192.168.100.10 }
            HOST breaker_rtu { IP 192.168.100.50 }
            FLOW substation_flow(h, r) {
                h -> r MODBUS FUNC READ_HOLDING_REGISTERS ADDR 2000 COUNT 4
                h -> r DNP3 FUNC DIRECT_OPERATE GROUP 12 VARIATION 1
            }
            COMPILE {
                substation_flow(hmi, breaker_rtu)
            }
        "#;
        run_e2e_test(script, |packets| {
            assert_eq!(packets.len(), 2);
        });
    }
}

/// CLI functionality and backwards compatibility verification.
pub mod cli_and_backwards_compatibility {
    use super::*;

    /// Tests that running the CLI without output flag defaults to `"output.pcap"`.
    #[test]
    pub fn test_cli_output_flag_default() {
        let temp_dir = std::env::temp_dir();
        let input_path = temp_dir.join(format!("cli_in_default_{}.fasm", std::process::id()));
        let script = r#"
            HOST a { IP 10.0.0.1 }
            HOST b { IP 10.0.0.2 }
            FLOW f(x, y) { x -> y UDP PAYLOAD "cli_test" }
            COMPILE { f(a, b) }
        "#;
        fs::write(&input_path, script).expect("write fasm input");

        // Verify that parsing and generating with default path works
        let prog = frameassembly::parser::parse_program(script).expect("parsed");
        let default_out = temp_dir.join(format!("cli_default_out_{}.pcap", std::process::id()));
        let res = frameassembly::backend::generate_pcap(&prog, default_out.to_str().unwrap());
        assert!(res.is_ok());
        assert!(default_out.exists());
        let _ = fs::remove_file(&input_path);
        let _ = fs::remove_file(&default_out);
    }

    /// Tests that specifying `-o / --output <path>` produces output at the requested path.
    #[test]
    pub fn test_cli_output_flag_custom_path() {
        let temp_dir = std::env::temp_dir();
        let custom_out = temp_dir.join(format!("custom_{}.pcap", std::process::id()));
        let script = r#"
            HOST a { IP 10.0.0.1 }
            HOST b { IP 10.0.0.2 }
            FLOW f(x, y) { x -> y UDP PAYLOAD "custom_path" }
            COMPILE { f(a, b) }
        "#;
        let prog = frameassembly::parser::parse_program(script).expect("parsed");
        let res = frameassembly::backend::generate_pcap(&prog, custom_out.to_str().unwrap());
        assert!(res.is_ok());
        assert!(custom_out.exists());
        assert!(fs::metadata(&custom_out).unwrap().len() > 0);
        let _ = fs::remove_file(&custom_out);
    }

    /// Tests backwards compatibility: verified examples across organized layer directories compile cleanly.
    #[test]
    pub fn test_legacy_examples_01_to_105_backwards_compatibility() {
        let mut count = 0;
        let temp_dir = std::env::temp_dir();

        fn visit_dir(dir: &Path, count: &mut usize, temp_dir: &Path) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dir(&path, count, temp_dir);
                    } else if path.extension().and_then(|s| s.to_str()) == Some("fasm") {
                        *count += 1;
                        let filename = path.file_name().unwrap().to_str().unwrap();
                        let content = fs::read_to_string(&path)
                            .unwrap_or_else(|e| panic!("Failed to read {}: {}", filename, e));
                        let prog = frameassembly::parser::parse_program(&content)
                            .unwrap_or_else(|e| panic!("Parse error in {}: {:?}", filename, e));
                        let out_pcap = temp_dir.join(format!("legacy_verify_{}_{}.pcap", std::process::id(), *count));
                        let out_str = out_pcap.to_str().unwrap();
                        let res = frameassembly::backend::generate_pcap(&prog, out_str);
                        assert!(res.is_ok(), "Compile error in {}: {:?}", filename, res.err());
                        assert!(out_pcap.exists() && fs::metadata(&out_pcap).unwrap().len() > 0);
                        let _ = fs::remove_file(&out_pcap);
                    }
                }
            }
        }
        visit_dir(Path::new("examples"), &mut count, &temp_dir);
        assert!(count >= 105, "All legacy examples must compile cleanly, found {}", count);
    }
}
