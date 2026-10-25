//! End-to-End (E2E) integration test suite for FrameAssembly Layer 2, Layer 3, and Layer 4 protocols.
//!
//! Validates the complete switching, routing, tunneling, security, and transport protocol catalog
//! across IPv4 and IPv6 endpoints with zero-keyword defaults and explicit field overrides:
//! - Tier 1: Layer 2 (`ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`), Layer 3
//!   (`ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`,
//!   `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`), and Layer 4 (`TCP`, `UDP`,
//!   `SCTP`, plus dual-transport `TRANSPORT TCP`).
//! - Tier 2: Boundary values (VLAN PCP/DEI, TTL, DSCP/ECN, 20-bit IPv6 Flow Labels, string escapes,
//!   contextual identifiers, and 4-tuple TCP sequence/port state tracking).
//! - Tier 3: Cross-feature combinations (dual-stack polymorphism, stacked VLANs, RFC 1112 / RFC 2464
//!   multicast MAC derivation, RFC 7323 TCP options, `WAIT` timing units, and `LOOP` blocks).
//! - CLI & Corpus Backwards Compatibility: default and custom output paths plus corpus compilation.

use std::fs;
use std::path::Path;

/// Context holding a captured network frame from an emitted PCAPNG file.
#[derive(Debug, Clone)]
pub struct PacketContext {
    /// Raw Ethernet frame byte buffer extracted from an Enhanced Packet Block.
    pub raw: Vec<u8>,
}

#[allow(dead_code)]
impl PacketContext {
    /// Extracts the 16-bit big-endian Ethernet EtherType at byte offset `12..14`.
    pub fn ethertype(&self) -> Option<u16> {
        (self.raw.len() >= 14).then(|| u16::from_be_bytes([self.raw[12], self.raw[13]]))
    }

    /// Extracts the 6-byte Ethernet source MAC address at byte offset `6..12`.
    pub fn src_mac(&self) -> Option<[u8; 6]> {
        self.raw.get(6..12).and_then(|s| s.try_into().ok())
    }

    /// Extracts the 6-byte Ethernet destination MAC address at byte offset `0..6`.
    pub fn dst_mac(&self) -> Option<[u8; 6]> {
        self.raw.get(0..6).and_then(|d| d.try_into().ok())
    }
}

/// Reads all Enhanced Packet Blocks from an emitted PCAPNG file on disk.
fn read_pcapng_packets(path: &Path) -> Result<Vec<PacketContext>, String> {
    let capture_file =
        fs::File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let mut ng_reader = pcap_file::pcapng::PcapNgReader::new(capture_file)
        .map_err(|e| format!("Failed to create PCAPNG reader: {}", e))?;
    let mut captured_frames = Vec::new();
    while let Some(next_blk) = ng_reader.next_block() {
        let parsed_blk = next_blk.map_err(|e| format!("Failed to read PCAPNG block: {}", e))?;
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = parsed_blk {
            captured_frames.push(PacketContext { raw: epb.data.to_vec() });
        }
    }
    Ok(captured_frames)
}

/// Compiles a `.fasm` script to a temporary PCAPNG file and runs the verification closure.
///
/// Panics immediately if parsing, semantic validation, or PCAPNG generation fails, or if zero
/// packets are emitted.
pub fn run_e2e_test<F>(script: &str, verifier: F)
where
    F: FnOnce(&[PacketContext]),
{
    /// Monotonic counter ensuring thread-safe temporary PCAPNG filenames across parallel tests.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq_id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_pcap = std::env::temp_dir().join(format!(
        "e2e_l234_{}_{}_{}.pcap",
        std::process::id(),
        seq_id,
        nanos
    ));
    let temp_pcap_str = temp_pcap.to_str().unwrap();

    match frameassembly::parser::parse_program(script) {
        Ok(program) => match frameassembly::backend::generate_pcap(&program, temp_pcap_str) {
            Ok(_) => {
                let packets = read_pcapng_packets(&temp_pcap).expect("read emitted pcapng");
                let _ = fs::remove_file(&temp_pcap);
                assert!(!packets.is_empty(), "Generated PCAPNG must contain at least one packet");
                verifier(&packets);
            }
            Err(compile_err) => {
                let _ = fs::remove_file(&temp_pcap);
                panic!("E2E L2-L4 compilation failure: {:?}", compile_err);
            }
        },
        Err(parse_err) => {
            let _ = fs::remove_file(&temp_pcap);
            panic!("E2E L2-L4 parser failure: {:?}", parse_err);
        }
    }
}

/// Tier 1: Feature coverage across Layer 2, Layer 3, and Layer 4 protocols.
pub mod tier1_feature_coverage {
    use super::*;

    /// Tests RFC 826 ARP protocol with zero sub-keywords (default `REQUEST`) and explicit `REPLY`.
    #[test]
    pub fn test_tier1_l2_arp() {
        let arp_script = r#"
            HOST arp_host_a { IP 192.168.10.1 MAC 00:11:22:33:44:01 }
            HOST arp_host_b { IP 192.168.10.2 MAC 00:11:22:33:44:02 }
            FLOW arp_resolution(requester, responder) {
                requester -> responder ARP
                requester <- responder ARP REPLY
            } COMPILE { arp_resolution(arp_host_a, arp_host_b) }"#;
        run_e2e_test(arp_script, |arp_pkts| assert_eq!((arp_pkts.len(), arp_pkts[0].ethertype(), arp_pkts[1].ethertype()), (2, Some(0x0806), Some(0x0806))));
    }

    /// Tests IEEE 802.1Q VLAN framing (`0x8100`) and tag control fields.
    #[test]
    pub fn test_tier1_l2_vlan() {
        let vlan_script = r#"
            HOST vlan_node_1 { IP 10.10.1.1 }
            HOST vlan_node_2 { IP 10.10.1.2 }
            FLOW vlan_tagged_flow(access_sw, trunk_sw) {
                access_sw -> trunk_sw VLAN 100 UDP PAYLOAD "vlan100"
            } COMPILE { vlan_tagged_flow(vlan_node_1, vlan_node_2) }"#;
        run_e2e_test(vlan_script, |vlan_pkts| assert_eq!((vlan_pkts.len(), vlan_pkts[0].ethertype()), (1, Some(0x8100))));
    }

    /// Tests IEEE 802.1ad QinQ (`0x88A8`) provider bridge double VLAN tagging.
    #[test]
    pub fn test_tier1_l2_qinq() {
        let qinq_script = r#"
            HOST metro_pe_1 { IP 10.10.2.1 }
            HOST metro_pe_2 { IP 10.10.2.2 }
            FLOW qinq_tunnel_flow(pe_ingress, pe_egress) {
                pe_ingress -> pe_egress QINQ 200 INNER_VLAN 10 UDP PAYLOAD "qinq"
            } COMPILE { qinq_tunnel_flow(metro_pe_1, metro_pe_2) }"#;
        run_e2e_test(qinq_script, |qinq_pkts| assert_eq!((qinq_pkts.len(), qinq_pkts[0].ethertype()), (1, Some(0x88A8))));
    }

    /// Tests IEEE 802.1AB LLDP (`0x88CC`) link layer discovery protocol framing.
    #[test]
    pub fn test_tier1_l2_lldp() {
        let lldp_script = r#"
            HOST leaf_sw_1 { IP 10.10.3.1 }
            HOST spine_sw_2 { IP 10.10.3.2 }
            FLOW lldp_announce(leaf_node, spine_node) {
                leaf_node -> spine_node LLDP SYSNAME "switch-leaf1"
            } COMPILE { lldp_announce(leaf_sw_1, spine_sw_2) }"#;
        run_e2e_test(lldp_script, |lldp_pkts| assert_eq!((lldp_pkts.len(), lldp_pkts[0].ethertype()), (1, Some(0x88CC))));
    }

    /// Tests IEEE 802.1D STP spanning tree bridge protocol data unit multicast MAC.
    #[test]
    pub fn test_tier1_l2_stp() {
        let stp_script = r#"
            HOST root_bridge { IP 10.10.4.1 }
            HOST desig_bridge { IP 10.10.4.2 }
            FLOW stp_bpdu_flow(root_br, desig_br) {
                root_br -> desig_br STP
            } COMPILE { stp_bpdu_flow(root_bridge, desig_bridge) }"#;
        run_e2e_test(stp_script, |stp_pkts| assert_eq!((stp_pkts.len(), stp_pkts[0].dst_mac()), (1, Some([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]))));
    }

    /// Tests IEEE 802.3ad LACP link aggregation control protocol slow-protocols MAC.
    #[test]
    pub fn test_tier1_l2_lacp() {
        let lacp_script = r#"
            HOST lag_actor { IP 10.10.5.1 }
            HOST lag_partner { IP 10.10.5.2 }
            FLOW lacp_pdu_flow(actor_port, partner_port) {
                actor_port -> partner_port LACP
            } COMPILE { lacp_pdu_flow(lag_actor, lag_partner) }"#;
        run_e2e_test(lacp_script, |lacp_pkts| assert_eq!((lacp_pkts.len(), lacp_pkts[0].dst_mac()), (1, Some([0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]))));
    }

    /// Tests IEEE 802.1X EAPOL (`0x888E`) port access authentication start frame.
    #[test]
    pub fn test_tier1_l2_eapol() {
        let eapol_script = r#"
            HOST supplicant_pc { IP 10.10.6.1 }
            HOST auth_switch { IP 10.10.6.2 }
            FLOW eapol_start_flow(supp, auth_sw) {
                supp -> auth_sw EAPOL TYPE START
            } COMPILE { eapol_start_flow(supplicant_pc, auth_switch) }"#;
        run_e2e_test(eapol_script, |eapol_pkts| assert_eq!((eapol_pkts.len(), eapol_pkts[0].ethertype()), (1, Some(0x888E))));
    }

    /// Tests RFC 3032 MPLS (`0x8847`) unicast label stack encoding.
    #[test]
    pub fn test_tier1_l2_mpls() {
        let mpls_script = r#"
            HOST lsr_ingress { IP 10.10.7.1 }
            HOST lsr_egress { IP 10.10.7.2 }
            FLOW mpls_lsp_flow(ler_in, ler_out) {
                ler_in -> ler_out MPLS 10001 EXP 3 BOS 1 MPLS_TTL 64 UDP PAYLOAD "mpls"
            } COMPILE { mpls_lsp_flow(lsr_ingress, lsr_egress) }"#;
        run_e2e_test(mpls_script, |mpls_pkts| assert_eq!((mpls_pkts.len(), mpls_pkts[0].ethertype()), (1, Some(0x8847))));
    }

    /// Tests RFC 792 / RFC 4443 polymorphic ICMP echo request and reply.
    #[test]
    pub fn test_tier1_l3_icmp() {
        let icmp_script = r#"
            HOST ping_src_v4 { IP 192.168.11.1 }
            HOST ping_dst_v4 { IP 192.168.11.2 }
            FLOW icmp_echo_pair(pinger, responder) {
                pinger -> responder ICMP ECHO_REQUEST
                pinger <- responder ICMP ECHO_REPLY
            } COMPILE { icmp_echo_pair(ping_src_v4, ping_dst_v4) }"#;
        run_e2e_test(icmp_script, |icmp_pkts| assert_eq!((icmp_pkts.len(), icmp_pkts[0].ethertype(), icmp_pkts[0].raw[23]), (2, Some(0x0800), 1)));
    }

    /// Tests RFC 4861 IPv6 Neighbor Discovery Protocol (`NDP`) solicitation and advertisement.
    #[test]
    pub fn test_tier1_l3_ndp() {
        let ndp_script = r#"
            HOST ndp_host_a { IP 2001:db8:10::1 }
            HOST ndp_host_b { IP 2001:db8:10::2 }
            FLOW ndp_resolve_flow(solicit_node, target_node) {
                solicit_node -> target_node NDP NEIGHBOR_SOLICIT TARGET 2001:db8:10::2
                solicit_node <- target_node NDP NEIGHBOR_ADVERT TARGET 2001:db8:10::2
            } COMPILE { ndp_resolve_flow(ndp_host_a, ndp_host_b) }"#;
        run_e2e_test(ndp_script, |ndp_pkts| assert_eq!((ndp_pkts.len(), ndp_pkts[0].ethertype(), ndp_pkts[0].raw[20]), (2, Some(0x86DD), 58)));
    }

    /// Tests RFC 2236 / RFC 3376 IGMP multicast group membership report.
    #[test]
    pub fn test_tier1_l3_igmp() {
        let igmp_script = r#"
            HOST igmp_member { IP 192.168.12.10 }
            HOST igmp_all_hosts { IP 224.0.0.1 }
            FLOW igmp_join_flow(host_member, mcast_grp) {
                host_member -> mcast_grp IGMP REPORT GROUP 239.1.1.1
            } COMPILE { igmp_join_flow(igmp_member, igmp_all_hosts) }"#;
        run_e2e_test(igmp_script, |igmp_pkts| assert_eq!((igmp_pkts.len(), igmp_pkts[0].ethertype(), igmp_pkts[0].raw[23]), (1, Some(0x0800), 2)));
    }

    /// Tests RFC 2710 / RFC 3810 MLD IPv6 Multicast Listener Discovery report.
    #[test]
    pub fn test_tier1_l3_mld() {
        let mld_script = r#"
            HOST mld_listener { IP fe80::10 }
            HOST mld_all_nodes { IP ff02::1 }
            FLOW mld_report_flow(listener_v6, mcast_v6) {
                listener_v6 -> mcast_v6 MLD REPORT MULTICAST_ADDR ff02::1:2
            } COMPILE { mld_report_flow(mld_listener, mld_all_nodes) }"#;
        run_e2e_test(mld_script, |mld_pkts| assert_eq!((mld_pkts.len(), mld_pkts[0].ethertype()), (1, Some(0x86DD))));
    }

    /// Tests RFC 2784 / RFC 2890 GRE tunnel encapsulation with key extension.
    #[test]
    pub fn test_tier1_l3_gre() {
        let gre_script = r#"
            HOST gre_tun_a { IP 10.20.1.1 }
            HOST gre_tun_b { IP 10.20.1.2 }
            FLOW gre_tunnel_flow(tun_src, tun_dst) {
                tun_src -> tun_dst GRE GRE_KEY 1234 PAYLOAD "inner_ip"
            } COMPILE { gre_tunnel_flow(gre_tun_a, gre_tun_b) }"#;
        run_e2e_test(gre_script, |gre_pkts| assert_eq!((gre_pkts.len(), gre_pkts[0].ethertype(), gre_pkts[0].raw[23]), (1, Some(0x0800), 47)));
    }

    /// Tests RFC 7348 VXLAN overlay network encapsulation on UDP port 4789.
    #[test]
    pub fn test_tier1_l3_vxlan() {
        let vxlan_script = r#"
            HOST vxlan_vtep_1 { IP 192.168.10.1 }
            HOST vxlan_vtep_2 { IP 192.168.10.2 }
            FLOW vxlan_overlay_flow(vtep_a, vtep_b) {
                vtep_a -> vtep_b VXLAN VNI 5000 PAYLOAD "inner_eth"
            } COMPILE { vxlan_overlay_flow(vxlan_vtep_1, vxlan_vtep_2) }"#;
        run_e2e_test(vxlan_script, |vxlan_pkts| assert_eq!((vxlan_pkts.len(), u16::from_be_bytes([vxlan_pkts[0].raw[36], vxlan_pkts[0].raw[37]])), (1, 4789)));
    }

    /// Tests RFC 8926 GENEVE overlay network encapsulation on UDP port 6081.
    #[test]
    pub fn test_tier1_l3_geneve() {
        let geneve_script = r#"
            HOST geneve_nve_1 { IP 192.168.20.1 }
            HOST geneve_nve_2 { IP 192.168.20.2 }
            FLOW geneve_overlay_flow(nve_a, nve_b) {
                nve_a -> nve_b GENEVE VNI 10000 PAYLOAD "inner_payload"
            } COMPILE { geneve_overlay_flow(geneve_nve_1, geneve_nve_2) }"#;
        run_e2e_test(geneve_script, |geneve_pkts| assert_eq!((geneve_pkts.len(), u16::from_be_bytes([geneve_pkts[0].raw[36], geneve_pkts[0].raw[37]])), (1, 6081)));
    }

    /// Tests RFC 4303 IPsec ESP encapsulating security payload (IP protocol 50).
    #[test]
    pub fn test_tier1_l3_ipsec_esp() {
        let esp_script = r#"
            HOST esp_vpn_gw1 { IP 198.51.100.1 }
            HOST esp_vpn_gw2 { IP 198.51.100.2 }
            FLOW ipsec_esp_flow(vpn_left, vpn_right) {
                vpn_left -> vpn_right ESP SPI 0x1000 SEQ 1 PAYLOAD "ciphertext"
            } COMPILE { ipsec_esp_flow(esp_vpn_gw1, esp_vpn_gw2) }"#;
        run_e2e_test(esp_script, |esp_pkts| assert_eq!((esp_pkts.len(), esp_pkts[0].ethertype(), esp_pkts[0].raw[23]), (1, Some(0x0800), 50)));
    }

    /// Tests RFC 4302 IPsec AH authentication header (IP protocol 51).
    #[test]
    pub fn test_tier1_l3_ipsec_ah() {
        let ah_script = r#"
            HOST ah_sec_gw1 { IP 198.51.100.11 }
            HOST ah_sec_gw2 { IP 198.51.100.12 }
            FLOW ipsec_ah_flow(ah_left, ah_right) {
                ah_left -> ah_right AH SPI 0x2000 SEQ 1 PAYLOAD "ah_payload"
            } COMPILE { ipsec_ah_flow(ah_sec_gw1, ah_sec_gw2) }"#;
        run_e2e_test(ah_script, |ah_pkts| assert_eq!((ah_pkts.len(), ah_pkts[0].ethertype(), ah_pkts[0].raw[23]), (1, Some(0x0800), 51)));
    }

    /// Tests RFC 7296 IKEv2 internet key exchange `SA_INIT` negotiation on UDP port 500.
    #[test]
    pub fn test_tier1_l3_ikev2() {
        let ike_script = r#"
            HOST ike_initiator { IP 198.51.100.21 }
            HOST ike_responder { IP 198.51.100.22 }
            FLOW ikev2_init_flow(init_gw, resp_gw) {
                init_gw -> resp_gw IKEV2 EXCHANGE SA_INIT MSGID 0
            } COMPILE { ikev2_init_flow(ike_initiator, ike_responder) }"#;
        run_e2e_test(ike_script, |ike_pkts| assert_eq!((ike_pkts.len(), u16::from_be_bytes([ike_pkts[0].raw[36], ike_pkts[0].raw[37]])), (1, 500)));
    }

    /// Tests WireGuard cryptographic tunnel handshake initiation on UDP port 51820.
    #[test]
    pub fn test_tier1_l3_wireguard() {
        let wg_script = r#"
            HOST wg_peer_alpha { IP 10.30.0.1 }
            HOST wg_peer_beta { IP 10.30.0.2 }
            FLOW wg_handshake_flow(peer_a, peer_b) {
                peer_a -> peer_b WIREGUARD TYPE INITIATION SENDER 0x11223344
            } COMPILE { wg_handshake_flow(wg_peer_alpha, wg_peer_beta) }"#;
        run_e2e_test(wg_script, |wg_pkts| assert_eq!((wg_pkts.len(), u16::from_be_bytes([wg_pkts[0].raw[36], wg_pkts[0].raw[37]])), (1, 51820)));
    }

    /// Tests RFC 2328 OSPFv2 routing protocol `HELLO` packet (IP protocol 89).
    #[test]
    pub fn test_tier1_l3_ospf() {
        let ospf_script = r#"
            HOST ospf_rtr_1 { IP 10.40.0.1 }
            HOST ospf_rtr_2 { IP 10.40.0.2 }
            FLOW ospf_hello_flow(dr_rtr, bdr_rtr) {
                dr_rtr -> bdr_rtr OSPF HELLO ROUTER_ID 10.40.0.1 AREA_ID 0
            } COMPILE { ospf_hello_flow(ospf_rtr_1, ospf_rtr_2) }"#;
        run_e2e_test(ospf_script, |ospf_pkts| assert_eq!((ospf_pkts.len(), ospf_pkts[0].ethertype(), ospf_pkts[0].raw[23]), (1, Some(0x0800), 89)));
    }

    /// Tests RFC 4271 BGP-4 `OPEN` and `KEEPALIVE` messages on TCP port 179.
    #[test]
    pub fn test_tier1_l3_bgp() {
        let bgp_script = r#"
            HOST bgp_ebgp_1 { IP 192.0.2.1 }
            HOST bgp_ebgp_2 { IP 192.0.2.2 }
            FLOW bgp_open_flow(as65001, as65002) {
                as65001 -> as65002 BGP OPEN ASN 65001 HOLDTIME 180 BGPID 192.0.2.1
                as65001 <- as65002 BGP KEEPALIVE
            } COMPILE { bgp_open_flow(bgp_ebgp_1, bgp_ebgp_2) }"#;
        run_e2e_test(bgp_script, |bgp_pkts| assert_eq!((bgp_pkts.len(), u16::from_be_bytes([bgp_pkts[0].raw[36], bgp_pkts[0].raw[37]])), (2, 179)));
    }

    /// Tests RFC 2453 RIPv2 routing table response advertisement on UDP port 520.
    #[test]
    pub fn test_tier1_l3_rip() {
        let rip_script = r#"
            HOST rip_sender { IP 192.168.13.1 }
            HOST rip_mcast { IP 224.0.0.9 }
            FLOW rip_update_flow(rip_rtr, rip_grp) {
                rip_rtr -> rip_grp RIP RESPONSE PREFIX 10.0.0.0 METRIC 1
            } COMPILE { rip_update_flow(rip_sender, rip_mcast) }"#;
        run_e2e_test(rip_script, |rip_pkts| assert_eq!((rip_pkts.len(), u16::from_be_bytes([rip_pkts[0].raw[36], rip_pkts[0].raw[37]])), (1, 520)));
    }

    /// Tests RFC 5798 VRRPv3 virtual router redundancy advertisement (IP protocol 112).
    #[test]
    pub fn test_tier1_l3_vrrp() {
        let vrrp_script = r#"
            HOST vrrp_master { IP 192.168.14.254 }
            HOST vrrp_mcast { IP 224.0.0.18 }
            FLOW vrrp_advert_flow(master_rtr, vrrp_group) {
                master_rtr -> vrrp_group VRRP VRID 1 PRIORITY 100 VIP 192.168.14.1
            } COMPILE { vrrp_advert_flow(vrrp_master, vrrp_mcast) }"#;
        run_e2e_test(vrrp_script, |vrrp_pkts| assert_eq!((vrrp_pkts.len(), vrrp_pkts[0].ethertype(), vrrp_pkts[0].raw[23]), (1, Some(0x0800), 112)));
    }

    /// Tests RFC 2281 Cisco HSRP hot standby router protocol hello on UDP port 1985.
    #[test]
    pub fn test_tier1_l3_hsrp() {
        let hsrp_script = r#"
            HOST hsrp_active { IP 192.168.15.253 }
            HOST hsrp_all_rtrs { IP 224.0.0.2 }
            FLOW hsrp_hello_flow(active_gw, all_routers) {
                active_gw -> all_routers HSRP GROUP 1 PRIORITY 110 STATE 16 VIP 192.168.15.1
            } COMPILE { hsrp_hello_flow(hsrp_active, hsrp_all_rtrs) }"#;
        run_e2e_test(hsrp_script, |hsrp_pkts| assert_eq!((hsrp_pkts.len(), u16::from_be_bytes([hsrp_pkts[0].raw[36], hsrp_pkts[0].raw[37]])), (1, 1985)));
    }

    /// Tests RFC 7761 PIM-SM protocol independent multicast hello (IP protocol 103).
    #[test]
    pub fn test_tier1_l3_pim() {
        let pim_script = r#"
            HOST pim_dr { IP 192.168.16.1 }
            HOST pim_routers { IP 224.0.0.13 }
            FLOW pim_neighbor_flow(dr_node, pim_mcast) {
                dr_node -> pim_mcast PIM HELLO
            } COMPILE { pim_neighbor_flow(pim_dr, pim_routers) }"#;
        run_e2e_test(pim_script, |pim_pkts| assert_eq!((pim_pkts.len(), pim_pkts[0].ethertype(), pim_pkts[0].raw[23]), (1, Some(0x0800), 103)));
    }

    /// Tests RFC 5880 BFD bidirectional forwarding detection control packet on UDP port 3784.
    #[test]
    pub fn test_tier1_l3_bfd() {
        let bfd_script = r#"
            HOST bfd_peer_1 { IP 10.50.0.1 }
            HOST bfd_peer_2 { IP 10.50.0.2 }
            FLOW bfd_control_flow(bfd_a, bfd_b) {
                bfd_a -> bfd_b BFD STATE 3 MY_DISC 100 YOUR_DISC 200
            } COMPILE { bfd_control_flow(bfd_peer_1, bfd_peer_2) }"#;
        run_e2e_test(bfd_script, |bfd_pkts| assert_eq!((bfd_pkts.len(), u16::from_be_bytes([bfd_pkts[0].raw[36], bfd_pkts[0].raw[37]])), (1, 3784)));
    }

    /// Tests OpenFlow 1.3 SDN switch control channel `HELLO` message on TCP port 6653.
    #[test]
    pub fn test_tier1_l3_openflow() {
        let of_script = r#"
            HOST sdn_controller { IP 10.60.0.1 }
            HOST ovs_datapath { IP 10.60.0.2 }
            FLOW openflow_hello_flow(ctrl, sw_dp) {
                ctrl -> sw_dp OPENFLOW TYPE HELLO XID 1
            } COMPILE { openflow_hello_flow(sdn_controller, ovs_datapath) }"#;
        run_e2e_test(of_script, |of_pkts| assert_eq!((of_pkts.len(), u16::from_be_bytes([of_pkts[0].raw[36], of_pkts[0].raw[37]])), (1, 6653)));
    }

    /// Tests RFC 9293 TCP 3-way handshake (`SYN`, `SYN ACK`, `ACK`).
    #[test]
    pub fn test_tier1_l4_tcp() {
        let tcp_script = r#"
            HOST tcp_cli { IP 10.70.0.1 }
            HOST tcp_srv { IP 10.70.0.2 }
            FLOW tcp_3whs_flow(cli_ep, srv_ep) {
                cli_ep -> srv_ep TCP SYN SRCPORT 49152 DSTPORT 80
                cli_ep <- srv_ep TCP SYN ACK
                cli_ep -> srv_ep TCP ACK
            } COMPILE { tcp_3whs_flow(tcp_cli, tcp_srv) }"#;
        run_e2e_test(tcp_script, |tcp_pkts| assert_eq!((tcp_pkts.len(), tcp_pkts[0].ethertype(), tcp_pkts[0].raw[23]), (3, Some(0x0800), 6)));
    }

    /// Tests RFC 768 UDP stateless datagram transport with explicit ports and payload.
    #[test]
    pub fn test_tier1_l4_udp() {
        let udp_script = r#"
            HOST udp_sender { IP 10.71.0.1 }
            HOST udp_receiver { IP 10.71.0.2 }
            FLOW udp_datagram_flow(u_src, u_dst) {
                u_src -> u_dst UDP SRCPORT 5000 DSTPORT 9000 PAYLOAD "hello_udp"
            } COMPILE { udp_datagram_flow(udp_sender, udp_receiver) }"#;
        run_e2e_test(udp_script, |udp_pkts| assert_eq!((udp_pkts.len(), udp_pkts[0].ethertype(), udp_pkts[0].raw[23]), (1, Some(0x0800), 17)));
    }

    /// Tests RFC 9260 SCTP transport `INIT` chunk with CRC32c checksum (IP protocol 132).
    #[test]
    pub fn test_tier1_l4_sctp() {
        let sctp_script = r#"
            HOST sctp_ep_a { IP 10.72.0.1 }
            HOST sctp_ep_b { IP 10.72.0.2 }
            FLOW sctp_init_flow(ep_1, ep_2) {
                ep_1 -> ep_2 SCTP CHUNK INIT VTAG 0 SRCPORT 2905 DSTPORT 2905
            } COMPILE { sctp_init_flow(sctp_ep_a, sctp_ep_b) }"#;
        run_e2e_test(sctp_script, |sctp_pkts| assert_eq!((sctp_pkts.len(), sctp_pkts[0].ethertype(), sctp_pkts[0].raw[23]), (1, Some(0x0800), 132)));
    }

    /// Tests dual-transport protocols (`DNS`, `SIP`, `SYSLOG`) switching from UDP to `TRANSPORT TCP`.
    #[test]
    pub fn test_tier1_dual_transport_tcp() {
        let dual_tcp_script = r#"
            HOST dual_cli { IP 10.73.0.1 }
            HOST dual_srv { IP 10.73.0.2 }
            FLOW dual_transport_flow(dt_c, dt_s) {
                dt_c -> dt_s DNS TRANSPORT TCP QUERY TXID 0x4321 QNAME "zone.transfer.org" QTYPE AXFR
                dt_c -> dt_s SIP TRANSPORT TCP REGISTER FROM "sip:bob@pbx"
                dt_c -> dt_s SYSLOG TRANSPORT TCP MSG "Audit log over TCP"
            } COMPILE { dual_transport_flow(dual_cli, dual_srv) }"#;
        run_e2e_test(dual_tcp_script, |dual_pkts| assert_eq!((dual_pkts.len(), dual_pkts[0].raw[23], dual_pkts[2].raw[23]), (3, 6, 6)));
    }
}

/// Tier 2: Boundary and corner cases (L2/L3 limits, escape sequences, 4-tuple TCP state).
pub mod tier2_boundary_and_corner_cases {
    use super::*;

    /// Tests boundary VLAN IDs (`1` and `4094`), `PCP` (`0..=7`), and `DEI` (`0..=1`).
    #[test]
    pub fn test_tier2_l2_vlan_pcp_dei_boundaries() {
        let vlan_bounds_script = r#"
            HOST vb_h1 { IP 10.80.1.1 }
            HOST vb_h2 { IP 10.80.1.2 }
            FLOW vlan_bounds_flow(v_src, v_dst) {
                v_src -> v_dst VLAN 1 PCP 0 DEI 0 UDP PAYLOAD "vlan_min"
                v_src -> v_dst VLAN 4094 PCP 7 DEI 1 UDP PAYLOAD "vlan_max"
            } COMPILE { vlan_bounds_flow(vb_h1, vb_h2) }"#;
        run_e2e_test(vlan_bounds_script, |vb_pkts| assert_eq!((vb_pkts.len(), vb_pkts[0].ethertype(), vb_pkts[1].ethertype()), (2, Some(0x8100), Some(0x8100))));
    }

    /// Tests boundary `TTL` values (`0`, `1`, and `255`).
    #[test]
    pub fn test_tier2_l3_ttl_boundaries() {
        let ttl_bounds_script = r#"
            HOST ttl_h1 { IP 10.80.2.1 }
            HOST ttl_h2 { IP 10.80.2.2 }
            FLOW ttl_bounds_flow(t_src, t_dst) {
                t_src -> t_dst TTL 0 UDP PAYLOAD "ttl0"
                t_src -> t_dst TTL 1 UDP PAYLOAD "ttl1"
                t_src -> t_dst TTL 255 UDP PAYLOAD "ttl255"
            } COMPILE { ttl_bounds_flow(ttl_h1, ttl_h2) }"#;
        run_e2e_test(ttl_bounds_script, |ttl_pkts| assert_eq!((ttl_pkts.len(), ttl_pkts[0].raw[22], ttl_pkts[2].raw[22]), (3, 0, 255)));
    }

    /// Tests boundary `DSCP` (`0` and `63`) and `ECN` (`0..=3`) header encoding.
    #[test]
    pub fn test_tier2_l3_dscp_and_ecn_boundaries() {
        let qos_bounds_script = r#"
            HOST qos_h1 { IP 10.80.3.1 }
            HOST qos_h2 { IP 10.80.3.2 }
            FLOW qos_bounds_flow(q_src, q_dst) {
                q_src -> q_dst DSCP 0 ECN 0 UDP PAYLOAD "dscp_min"
                q_src -> q_dst DSCP 63 ECN 3 UDP PAYLOAD "dscp_max"
            } COMPILE { qos_bounds_flow(qos_h1, qos_h2) }"#;
        run_e2e_test(qos_bounds_script, |qos_pkts| assert_eq!((qos_pkts.len(), qos_pkts[0].raw[15], qos_pkts[1].raw[15]), (2, 0x00, 0xFF)));
    }

    /// Tests boundary 20-bit IPv6 `FLOWLABEL` values (`0` and `1048575` / `0xFFFFF`).
    #[test]
    pub fn test_tier2_l3_flowlabel_boundaries() {
        let fl_bounds_script = r#"
            HOST fl_v6_a { IP 2001:db8:80::1 }
            HOST fl_v6_b { IP 2001:db8:80::2 }
            FLOW flowlabel_bounds(fl_src, fl_dst) {
                fl_src -> fl_dst FLOWLABEL 0 UDP PAYLOAD "flowlabel_0"
                fl_src -> fl_dst FLOWLABEL 1048575 UDP PAYLOAD "flowlabel_max"
            } COMPILE { flowlabel_bounds(fl_v6_a, fl_v6_b) }"#;
        run_e2e_test(fl_bounds_script, |fl_pkts| assert_eq!((fl_pkts.len(), fl_pkts[0].ethertype()), (2, Some(0x86DD))));
    }

    /// Tests `FLOWLABEL` on IPv4 hosts being silently ignored per dual-stack polymorphism rules.
    #[test]
    pub fn test_tier2_l3_flowlabel_ipv4_silently_ignored() {
        let fl_v4_script = r#"
            HOST fl_v4_a { IP 10.80.4.1 }
            HOST fl_v4_b { IP 10.80.4.2 }
            FLOW flowlabel_ipv4_ignore(v4_s, v4_d) {
                v4_s -> v4_d FLOWLABEL 99999 UDP PAYLOAD "v4_flowlabel"
            } COMPILE { flowlabel_ipv4_ignore(fl_v4_a, fl_v4_b) }"#;
        run_e2e_test(fl_v4_script, |fl_v4_pkts| assert_eq!((fl_v4_pkts.len(), fl_v4_pkts[0].ethertype()), (1, Some(0x0800))));
    }

    /// Tests string escape sequences (`\r`, `\n`, `\t`, `\"`) and raw `HEXPAYLOAD` encoding.
    #[test]
    pub fn test_tier2_payload_escape_sequences_and_hex() {
        let esc_script = r#"
            HOST esc_h1 { IP 10.80.5.1 }
            HOST esc_h2 { IP 10.80.5.2 }
            FLOW escape_and_hex_flow(e_src, e_dst) {
                e_src -> e_dst UDP PAYLOAD "line1\r\nline2\t\"quoted\""
                e_src -> e_dst UDP HEXPAYLOAD "deadbeefcafebabe01020304"
            } COMPILE { escape_and_hex_flow(esc_h1, esc_h2) }"#;
        run_e2e_test(esc_script, |esc_pkts| assert_eq!((esc_pkts.len(), &esc_pkts[1].raw[42..46]), (2, &[0xde, 0xad, 0xbe, 0xef][..])));
    }

    /// Tests contextual sub-keywords used freely as `HOST`, `FLOW`, and parameter identifiers.
    #[test]
    pub fn test_tier2_contextual_keywords_as_identifiers() {
        let ctx_ident_script = r#"
            HOST dns { IP 10.80.6.1 }
            HOST tcp { IP 10.80.6.2 }
            FLOW query(ms, s) {
                ms -> s UDP PAYLOAD "contextual_idents"
            } COMPILE { query(dns, tcp) }"#;
        run_e2e_test(ctx_ident_script, |ctx_pkts| assert_eq!((ctx_pkts.len(), ctx_pkts[0].ethertype()), (1, Some(0x0800))));
    }

    /// Tests two-stage TCP port inheritance across reversed arrows (`->` and `<-`) when omitted.
    #[test]
    pub fn test_tier2_two_stage_tcp_port_inheritance() {
        let port_inh_script = r#"
            HOST pi_cli { IP 10.80.7.1 }
            HOST pi_srv { IP 10.80.7.2 }
            FLOW port_inherit_flow(p_c, p_s) {
                p_c -> p_s TCP SYN SRCPORT 54321 DSTPORT 8080
                p_c <- p_s TCP SYN ACK
                p_c -> p_s TCP ACK
            } COMPILE { port_inherit_flow(pi_cli, pi_srv) }"#;
        run_e2e_test(port_inh_script, |pi_pkts| assert_eq!((pi_pkts.len(), u16::from_be_bytes([pi_pkts[1].raw[34], pi_pkts[1].raw[35]])), (3, 8080)));
    }

    /// Tests loopback 4-tuple TCP connection tracking (`127.0.0.1 -> 127.0.0.1`).
    #[test]
    pub fn test_tier2_loopback_4tuple_tcp_tracking() {
        let loop_script = r#"
            HOST loop_v4 { IP 127.0.0.1 }
            FLOW loopback_tcp_flow(lo_a, lo_b) {
                lo_a -> lo_b TCP SYN SRCPORT 10001 DSTPORT 10002
                lo_a <- lo_b TCP SYN ACK
                lo_a -> lo_b TCP ACK
            } COMPILE { loopback_tcp_flow(loop_v4, loop_v4) }"#;
        run_e2e_test(loop_script, |lo_pkts| assert_eq!((lo_pkts.len(), u16::from_be_bytes([lo_pkts[1].raw[34], lo_pkts[1].raw[35]])), (3, 10002)));
    }

    /// Tests concurrent multi-port TCP connections between the same host pair.
    #[test]
    pub fn test_tier2_concurrent_multi_port_connections() {
        let multi_conn_script = r#"
            HOST mp_cli { IP 10.80.8.1 }
            HOST mp_srv { IP 10.80.8.2 }
            FLOW conn_a(ca, sa) { ca -> sa TCP SYN SRCPORT 40001 DSTPORT 80 }
            FLOW conn_b(cb, sb) { cb -> sb TCP SYN SRCPORT 40002 DSTPORT 443 }
            COMPILE {
                conn_a(mp_cli, mp_srv)
                conn_b(mp_cli, mp_srv)
            }"#;
        run_e2e_test(multi_conn_script, |mp_pkts| assert_eq!((mp_pkts.len(), u16::from_be_bytes([mp_pkts[0].raw[36], mp_pkts[0].raw[37]]), u16::from_be_bytes([mp_pkts[1].raw[36], mp_pkts[1].raw[37]])), (2, 80, 443)));
    }

    /// Tests strict `1 Statement = 1 Frame` invariant for TCP-based Layer 7 protocols.
    #[test]
    pub fn test_tier2_tcp_l7_strict_one_statement_one_frame() {
        let one_to_one_script = r#"
            HOST http_c { IP 10.80.9.1 }
            HOST http_s { IP 10.80.9.2 }
            FLOW strict_http_frames(hc, hs) {
                hc -> hs HTTP GET URI "/"
                hc <- hs HTTP STATUS 200
            } COMPILE { strict_http_frames(http_c, http_s) }"#;
        run_e2e_test(one_to_one_script, |http_pkts| assert_eq!(http_pkts.len(), 2, "2 statements must emit 2 frames"));
    }
}

/// Tier 3: Cross-feature combinations (dual-stack polymorphism, VLAN+L4, multicast MACs, timing).
pub mod tier3_cross_feature_combinations {
    use super::*;

    /// Tests dual-stack polymorphic `FLOW` invoked over both IPv4 and IPv6 host pairs.
    #[test]
    pub fn test_tier3_dual_stack_polymorphic_flow() {
        let poly_script = r#"
            HOST client_v4 { IP 192.168.90.1 }
            HOST server_v4 { IP 192.168.90.2 }
            HOST client_v6 { IP 2001:db8:90::1 }
            HOST server_v6 { IP 2001:db8:90::2 }
            FLOW dual_ping_flow(ep_c, ep_s) {
                ep_c -> ep_s ICMP ECHO_REQUEST
                ep_c <- ep_s ICMP ECHO_REPLY
            } COMPILE {
                dual_ping_flow(client_v4, server_v4)
                dual_ping_flow(client_v6, server_v6)
            }"#;
        run_e2e_test(poly_script, |poly_pkts| assert_eq!((poly_pkts.len(), poly_pkts[0].ethertype(), poly_pkts[2].ethertype()), (4, Some(0x0800), Some(0x86DD))));
    }

    /// Tests single `VLAN` and double `QINQ` tagging stacked with `TCP` and `UDP` transports.
    #[test]
    pub fn test_tier3_vlan_stacked_with_transports() {
        let stacked_script = r#"
            HOST st_cli { IP 10.90.1.1 }
            HOST st_srv { IP 10.90.1.2 }
            FLOW stacked_vlan_l4(sc, ss) {
                sc -> ss VLAN 100 TCP SYN SRCPORT 12345 DSTPORT 80
                sc -> ss QINQ 200 INNER_VLAN 10 UDP SRCPORT 53 DSTPORT 53 PAYLOAD "dns"
            } COMPILE { stacked_vlan_l4(st_cli, st_srv) }"#;
        run_e2e_test(stacked_script, |st_pkts| assert_eq!((st_pkts.len(), st_pkts[0].ethertype(), st_pkts[1].ethertype()), (2, Some(0x8100), Some(0x88A8))));
    }

    /// Tests multicast MAC auto-derivation: RFC 1112 (`01:00:5e:..`) and RFC 2464 (`33:33:..`).
    #[test]
    pub fn test_tier3_multicast_mac_auto_derivation() {
        let mcast_auto_script = r#"
            HOST uni_v4 { IP 192.168.91.1 }
            HOST grp_v4 { IP 224.0.0.1 }
            HOST uni_v6 { IP fe80::91 }
            HOST grp_v6 { IP ff02::1 }
            FLOW mcast_derive_flow(src4, dst4, src6, dst6) {
                src4 -> dst4 UDP PAYLOAD "mcast_v4"
                src6 -> dst6 UDP PAYLOAD "mcast_v6"
            } COMPILE { mcast_derive_flow(uni_v4, grp_v4, uni_v6, grp_v6) }"#;
        run_e2e_test(mcast_auto_script, |mc_pkts| assert_eq!((mc_pkts.len(), mc_pkts[0].dst_mac(), mc_pkts[1].dst_mac()), (2, Some([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]), Some([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]))));
    }

    /// Tests explicit `MAC` overrides taking precedence over multicast MAC auto-derivation.
    #[test]
    pub fn test_tier3_multicast_mac_explicit_override() {
        let mcast_ovr_script = r#"
            HOST ovr_src { IP 192.168.92.1 }
            HOST ovr_mcast { IP 224.0.0.1 MAC 00:AA:BB:CC:DD:EE }
            FLOW mcast_override_flow(os, om) {
                os -> om UDP PAYLOAD "override_mac"
            } COMPILE { mcast_override_flow(ovr_src, ovr_mcast) }"#;
        run_e2e_test(mcast_ovr_script, |ovr_pkts| assert_eq!((ovr_pkts.len(), ovr_pkts[0].dst_mac()), (1, Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]))));
    }

    /// Tests RFC 7323 TCP options matrix (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`).
    #[test]
    pub fn test_tier3_tcp_options_matrix() {
        let tcp_opt_script = r#"
            HOST opt_cli { IP 10.90.2.1 }
            HOST opt_srv { IP 10.90.2.2 }
            FLOW tcp_opts_flow(oc, os) {
                oc -> os TCP SYN SRCPORT 12345 DSTPORT 80 MSS 1460 WSCALE 7 SACK_PERM TSVAL 100 TSECR 0
            } COMPILE { tcp_opts_flow(opt_cli, opt_srv) }"#;
        run_e2e_test(tcp_opt_script, |opt_pkts| assert!(opt_pkts[0].raw.len() > 54, "TCP options must extend header beyond 20B"));
    }

    /// Tests `WAIT` timing modifiers across all supported duration units (`ns`, `us`, `ms`, `s`, `m`).
    #[test]
    pub fn test_tier3_timing_wait_units() {
        let wait_script = r#"
            HOST tm_h1 { IP 10.90.3.1 }
            HOST tm_h2 { IP 10.90.3.2 }
            FLOW wait_units_flow(ts, td) {
                ts -> td UDP PAYLOAD "p1" WAIT 500ns
                ts -> td UDP PAYLOAD "p2" WAIT 10us
                ts -> td UDP PAYLOAD "p3" WAIT 5ms
                ts -> td UDP PAYLOAD "p4" WAIT 1s
                ts -> td UDP PAYLOAD "p5" WAIT 1m
            } COMPILE { wait_units_flow(tm_h1, tm_h2) }"#;
        run_e2e_test(wait_script, |wait_pkts| assert_eq!(wait_pkts.len(), 5));
    }

    /// Tests stress execution of bidirectional statements inside a `LOOP 10` block.
    #[test]
    pub fn test_tier3_loop_block_multi_protocol_stress() {
        let loop_stress_script = r#"
            HOST lp_c { IP 10.90.4.1 }
            HOST lp_s { IP 10.90.4.2 }
            FLOW ping_pong_loop(l_cli, l_srv) {
                l_cli -> l_srv UDP PAYLOAD "ping"
                l_cli <- l_srv UDP PAYLOAD "pong"
            } COMPILE { LOOP 10 { ping_pong_loop(lp_c, lp_s) } }"#;
        run_e2e_test(loop_stress_script, |lp_pkts| assert_eq!(lp_pkts.len(), 20));
    }
}

/// CLI output path handling and `.fasm` corpus backwards compatibility verification.
pub mod cli_and_backwards_compatibility {
    use super::*;

    /// Tests that compiling a `.fasm` program to a default PCAPNG path succeeds cleanly.
    #[test]
    pub fn test_cli_output_flag_default() {
        let temp_dir = std::env::temp_dir();
        let input_path = temp_dir.join(format!("cli_in_default_{}.fasm", std::process::id()));
        let default_script = r#"
            HOST def_a { IP 10.99.0.1 }
            HOST def_b { IP 10.99.0.2 }
            FLOW def_f(dx, dy) { dx -> dy UDP PAYLOAD "cli_test" }
            COMPILE { def_f(def_a, def_b) }"#;
        fs::write(&input_path, default_script).expect("write fasm input");

        let prog = frameassembly::parser::parse_program(default_script).expect("parsed default");
        let default_out = temp_dir.join(format!("cli_default_out_{}.pcap", std::process::id()));
        let gen_res = frameassembly::backend::generate_pcap(&prog, default_out.to_str().unwrap());
        assert!(gen_res.is_ok() && default_out.exists());
        let _ = fs::remove_file(&input_path);
        let _ = fs::remove_file(&default_out);
    }

    /// Tests that specifying a custom output path produces a valid non-empty PCAPNG file.
    #[test]
    pub fn test_cli_output_flag_custom_path() {
        let temp_dir = std::env::temp_dir();
        let custom_out = temp_dir.join(format!("custom_{}.pcap", std::process::id()));
        let custom_script = r#"
            HOST cust_a { IP 10.99.1.1 }
            HOST cust_b { IP 10.99.1.2 }
            FLOW cust_f(cx, cy) { cx -> cy UDP PAYLOAD "custom_path" }
            COMPILE { cust_f(cust_a, cust_b) }"#;
        let prog = frameassembly::parser::parse_program(custom_script).expect("parsed custom");
        let gen_res = frameassembly::backend::generate_pcap(&prog, custom_out.to_str().unwrap());
        assert!(gen_res.is_ok() && fs::metadata(&custom_out).unwrap().len() > 0);
        let _ = fs::remove_file(&custom_out);
    }

    /// Recursively traverses an `examples/` directory tree and compiles a sample of `.fasm` files.
    fn visit_examples_dir(dir: &Path, count: &mut usize, temp_dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_examples_dir(&path, count, temp_dir);
                } else if path.extension().and_then(|s| s.to_str()) == Some("fasm") {
                    *count += 1;
                    let filename = path.file_name().unwrap().to_str().unwrap();
                    let content = fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("Failed to read {}: {}", filename, e));
                    let prog = frameassembly::parser::parse_program(&content)
                        .unwrap_or_else(|e| panic!("Parse error in {}: {:?}", filename, e));
                    let out_pcap = temp_dir.join(format!("legacy_verify_{}_{}.pcap", std::process::id(), *count));
                    let res = frameassembly::backend::generate_pcap(&prog, out_pcap.to_str().unwrap());
                    assert!(res.is_ok(), "Compile error in {}: {:?}", filename, res.err());
                    assert!(out_pcap.exists() && fs::metadata(&out_pcap).unwrap().len() > 0);
                    let _ = fs::remove_file(&out_pcap);
                }
            }
        }
    }

    /// Tests backwards compatibility: verified `.fasm` examples across layer directories compile.
    #[test]
    pub fn test_legacy_examples_01_to_105_backwards_compatibility() {
        let mut compiled_total = 0;
        let scratch_dir = std::env::temp_dir();
        visit_examples_dir(Path::new("examples"), &mut compiled_total, &scratch_dir);
        assert!(compiled_total >= 105, "All corpus examples must compile cleanly, found {}", compiled_total);
    }
}
