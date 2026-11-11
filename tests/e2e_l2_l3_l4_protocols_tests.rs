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
//!   multicast MAC derivation, RFC 7323 TCP options, `wait` timing units, and repeated flow calls).
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
            host arp_host_a { ip 192.168.10.1 mac 00:11:22:33:44:01 }
            host arp_host_b { ip 192.168.10.2 mac 00:11:22:33:44:02 }
            flow arp_resolution(requester, responder) {
                requester -> responder arp
                requester <- responder arp reply
            } compile { arp_resolution(arp_host_a, arp_host_b) }"#;
        run_e2e_test(arp_script, |arp_pkts| assert_eq!((arp_pkts.len(), arp_pkts[0].ethertype(), arp_pkts[1].ethertype()), (2, Some(0x0806), Some(0x0806))));
    }

    /// Tests IEEE 802.1Q VLAN framing (`0x8100`) and tag control fields.
    #[test]
    pub fn test_tier1_l2_vlan() {
        let vlan_script = r#"
            host vlan_node_1 { ip 10.10.1.1 }
            host vlan_node_2 { ip 10.10.1.2 }
            flow vlan_tagged_flow(access_sw, trunk_sw) {
                access_sw -> trunk_sw vlan 100 udp payload "vlan100"
            } compile { vlan_tagged_flow(vlan_node_1, vlan_node_2) }"#;
        run_e2e_test(vlan_script, |vlan_pkts| assert_eq!((vlan_pkts.len(), vlan_pkts[0].ethertype()), (1, Some(0x8100))));
    }

    /// Tests IEEE 802.1ad QinQ (`0x88A8`) provider bridge double VLAN tagging.
    #[test]
    pub fn test_tier1_l2_qinq() {
        let qinq_script = r#"
            host metro_pe_1 { ip 10.10.2.1 }
            host metro_pe_2 { ip 10.10.2.2 }
            flow qinq_tunnel_flow(pe_ingress, pe_egress) {
                pe_ingress -> pe_egress qinq 200 innervlan 10 udp payload "qinq"
            } compile { qinq_tunnel_flow(metro_pe_1, metro_pe_2) }"#;
        run_e2e_test(qinq_script, |qinq_pkts| assert_eq!((qinq_pkts.len(), qinq_pkts[0].ethertype()), (1, Some(0x88A8))));
    }

    /// Tests IEEE 802.1AB LLDP (`0x88CC`) link layer discovery protocol framing.
    #[test]
    pub fn test_tier1_l2_lldp() {
        let lldp_script = r#"
            host leaf_sw_1 { ip 10.10.3.1 }
            host spine_sw_2 { ip 10.10.3.2 }
            flow lldp_announce(leaf_node, spine_node) {
                leaf_node -> spine_node lldp sysname "switch-leaf1"
            } compile { lldp_announce(leaf_sw_1, spine_sw_2) }"#;
        run_e2e_test(lldp_script, |lldp_pkts| assert_eq!((lldp_pkts.len(), lldp_pkts[0].ethertype()), (1, Some(0x88CC))));
    }

    /// Tests IEEE 802.1D STP spanning tree bridge protocol data unit multicast MAC.
    #[test]
    pub fn test_tier1_l2_stp() {
        let stp_script = r#"
            host root_bridge { ip 10.10.4.1 }
            host desig_bridge { ip 10.10.4.2 }
            flow stp_bpdu_flow(root_br, desig_br) {
                root_br -> desig_br stp
            } compile { stp_bpdu_flow(root_bridge, desig_bridge) }"#;
        run_e2e_test(stp_script, |stp_pkts| assert_eq!((stp_pkts.len(), stp_pkts[0].dst_mac()), (1, Some([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]))));
    }

    /// Tests IEEE 802.3ad LACP link aggregation control protocol slow-protocols MAC.
    #[test]
    pub fn test_tier1_l2_lacp() {
        let lacp_script = r#"
            host lag_actor { ip 10.10.5.1 }
            host lag_partner { ip 10.10.5.2 }
            flow lacp_pdu_flow(actor_port, partner_port) {
                actor_port -> partner_port lacp
            } compile { lacp_pdu_flow(lag_actor, lag_partner) }"#;
        run_e2e_test(lacp_script, |lacp_pkts| assert_eq!((lacp_pkts.len(), lacp_pkts[0].dst_mac()), (1, Some([0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]))));
    }

    /// Tests IEEE 802.1X EAPOL (`0x888E`) port access authentication start frame.
    #[test]
    pub fn test_tier1_l2_eapol() {
        let eapol_script = r#"
            host supplicant_pc { ip 10.10.6.1 }
            host auth_switch { ip 10.10.6.2 }
            flow eapol_start_flow(supp, auth_sw) {
                supp -> auth_sw eapol type start
            } compile { eapol_start_flow(supplicant_pc, auth_switch) }"#;
        run_e2e_test(eapol_script, |eapol_pkts| assert_eq!((eapol_pkts.len(), eapol_pkts[0].ethertype()), (1, Some(0x888E))));
    }

    /// Tests RFC 3032 MPLS (`0x8847`) unicast label stack encoding.
    #[test]
    pub fn test_tier1_l2_mpls() {
        let mpls_script = r#"
            host lsr_ingress { ip 10.10.7.1 }
            host lsr_egress { ip 10.10.7.2 }
            flow mpls_lsp_flow(ler_in, ler_out) {
                ler_in -> ler_out mpls 10001 exp 3 bos 1 mplsttl 64 udp payload "mpls"
            } compile { mpls_lsp_flow(lsr_ingress, lsr_egress) }"#;
        run_e2e_test(mpls_script, |mpls_pkts| assert_eq!((mpls_pkts.len(), mpls_pkts[0].ethertype()), (1, Some(0x8847))));
    }

    /// Tests RFC 792 / RFC 4443 polymorphic ICMP echo request and reply.
    #[test]
    pub fn test_tier1_l3_icmp() {
        let icmp_script = r#"
            host ping_src_v4 { ip 192.168.11.1 }
            host ping_dst_v4 { ip 192.168.11.2 }
            flow icmp_echo_pair(pinger, responder) {
                pinger -> responder icmp echorequest
                pinger <- responder icmp echoreply
            } compile { icmp_echo_pair(ping_src_v4, ping_dst_v4) }"#;
        run_e2e_test(icmp_script, |icmp_pkts| assert_eq!((icmp_pkts.len(), icmp_pkts[0].ethertype(), icmp_pkts[0].raw[23]), (2, Some(0x0800), 1)));
    }

    /// Tests RFC 4861 IPv6 Neighbor Discovery Protocol (`NDP`) solicitation and advertisement.
    #[test]
    pub fn test_tier1_l3_ndp() {
        let ndp_script = r#"
            host ndp_host_a { ip 2001:db8:10::1 }
            host ndp_host_b { ip 2001:db8:10::2 }
            flow ndp_resolve_flow(solicit_node, target_node) {
                solicit_node -> target_node ndp neighborsolicit target 2001:db8:10::2
                solicit_node <- target_node ndp neighboradvert target 2001:db8:10::2
            } compile { ndp_resolve_flow(ndp_host_a, ndp_host_b) }"#;
        run_e2e_test(ndp_script, |ndp_pkts| assert_eq!((ndp_pkts.len(), ndp_pkts[0].ethertype(), ndp_pkts[0].raw[20]), (2, Some(0x86DD), 58)));
    }

    /// Tests RFC 2236 / RFC 3376 IGMP multicast group membership report.
    #[test]
    pub fn test_tier1_l3_igmp() {
        let igmp_script = r#"
            host igmp_member { ip 192.168.12.10 }
            host igmp_all_hosts { ip 224.0.0.1 }
            flow igmp_join_flow(host_member, mcast_grp) {
                host_member -> mcast_grp igmp report group 239.1.1.1
            } compile { igmp_join_flow(igmp_member, igmp_all_hosts) }"#;
        run_e2e_test(igmp_script, |igmp_pkts| assert_eq!((igmp_pkts.len(), igmp_pkts[0].ethertype(), igmp_pkts[0].raw[23]), (1, Some(0x0800), 2)));
    }

    /// Tests RFC 2710 / RFC 3810 MLD IPv6 Multicast Listener Discovery report.
    #[test]
    pub fn test_tier1_l3_mld() {
        let mld_script = r#"
            host mld_listener { ip fe80::10 }
            host mld_all_nodes { ip ff02::1 }
            flow mld_report_flow(listener_v6, mcast_v6) {
                listener_v6 -> mcast_v6 mld report multicastaddr ff02::1:2
            } compile { mld_report_flow(mld_listener, mld_all_nodes) }"#;
        run_e2e_test(mld_script, |mld_pkts| assert_eq!((mld_pkts.len(), mld_pkts[0].ethertype()), (1, Some(0x86DD))));
    }

    /// Tests RFC 2784 / RFC 2890 GRE tunnel encapsulation with key extension.
    #[test]
    pub fn test_tier1_l3_gre() {
        let gre_script = r#"
            host gre_tun_a { ip 10.20.1.1 }
            host gre_tun_b { ip 10.20.1.2 }
            flow gre_tunnel_flow(tun_src, tun_dst) {
                tun_src -> tun_dst gre grekey 1234 payload "inner_ip"
            } compile { gre_tunnel_flow(gre_tun_a, gre_tun_b) }"#;
        run_e2e_test(gre_script, |gre_pkts| assert_eq!((gre_pkts.len(), gre_pkts[0].ethertype(), gre_pkts[0].raw[23]), (1, Some(0x0800), 47)));
    }

    /// Tests RFC 7348 VXLAN overlay network encapsulation on UDP port 4789.
    #[test]
    pub fn test_tier1_l3_vxlan() {
        let vxlan_script = r#"
            host vxlan_vtep_1 { ip 192.168.10.1 }
            host vxlan_vtep_2 { ip 192.168.10.2 }
            flow vxlan_overlay_flow(vtep_a, vtep_b) {
                vtep_a -> vtep_b vxlan vni 5000 payload "inner_eth"
            } compile { vxlan_overlay_flow(vxlan_vtep_1, vxlan_vtep_2) }"#;
        run_e2e_test(vxlan_script, |vxlan_pkts| assert_eq!((vxlan_pkts.len(), u16::from_be_bytes([vxlan_pkts[0].raw[36], vxlan_pkts[0].raw[37]])), (1, 4789)));
    }

    /// Tests RFC 8926 GENEVE overlay network encapsulation on UDP port 6081.
    #[test]
    pub fn test_tier1_l3_geneve() {
        let geneve_script = r#"
            host geneve_nve_1 { ip 192.168.20.1 }
            host geneve_nve_2 { ip 192.168.20.2 }
            flow geneve_overlay_flow(nve_a, nve_b) {
                nve_a -> nve_b geneve vni 10000 payload "inner_payload"
            } compile { geneve_overlay_flow(geneve_nve_1, geneve_nve_2) }"#;
        run_e2e_test(geneve_script, |geneve_pkts| assert_eq!((geneve_pkts.len(), u16::from_be_bytes([geneve_pkts[0].raw[36], geneve_pkts[0].raw[37]])), (1, 6081)));
    }

    /// Tests RFC 4303 IPsec ESP encapsulating security payload (IP protocol 50).
    #[test]
    pub fn test_tier1_l3_ipsec_esp() {
        let esp_script = r#"
            host esp_vpn_gw1 { ip 198.51.100.1 }
            host esp_vpn_gw2 { ip 198.51.100.2 }
            flow ipsec_esp_flow(vpn_left, vpn_right) {
                vpn_left -> vpn_right esp spi 0x1000 seq 1 payload "ciphertext"
            } compile { ipsec_esp_flow(esp_vpn_gw1, esp_vpn_gw2) }"#;
        run_e2e_test(esp_script, |esp_pkts| assert_eq!((esp_pkts.len(), esp_pkts[0].ethertype(), esp_pkts[0].raw[23]), (1, Some(0x0800), 50)));
    }

    /// Tests RFC 4302 IPsec AH authentication header (IP protocol 51).
    #[test]
    pub fn test_tier1_l3_ipsec_ah() {
        let ah_script = r#"
            host ah_sec_gw1 { ip 198.51.100.11 }
            host ah_sec_gw2 { ip 198.51.100.12 }
            flow ipsec_ah_flow(ah_left, ah_right) {
                ah_left -> ah_right ah spi 0x2000 seq 1 payload "ah_payload"
            } compile { ipsec_ah_flow(ah_sec_gw1, ah_sec_gw2) }"#;
        run_e2e_test(ah_script, |ah_pkts| assert_eq!((ah_pkts.len(), ah_pkts[0].ethertype(), ah_pkts[0].raw[23]), (1, Some(0x0800), 51)));
    }

    /// Tests RFC 7296 IKEv2 internet key exchange `SA_INIT` negotiation on UDP port 500.
    #[test]
    pub fn test_tier1_l3_ikev2() {
        let ike_script = r#"
            host ike_initiator { ip 198.51.100.21 }
            host ike_responder { ip 198.51.100.22 }
            flow ikev2_init_flow(init_gw, resp_gw) {
                init_gw -> resp_gw ikev2 exchange sainit msgid 0
            } compile { ikev2_init_flow(ike_initiator, ike_responder) }"#;
        run_e2e_test(ike_script, |ike_pkts| assert_eq!((ike_pkts.len(), u16::from_be_bytes([ike_pkts[0].raw[36], ike_pkts[0].raw[37]])), (1, 500)));
    }

    /// Tests WireGuard cryptographic tunnel handshake initiation on UDP port 51820.
    #[test]
    pub fn test_tier1_l3_wireguard() {
        let wg_script = r#"
            host wg_peer_alpha { ip 10.30.0.1 }
            host wg_peer_beta { ip 10.30.0.2 }
            flow wg_handshake_flow(peer_a, peer_b) {
                peer_a -> peer_b wireguard type initiation sender 0x11223344
            } compile { wg_handshake_flow(wg_peer_alpha, wg_peer_beta) }"#;
        run_e2e_test(wg_script, |wg_pkts| assert_eq!((wg_pkts.len(), u16::from_be_bytes([wg_pkts[0].raw[36], wg_pkts[0].raw[37]])), (1, 51820)));
    }

    /// Tests RFC 2328 OSPFv2 routing protocol `HELLO` packet (IP protocol 89).
    #[test]
    pub fn test_tier1_l3_ospf() {
        let ospf_script = r#"
            host ospf_rtr_1 { ip 10.40.0.1 }
            host ospf_rtr_2 { ip 10.40.0.2 }
            flow ospf_hello_flow(dr_rtr, bdr_rtr) {
                dr_rtr -> bdr_rtr ospf hello routerid 10.40.0.1 areaid 0
            } compile { ospf_hello_flow(ospf_rtr_1, ospf_rtr_2) }"#;
        run_e2e_test(ospf_script, |ospf_pkts| assert_eq!((ospf_pkts.len(), ospf_pkts[0].ethertype(), ospf_pkts[0].raw[23]), (1, Some(0x0800), 89)));
    }

    /// Tests RFC 4271 BGP-4 `OPEN` and `KEEPALIVE` messages on TCP port 179.
    #[test]
    pub fn test_tier1_l3_bgp() {
        let bgp_script = r#"
            host bgp_ebgp_1 { ip 192.0.2.1 }
            host bgp_ebgp_2 { ip 192.0.2.2 }
            flow bgp_open_flow(as65001, as65002) {
                as65001 -> as65002 bgp open asn 65001 holdtime 180 bgpid 192.0.2.1
                as65001 <- as65002 bgp keepalive
            } compile { bgp_open_flow(bgp_ebgp_1, bgp_ebgp_2) }"#;
        run_e2e_test(bgp_script, |bgp_pkts| assert_eq!((bgp_pkts.len(), u16::from_be_bytes([bgp_pkts[0].raw[36], bgp_pkts[0].raw[37]])), (2, 179)));
    }

    /// Tests RFC 2453 RIPv2 routing table response advertisement on UDP port 520.
    #[test]
    pub fn test_tier1_l3_rip() {
        let rip_script = r#"
            host rip_sender { ip 192.168.13.1 }
            host rip_mcast { ip 224.0.0.9 }
            flow rip_update_flow(rip_rtr, rip_grp) {
                rip_rtr -> rip_grp rip response prefix 10.0.0.0 metric 1
            } compile { rip_update_flow(rip_sender, rip_mcast) }"#;
        run_e2e_test(rip_script, |rip_pkts| assert_eq!((rip_pkts.len(), u16::from_be_bytes([rip_pkts[0].raw[36], rip_pkts[0].raw[37]])), (1, 520)));
    }

    /// Tests RFC 5798 VRRPv3 virtual router redundancy advertisement (IP protocol 112).
    #[test]
    pub fn test_tier1_l3_vrrp() {
        let vrrp_script = r#"
            host vrrp_master { ip 192.168.14.254 }
            host vrrp_mcast { ip 224.0.0.18 }
            flow vrrp_advert_flow(master_rtr, vrrp_group) {
                master_rtr -> vrrp_group vrrp vrid 1 priority 100 vip 192.168.14.1
            } compile { vrrp_advert_flow(vrrp_master, vrrp_mcast) }"#;
        run_e2e_test(vrrp_script, |vrrp_pkts| assert_eq!((vrrp_pkts.len(), vrrp_pkts[0].ethertype(), vrrp_pkts[0].raw[23]), (1, Some(0x0800), 112)));
    }

    /// Tests RFC 2281 Cisco HSRP hot standby router protocol hello on UDP port 1985.
    #[test]
    pub fn test_tier1_l3_hsrp() {
        let hsrp_script = r#"
            host hsrp_active { ip 192.168.15.253 }
            host hsrp_all_rtrs { ip 224.0.0.2 }
            flow hsrp_hello_flow(active_gw, all_routers) {
                active_gw -> all_routers hsrp group 1 priority 110 state 16 vip 192.168.15.1
            } compile { hsrp_hello_flow(hsrp_active, hsrp_all_rtrs) }"#;
        run_e2e_test(hsrp_script, |hsrp_pkts| assert_eq!((hsrp_pkts.len(), u16::from_be_bytes([hsrp_pkts[0].raw[36], hsrp_pkts[0].raw[37]])), (1, 1985)));
    }

    /// Tests RFC 7761 PIM-SM protocol independent multicast hello (IP protocol 103).
    #[test]
    pub fn test_tier1_l3_pim() {
        let pim_script = r#"
            host pim_dr { ip 192.168.16.1 }
            host pim_routers { ip 224.0.0.13 }
            flow pim_neighbor_flow(dr_node, pim_mcast) {
                dr_node -> pim_mcast pim hello
            } compile { pim_neighbor_flow(pim_dr, pim_routers) }"#;
        run_e2e_test(pim_script, |pim_pkts| assert_eq!((pim_pkts.len(), pim_pkts[0].ethertype(), pim_pkts[0].raw[23]), (1, Some(0x0800), 103)));
    }

    /// Tests RFC 5880 BFD bidirectional forwarding detection control packet on UDP port 3784.
    #[test]
    pub fn test_tier1_l3_bfd() {
        let bfd_script = r#"
            host bfd_peer_1 { ip 10.50.0.1 }
            host bfd_peer_2 { ip 10.50.0.2 }
            flow bfd_control_flow(bfd_a, bfd_b) {
                bfd_a -> bfd_b bfd state 3 mydisc 100 yourdisc 200
            } compile { bfd_control_flow(bfd_peer_1, bfd_peer_2) }"#;
        run_e2e_test(bfd_script, |bfd_pkts| assert_eq!((bfd_pkts.len(), u16::from_be_bytes([bfd_pkts[0].raw[36], bfd_pkts[0].raw[37]])), (1, 3784)));
    }

    /// Tests OpenFlow 1.3 SDN switch control channel `HELLO` message on TCP port 6653.
    #[test]
    pub fn test_tier1_l3_openflow() {
        let of_script = r#"
            host sdn_controller { ip 10.60.0.1 }
            host ovs_datapath { ip 10.60.0.2 }
            flow openflow_hello_flow(ctrl, sw_dp) {
                ctrl -> sw_dp openflow type hello xid 1
            } compile { openflow_hello_flow(sdn_controller, ovs_datapath) }"#;
        run_e2e_test(of_script, |of_pkts| assert_eq!((of_pkts.len(), u16::from_be_bytes([of_pkts[0].raw[36], of_pkts[0].raw[37]])), (1, 6653)));
    }

    /// Tests RFC 9293 TCP 3-way handshake (`SYN`, `SYN ACK`, `ACK`).
    #[test]
    pub fn test_tier1_l4_tcp() {
        let tcp_script = r#"
            host tcp_cli { ip 10.70.0.1 }
            host tcp_srv { ip 10.70.0.2 }
            flow tcp_3whs_flow(cli_ep, srv_ep) {
                cli_ep -> srv_ep tcp syn srcport 49152 dstport 80
                cli_ep <- srv_ep tcp syn ack
                cli_ep -> srv_ep tcp ack
            } compile { tcp_3whs_flow(tcp_cli, tcp_srv) }"#;
        run_e2e_test(tcp_script, |tcp_pkts| assert_eq!((tcp_pkts.len(), tcp_pkts[0].ethertype(), tcp_pkts[0].raw[23]), (3, Some(0x0800), 6)));
    }

    /// Tests RFC 768 UDP stateless datagram transport with explicit ports and payload.
    #[test]
    pub fn test_tier1_l4_udp() {
        let udp_script = r#"
            host udp_sender { ip 10.71.0.1 }
            host udp_receiver { ip 10.71.0.2 }
            flow udp_datagram_flow(u_src, u_dst) {
                u_src -> u_dst udp srcport 5000 dstport 9000 payload "hello_udp"
            } compile { udp_datagram_flow(udp_sender, udp_receiver) }"#;
        run_e2e_test(udp_script, |udp_pkts| assert_eq!((udp_pkts.len(), udp_pkts[0].ethertype(), udp_pkts[0].raw[23]), (1, Some(0x0800), 17)));
    }

    /// Tests RFC 9260 SCTP transport `INIT` chunk with CRC32c checksum (IP protocol 132).
    #[test]
    pub fn test_tier1_l4_sctp() {
        let sctp_script = r#"
            host sctp_ep_a { ip 10.72.0.1 }
            host sctp_ep_b { ip 10.72.0.2 }
            flow sctp_init_flow(ep_1, ep_2) {
                ep_1 -> ep_2 sctp chunk init vtag 0 srcport 2905 dstport 2905
            } compile { sctp_init_flow(sctp_ep_a, sctp_ep_b) }"#;
        run_e2e_test(sctp_script, |sctp_pkts| assert_eq!((sctp_pkts.len(), sctp_pkts[0].ethertype(), sctp_pkts[0].raw[23]), (1, Some(0x0800), 132)));
    }

    /// Tests dual-transport protocols (`DNS`, `SIP`, `SYSLOG`) switching from UDP to `TRANSPORT TCP`.
    #[test]
    pub fn test_tier1_dual_transport_tcp() {
        let dual_tcp_script = r#"
            host dual_cli { ip 10.73.0.1 }
            host dual_srv { ip 10.73.0.2 }
            flow dual_transport_flow(dt_c, dt_s) {
                dt_c -> dt_s dns transport tcp query txid 0x4321 qname "zone.transfer.org" qtype axfr
                dt_c -> dt_s sip transport tcp register from "sip:bob@pbx"
                dt_c -> dt_s syslog transport tcp msg "Audit log over TCP"
            } compile { dual_transport_flow(dual_cli, dual_srv) }"#;
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
            host vb_h1 { ip 10.80.1.1 }
            host vb_h2 { ip 10.80.1.2 }
            flow vlan_bounds_flow(v_src, v_dst) {
                v_src -> v_dst vlan 1 pcp 0 dei 0 udp payload "vlan_min"
                v_src -> v_dst vlan 4094 pcp 7 dei 1 udp payload "vlan_max"
            } compile { vlan_bounds_flow(vb_h1, vb_h2) }"#;
        run_e2e_test(vlan_bounds_script, |vb_pkts| assert_eq!((vb_pkts.len(), vb_pkts[0].ethertype(), vb_pkts[1].ethertype()), (2, Some(0x8100), Some(0x8100))));
    }

    /// Tests boundary `TTL` values (`0`, `1`, and `255`).
    #[test]
    pub fn test_tier2_l3_ttl_boundaries() {
        let ttl_bounds_script = r#"
            host ttl_h1 { ip 10.80.2.1 }
            host ttl_h2 { ip 10.80.2.2 }
            flow ttl_bounds_flow(t_src, t_dst) {
                t_src -> t_dst ttl 0 udp payload "ttl0"
                t_src -> t_dst ttl 1 udp payload "ttl1"
                t_src -> t_dst ttl 255 udp payload "ttl255"
            } compile { ttl_bounds_flow(ttl_h1, ttl_h2) }"#;
        run_e2e_test(ttl_bounds_script, |ttl_pkts| assert_eq!((ttl_pkts.len(), ttl_pkts[0].raw[22], ttl_pkts[2].raw[22]), (3, 0, 255)));
    }

    /// Tests boundary `DSCP` (`0` and `63`) and `ECN` (`0..=3`) header encoding.
    #[test]
    pub fn test_tier2_l3_dscp_and_ecn_boundaries() {
        let qos_bounds_script = r#"
            host qos_h1 { ip 10.80.3.1 }
            host qos_h2 { ip 10.80.3.2 }
            flow qos_bounds_flow(q_src, q_dst) {
                q_src -> q_dst dscp 0 ecn 0 udp payload "dscp_min"
                q_src -> q_dst dscp 63 ecn 3 udp payload "dscp_max"
            } compile { qos_bounds_flow(qos_h1, qos_h2) }"#;
        run_e2e_test(qos_bounds_script, |qos_pkts| assert_eq!((qos_pkts.len(), qos_pkts[0].raw[15], qos_pkts[1].raw[15]), (2, 0x00, 0xFF)));
    }

    /// Tests boundary 20-bit IPv6 `FLOWLABEL` values (`0` and `1048575` / `0xFFFFF`).
    #[test]
    pub fn test_tier2_l3_flowlabel_boundaries() {
        let fl_bounds_script = r#"
            host fl_v6_a { ip 2001:db8:80::1 }
            host fl_v6_b { ip 2001:db8:80::2 }
            flow flowlabel_bounds(fl_src, fl_dst) {
                fl_src -> fl_dst flowlabel 0 udp payload "flowlabel_0"
                fl_src -> fl_dst flowlabel 1048575 udp payload "flowlabel_max"
            } compile { flowlabel_bounds(fl_v6_a, fl_v6_b) }"#;
        run_e2e_test(fl_bounds_script, |fl_pkts| assert_eq!((fl_pkts.len(), fl_pkts[0].ethertype()), (2, Some(0x86DD))));
    }

    /// Tests `FLOWLABEL` on IPv4 hosts being silently ignored per dual-stack polymorphism rules.
    #[test]
    pub fn test_tier2_l3_flowlabel_ipv4_silently_ignored() {
        let fl_v4_script = r#"
            host fl_v4_a { ip 10.80.4.1 }
            host fl_v4_b { ip 10.80.4.2 }
            flow flowlabel_ipv4_ignore(v4_s, v4_d) {
                v4_s -> v4_d flowlabel 99999 udp payload "v4_flowlabel"
            } compile { flowlabel_ipv4_ignore(fl_v4_a, fl_v4_b) }"#;
        run_e2e_test(fl_v4_script, |fl_v4_pkts| assert_eq!((fl_v4_pkts.len(), fl_v4_pkts[0].ethertype()), (1, Some(0x0800))));
    }

    /// Tests string escape sequences (`\r`, `\n`, `\t`, `\"`) and raw `HEXPAYLOAD` encoding.
    #[test]
    pub fn test_tier2_payload_escape_sequences_and_hex() {
        let esc_script = r#"
            host esc_h1 { ip 10.80.5.1 }
            host esc_h2 { ip 10.80.5.2 }
            flow escape_and_hex_flow(e_src, e_dst) {
                e_src -> e_dst udp payload "line1\r\nline2\t\"quoted\""
                e_src -> e_dst udp hexpayload "deadbeefcafebabe01020304"
            } compile { escape_and_hex_flow(esc_h1, esc_h2) }"#;
        run_e2e_test(esc_script, |esc_pkts| assert_eq!((esc_pkts.len(), &esc_pkts[1].raw[42..46]), (2, &[0xde, 0xad, 0xbe, 0xef][..])));
    }

    /// Tests contextual sub-keywords used freely as `HOST`, `FLOW`, and parameter identifiers.
    #[test]
    pub fn test_tier2_contextual_keywords_as_identifiers() {
        let ctx_ident_script = r#"
            host dns { ip 10.80.6.1 }
            host tcp { ip 10.80.6.2 }
            flow query(ms, s) {
                ms -> s udp payload "contextual_idents"
            } compile { query(dns, tcp) }"#;
        run_e2e_test(ctx_ident_script, |ctx_pkts| assert_eq!((ctx_pkts.len(), ctx_pkts[0].ethertype()), (1, Some(0x0800))));
    }

    /// Tests two-stage TCP port inheritance across reversed arrows (`->` and `<-`) when omitted.
    #[test]
    pub fn test_tier2_two_stage_tcp_port_inheritance() {
        let port_inh_script = r#"
            host pi_cli { ip 10.80.7.1 }
            host pi_srv { ip 10.80.7.2 }
            flow port_inherit_flow(p_c, p_s) {
                p_c -> p_s tcp syn srcport 54321 dstport 8080
                p_c <- p_s tcp syn ack
                p_c -> p_s tcp ack
            } compile { port_inherit_flow(pi_cli, pi_srv) }"#;
        run_e2e_test(port_inh_script, |pi_pkts| assert_eq!((pi_pkts.len(), u16::from_be_bytes([pi_pkts[1].raw[34], pi_pkts[1].raw[35]])), (3, 8080)));
    }

    /// Tests loopback 4-tuple TCP connection tracking (`127.0.0.1 -> 127.0.0.1`).
    #[test]
    pub fn test_tier2_loopback_4tuple_tcp_tracking() {
        let loop_script = r#"
            host loop_v4 { ip 127.0.0.1 }
            flow loopback_tcp_flow(lo_a, lo_b) {
                lo_a -> lo_b tcp syn srcport 10001 dstport 10002
                lo_a <- lo_b tcp syn ack
                lo_a -> lo_b tcp ack
            } compile { loopback_tcp_flow(loop_v4, loop_v4) }"#;
        run_e2e_test(loop_script, |lo_pkts| assert_eq!((lo_pkts.len(), u16::from_be_bytes([lo_pkts[1].raw[34], lo_pkts[1].raw[35]])), (3, 10002)));
    }

    /// Tests concurrent multi-port TCP connections between the same host pair.
    #[test]
    pub fn test_tier2_concurrent_multi_port_connections() {
        let multi_conn_script = r#"
            host mp_cli { ip 10.80.8.1 }
            host mp_srv { ip 10.80.8.2 }
            flow conn_a(ca, sa) { ca -> sa tcp syn srcport 40001 dstport 80 }
            flow conn_b(cb, sb) { cb -> sb tcp syn srcport 40002 dstport 443 }
            compile {
                conn_a(mp_cli, mp_srv)
                conn_b(mp_cli, mp_srv)
            }"#;
        run_e2e_test(multi_conn_script, |mp_pkts| assert_eq!((mp_pkts.len(), u16::from_be_bytes([mp_pkts[0].raw[36], mp_pkts[0].raw[37]]), u16::from_be_bytes([mp_pkts[1].raw[36], mp_pkts[1].raw[37]])), (2, 80, 443)));
    }

    /// Tests strict `1 Statement = 1 Frame` invariant for TCP-based Layer 7 protocols.
    #[test]
    pub fn test_tier2_tcp_l7_strict_one_statement_one_frame() {
        let one_to_one_script = r#"
            host http_c { ip 10.80.9.1 }
            host http_s { ip 10.80.9.2 }
            flow strict_http_frames(hc, hs) {
                hc -> hs http get uri "/"
                hc <- hs http status 200
            } compile { strict_http_frames(http_c, http_s) }"#;
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
            host client_v4 { ip 192.168.90.1 }
            host server_v4 { ip 192.168.90.2 }
            host client_v6 { ip 2001:db8:90::1 }
            host server_v6 { ip 2001:db8:90::2 }
            flow dual_ping_flow(ep_c, ep_s) {
                ep_c -> ep_s icmp echorequest
                ep_c <- ep_s icmp echoreply
            } compile {
                dual_ping_flow(client_v4, server_v4)
                dual_ping_flow(client_v6, server_v6)
            }"#;
        run_e2e_test(poly_script, |poly_pkts| assert_eq!((poly_pkts.len(), poly_pkts[0].ethertype(), poly_pkts[2].ethertype()), (4, Some(0x0800), Some(0x86DD))));
    }

    /// Tests single `VLAN` and double `QINQ` tagging stacked with `TCP` and `UDP` transports.
    #[test]
    pub fn test_tier3_vlan_stacked_with_transports() {
        let stacked_script = r#"
            host st_cli { ip 10.90.1.1 }
            host st_srv { ip 10.90.1.2 }
            flow stacked_vlan_l4(sc, ss) {
                sc -> ss vlan 100 tcp syn srcport 12345 dstport 80
                sc -> ss qinq 200 innervlan 10 udp srcport 53 dstport 53 payload "dns"
            } compile { stacked_vlan_l4(st_cli, st_srv) }"#;
        run_e2e_test(stacked_script, |st_pkts| assert_eq!((st_pkts.len(), st_pkts[0].ethertype(), st_pkts[1].ethertype()), (2, Some(0x8100), Some(0x88A8))));
    }

    /// Tests multicast MAC auto-derivation: RFC 1112 (`01:00:5e:..`) and RFC 2464 (`33:33:..`).
    #[test]
    pub fn test_tier3_multicast_mac_auto_derivation() {
        let mcast_auto_script = r#"
            host uni_v4 { ip 192.168.91.1 }
            host grp_v4 { ip 224.0.0.1 }
            host uni_v6 { ip fe80::91 }
            host grp_v6 { ip ff02::1 }
            flow mcast_derive_flow(src4, dst4, src6, dst6) {
                src4 -> dst4 udp payload "mcast_v4"
                src6 -> dst6 udp payload "mcast_v6"
            } compile { mcast_derive_flow(uni_v4, grp_v4, uni_v6, grp_v6) }"#;
        run_e2e_test(mcast_auto_script, |mc_pkts| assert_eq!((mc_pkts.len(), mc_pkts[0].dst_mac(), mc_pkts[1].dst_mac()), (2, Some([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]), Some([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]))));
    }

    /// Tests explicit `MAC` overrides taking precedence over multicast MAC auto-derivation.
    #[test]
    pub fn test_tier3_multicast_mac_explicit_override() {
        let mcast_ovr_script = r#"
            host ovr_src { ip 192.168.92.1 }
            host ovr_mcast { ip 224.0.0.1 mac 00:AA:BB:CC:DD:EE }
            flow mcast_override_flow(os, om) {
                os -> om udp payload "override_mac"
            } compile { mcast_override_flow(ovr_src, ovr_mcast) }"#;
        run_e2e_test(mcast_ovr_script, |ovr_pkts| assert_eq!((ovr_pkts.len(), ovr_pkts[0].dst_mac()), (1, Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]))));
    }

    /// Tests RFC 7323 TCP options matrix (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`).
    #[test]
    pub fn test_tier3_tcp_options_matrix() {
        let tcp_opt_script = r#"
            host opt_cli { ip 10.90.2.1 }
            host opt_srv { ip 10.90.2.2 }
            flow tcp_opts_flow(oc, os) {
                oc -> os tcp syn srcport 12345 dstport 80 mss 1460 wscale 7 sackperm tsval 100 tsecr 0
            } compile { tcp_opts_flow(opt_cli, opt_srv) }"#;
        run_e2e_test(tcp_opt_script, |opt_pkts| assert!(opt_pkts[0].raw.len() > 54, "TCP options must extend header beyond 20B"));
    }

    /// Tests `WAIT` timing modifiers across all supported duration units (`ns`, `us`, `ms`, `s`, `m`).
    #[test]
    pub fn test_tier3_timing_wait_units() {
        let wait_script = r#"
            host tm_h1 { ip 10.90.3.1 }
            host tm_h2 { ip 10.90.3.2 }
            flow wait_units_flow(ts, td) {
                ts -> td udp payload "p1" wait 500ns
                ts -> td udp payload "p2" wait 10us
                ts -> td udp payload "p3" wait 5ms
                ts -> td udp payload "p4" wait 1s
                ts -> td udp payload "p5" wait 1m
            } compile { wait_units_flow(tm_h1, tm_h2) }"#;
        run_e2e_test(wait_script, |wait_pkts| assert_eq!(wait_pkts.len(), 5));
    }

    /// Tests stress execution of bidirectional statements across 10 repeated flow calls in `compile`.
    #[test]
    pub fn test_tier3_repeated_flow_multi_protocol_stress() {
        let loop_stress_script = r#"
            host lp_c { ip 10.90.4.1 }
            host lp_s { ip 10.90.4.2 }
            flow ping_pong_loop(l_cli, l_srv) {
                l_cli -> l_srv udp payload "ping"
                l_cli <- l_srv udp payload "pong"
            } compile { ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s)
                ping_pong_loop(lp_c, lp_s) }"#;
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
            host def_a { ip 10.99.0.1 }
            host def_b { ip 10.99.0.2 }
            flow def_f(dx, dy) { dx -> dy udp payload "cli_test" }
            compile { def_f(def_a, def_b) }"#;
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
            host cust_a { ip 10.99.1.1 }
            host cust_b { ip 10.99.1.2 }
            flow cust_f(cx, cy) { cx -> cy udp payload "custom_path" }
            compile { cust_f(cust_a, cust_b) }"#;
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
