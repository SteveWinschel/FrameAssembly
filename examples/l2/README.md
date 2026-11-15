# Layer 2 Example Scenarios

[← All Examples](../README.md) • [Layer 2 Protocol Guide](../../docs/03_l2_protocols.md) • [Use-Case Cookbook](../../docs/02_use_cases.md)

This folder holds **257 `.frasm` scenarios** across all **8 Layer 2 protocols**: ARP, 802.1X EAPOL, LACP, LLDP, MPLS, 802.1ad QinQ, STP/RSTP, and 802.1Q VLANs. Every protocol folder includes a minimal 2-block `<proto>_default_frame.frasm` starter (`host` + `compile`, zero `flow` block) alongside 31+ practical captures.

Preview or compile any file from the repository root:

```console
$ frameassembly show examples/l2/vlan/vlan_default_frame.frasm
$ frameassembly examples/l2/qinq/qinq_carrier_double_tag_trunk.frasm temp/qinq_trunk.pcap
```

## All 8 Layer 2 Protocols

| Protocol | Directory | EtherType / Framing | Wireshark Filter | Starter (2-Block) | Featured Scenario | Count |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **ARP** | [`arp/`](arp/) | `0x0806` (NDP on IPv6) | `arp` | [`arp_default_frame.frasm`](arp/arp_default_frame.frasm) | [`arp_address_conflict_detection_probe.frasm`](arp/arp_address_conflict_detection_probe.frasm) | 32 |
| **802.1X EAPOL** | [`eapol/`](eapol/) | `0x888E` | `eapol \|\| eap` | [`eapol_default_frame.frasm`](eapol/eapol_default_frame.frasm) | [`eapol_byod_onboarding_coa_reauthentication.frasm`](eapol/eapol_byod_onboarding_coa_reauthentication.frasm) | 32 |
| **LACP** | [`lacp/`](lacp/) | `0x8809` (`01:80:C2:00:00:02`) | `lacp` | [`lacp_default_frame.frasm`](lacp/lacp_default_frame.frasm) | [`lacp_active_initiator_passive_partner.frasm`](lacp/lacp_active_initiator_passive_partner.frasm) | 32 |
| **LLDP** | [`lldp/`](lldp/) | `0x88CC` (`01:80:C2:00:00:0E`) | `lldp` | [`lldp_default_frame.frasm`](lldp/lldp_default_frame.frasm) | [`lldp_bidirectional_spine_leaf_400g.frasm`](lldp/lldp_bidirectional_spine_leaf_400g.frasm) | 32 |
| **MPLS** | [`mpls/`](mpls/) | `0x8847` (stacked labels) | `mpls` | [`mpls_default_frame.frasm`](mpls/mpls_default_frame.frasm) | [`mpls_5g_backhaul_sctp_ngap_l3vpn.frasm`](mpls/mpls_5g_backhaul_sctp_ngap_l3vpn.frasm) | 32 |
| **802.1ad QinQ** | [`qinq/`](qinq/) | `0x88A8` + `0x8100` | `eth.type == 0x88a8 \|\| vlan` | [`qinq_default_frame.frasm`](qinq/qinq_default_frame.frasm) | [`qinq_carrier_double_tag_trunk.frasm`](qinq/qinq_carrier_double_tag_trunk.frasm) | 33 |
| **STP / RSTP** | [`stp/`](stp/) | IEEE 802.3 (`01:80:C2:00:00:00`) | `stp` | [`stp_default_frame.frasm`](stp/stp_default_frame.frasm) | [`stp_bpdu_guard_self_loop_detection.frasm`](stp/stp_bpdu_guard_self_loop_detection.frasm) | 32 |
| **802.1Q VLAN** | [`vlan/`](vlan/) | `0x8100` (VID, PCP, DEI) | `vlan` | [`vlan_default_frame.frasm`](vlan/vlan_default_frame.frasm) | [`vlan_boundary_max_4094_trunk.frasm`](vlan/vlan_boundary_max_4094_trunk.frasm) | 32 |

## Protocol Highlights

- **ARP ([`arp/`](arp/))**: RFC 5227 Address Conflict Detection probes ([`arp_address_conflict_detection_probe.frasm`](arp/arp_address_conflict_detection_probe.frasm)), Dynamic ARP Inspection spoof checks ([`arp_dynamic_inspection_spoof_test.frasm`](arp/arp_dynamic_inspection_spoof_test.frasm)), Gratuitous ARP VIP takeovers ([`arp_gratuitous_announcement.frasm`](arp/arp_gratuitous_announcement.frasm)), and IPv6 NDP translation ([`arp_ipv6_polymorphic_ndp_solicitation_adaptation.frasm`](arp/arp_ipv6_polymorphic_ndp_solicitation_adaptation.frasm)).
- **802.1X EAPOL ([`eapol/`](eapol/))**: EAP-TLS, PEAP, EAP-AKA', CoA re-authentication ([`eapol_byod_onboarding_coa_reauthentication.frasm`](eapol/eapol_byod_onboarding_coa_reauthentication.frasm)), authentication rejections ([`eapol_authentication_failure_reject.frasm`](eapol/eapol_authentication_failure_reject.frasm)), and MAC Authentication Bypass fallbacks ([`eapol_datacenter_bare_metal_pxe_mab_fallback.frasm`](eapol/eapol_datacenter_bare_metal_pxe_mab_fallback.frasm)).
- **LACP ([`lacp/`](lacp/))**: Active/passive bond negotiation ([`lacp_active_initiator_passive_partner.frasm`](lacp/lacp_active_initiator_passive_partner.frasm)), actor/partner key mismatches ([`lacp_cabling_key_mismatch_out_of_sync.frasm`](lacp/lacp_cabling_key_mismatch_out_of_sync.frasm)), MLAG/VSS trunks ([`lacp_chassis_vss_stackwise_virtual_mec_trunk.frasm`](lacp/lacp_chassis_vss_stackwise_virtual_mec_trunk.frasm)), and short-timeout 5G UPF bonds.
- **LLDP ([`lldp/`](lldp/))**: Spine-leaf 400GbE discovery ([`lldp_bidirectional_spine_leaf_400g.frasm`](lldp/lldp_bidirectional_spine_leaf_400g.frasm)), IEEE 802.3at PoE+ Class 4 camera power negotiation ([`lldp_campus_ip_camera_poe_plus_class4_negotiation.frasm`](lldp/lldp_campus_ip_camera_poe_plus_class4_negotiation.frasm)), O-RAN fronthaul, and AI RoCEv2 fabric TLVs.
- **MPLS ([`mpls/`](mpls/))**: Stacked transport/service labels for 5G backhaul ([`mpls_5g_backhaul_sctp_ngap_l3vpn.frasm`](mpls/mpls_5g_backhaul_sctp_ngap_l3vpn.frasm)), dual-stack 6VPE IPv6 transit ([`mpls_6vpe_ipv6_vpn_http2_transit.frasm`](mpls/mpls_6vpe_ipv6_vpn_http2_transit.frasm)), TI-LFA fast reroute, and RFC 5884 LSP BFD monitoring ([`mpls_bfd_lsp_liveliness_monitoring.frasm`](mpls/mpls_bfd_lsp_liveliness_monitoring.frasm)).
- **802.1ad QinQ ([`qinq/`](qinq/))**: Dual-stack provider S-VLAN + customer C-VLAN trunks ([`qinq_carrier_double_tag_trunk.frasm`](qinq/qinq_carrier_double_tag_trunk.frasm)), boundary VLAN 4094 frames ([`qinq_boundary_max_4094_double_tag.frasm`](qinq/qinq_boundary_max_4094_double_tag.frasm)), and BNG wholesale broadband access ([`qinq_broadband_bng_pppoe_wholesale_bitstream.frasm`](qinq/qinq_broadband_bng_pppoe_wholesale_bitstream.frasm)).
- **STP / RSTP ([`stp/`](stp/))**: BPDU Guard loop traps ([`stp_bpdu_guard_self_loop_detection.frasm`](stp/stp_bpdu_guard_self_loop_detection.frasm)), Root/Configuration BPDUs ([`stp_config_bpdu_root.frasm`](stp/stp_config_bpdu_root.frasm)), and UplinkFast / BackboneFast failover sequences.
- **802.1Q VLAN ([`vlan/`](vlan/))**: Access port tags ([`vlan_basic_access_tag.frasm`](vlan/vlan_basic_access_tag.frasm)), boundary trunk ID 4094 ([`vlan_boundary_max_4094_trunk.frasm`](vlan/vlan_boundary_max_4094_trunk.frasm)), Dante audio/SMPTE ST 2110 CoS PCP priority tagging, and dual-stack IXP peering ([`vlan_ixp_peering_dual_stack_bgp.frasm`](vlan/vlan_ixp_peering_dual_stack_bgp.frasm)).

## Notes on MAC-Only Hosts, Tagging, and Timing

- **MAC-only endpoints:** Pure Layer 2 protocols (`arp`, `eapol`, `lacp`, `lldp`, `mpls`, `qinq`, `stp`, `vlan`) compile with `host name { mac aa:bb:cc:dd:ee:ff }` alone when no Layer 3–7 payload is stacked inside the frame.
- **Cross-layer VLAN, QinQ, and MPLS tags:** Prefix any Layer 3, 4, or 7 statement with `vlan <id> [pcp <0-7>] [dei <0-1>]`, `qinq <svid> [innervlan <cvid>]`, or `mpls <label> [exp <0-7>]` when testing switch trunks and QoS queues.
- **Post-packet `wait`:** Adding `wait 2ms` on a line pauses 2ms *after* that frame is sent before the next frame starts (default gap is `10ms` when omitted).
