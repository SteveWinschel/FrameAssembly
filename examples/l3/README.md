# Layer 3 Example Scenarios

[← All Examples](../README.md) • [Layer 3 Protocol Guide](../../docs/04_l3_protocols.md) • [Use-Case Cookbook](../../docs/02_use_cases.md)

This folder holds **645 `.frasm` scenarios** across all **20 Layer 3 protocols** (routing, first-hop redundancy, overlay tunnels, neighbor discovery, multicast, and VPNs). Every protocol folder starts with a minimal 2-block `<proto>_default_frame.frasm` file (`host` + `compile`, zero `flow` block) alongside 31+ realistic captures.

Run any file from the repository root:

```console
$ frameassembly show examples/l3/bgp/bgp_default_frame.frasm
$ frameassembly examples/l3/bgp/bgp_four_byte_asn_peering.frasm temp/bgp_peering.pcap
```

## All 20 Layer 3 Protocols

| Protocol | Directory | Wire Framing | Wireshark Filter | Starter (2-Block) | Featured Scenario | Count |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **IPsec AH** | [`ah/`](ah/) | IP Proto `51` | `ah` | [`ah_default_frame.frasm`](ah/ah_default_frame.frasm) | [`ah_vrrp_redundancy_group_auth_header.frasm`](ah/ah_vrrp_redundancy_group_auth_header.frasm) | 32 |
| **BFD / S-BFD** | [`bfd/`](bfd/) | UDP `3784` / `4784` / `7784` | `bfd` | [`bfd_default_frame.frasm`](bfd/bfd_default_frame.frasm) | [`bfd_bgp_fast_external_fallover_trigger.frasm`](bfd/bfd_bgp_fast_external_fallover_trigger.frasm) | 32 |
| **BGP-4 / MP-BGP** | [`bgp/`](bgp/) | TCP `179` | `bgp` | [`bgp_default_frame.frasm`](bgp/bgp_default_frame.frasm) | [`bgp_four_byte_asn_peering.frasm`](bgp/bgp_four_byte_asn_peering.frasm) | 33 |
| **IPsec ESP** | [`esp/`](esp/) | IP Proto `50` | `esp` | [`esp_default_frame.frasm`](esp/esp_default_frame.frasm) | [`esp_anti_replay_sliding_window_stress.frasm`](esp/esp_anti_replay_sliding_window_stress.frasm) | 32 |
| **GENEVE** | [`geneve/`](geneve/) | UDP `6081` | `geneve` | [`geneve_default_frame.frasm`](geneve/geneve_default_frame.frasm) | [`geneve_aws_gwlb_appliance_inspection_tlv.frasm`](geneve/geneve_aws_gwlb_appliance_inspection_tlv.frasm) | 32 |
| **GRE / NVGRE** | [`gre/`](gre/) | IP Proto `47` | `gre` | [`gre_default_frame.frasm`](gre/gre_default_frame.frasm) | [`gre_erspan_tap_mirroring.frasm`](gre/gre_erspan_tap_mirroring.frasm) | 32 |
| **HSRPv1 / v2** | [`hsrp/`](hsrp/) | UDP `1985` / `2029` | `hsrp || hsrp2` | [`hsrp_default_frame.frasm`](hsrp/hsrp_default_frame.frasm) | [`hsrp_preemption_coup_takeover.frasm`](hsrp/hsrp_preemption_coup_takeover.frasm) | 32 |
| **ICMP / ICMPv6** | [`icmp/`](icmp/) | IP Proto `1` / NH `58` | `icmp || icmpv6` | [`icmp_default_frame.frasm`](icmp/icmp_default_frame.frasm) | [`icmp_mtu_blackhole_troubleshoot.frasm`](icmp/icmp_mtu_blackhole_troubleshoot.frasm) | 33 |
| **IGMP** | [`igmp/`](igmp/) | IP Proto `2` | `igmp` | [`igmp_default_frame.frasm`](igmp/igmp_default_frame.frasm) | [`igmp_iptv_channel_zap_sequence.frasm`](igmp/igmp_iptv_channel_zap_sequence.frasm) | 32 |
| **IKEv2** | [`ikev2/`](ikev2/) | UDP `500` / `4500` | `isakmp` | [`ikev2_default_frame.frasm`](ikev2/ikev2_default_frame.frasm) | [`ikev2_cloud_vpc_redundant_tunnel_bringup.frasm`](ikev2/ikev2_cloud_vpc_redundant_tunnel_bringup.frasm) | 32 |
| **IPsec (`ipsec` alias)** | [`ipsec/`](ipsec/) | IP Proto `50` | `esp` | [`ipsec_default_frame.frasm`](ipsec/ipsec_default_frame.frasm) | [`ipsec_aes_gcm_authenticated_payload.frasm`](ipsec/ipsec_aes_gcm_authenticated_payload.frasm) | 32 |
| **MLD** | [`mld/`](mld/) | ICMPv6 NH `58` | `icmpv6.mld` | [`mld_default_frame.frasm`](mld/mld_default_frame.frasm) | [`mld_datacenter_vxlan_ipv6_underlay_join.frasm`](mld/mld_datacenter_vxlan_ipv6_underlay_join.frasm) | 32 |
| **NDP** | [`ndp/`](ndp/) | ICMPv6 NH `58` | `icmpv6.nd` | [`ndp_default_frame.frasm`](ndp/ndp_default_frame.frasm) | [`ndp_dad_duplicate_address_detection.frasm`](ndp/ndp_dad_duplicate_address_detection.frasm) | 32 |
| **OpenFlow** | [`openflow/`](openflow/) | TCP `6653` / `6633` | `openflow_v4` | [`openflow_default_frame.frasm`](openflow/openflow_default_frame.frasm) | [`openflow_flow_mod_add_rule.frasm`](openflow/openflow_flow_mod_add_rule.frasm) | 32 |
| **OSPFv2 / v3** | [`ospf/`](ospf/) | IP Proto `89` | `ospf` | [`ospf_default_frame.frasm`](ospf/ospf_default_frame.frasm) | [`ospf_ipv6_ospfv3_neighbor_hello.frasm`](ospf/ospf_ipv6_ospfv3_neighbor_hello.frasm) | 33 |
| **PIM-SM / SSM** | [`pim/`](pim/) | IP Proto `103` | `pim` | [`pim_default_frame.frasm`](pim/pim_default_frame.frasm) | [`pim_anycast_rp_rfc4610_register_sync.frasm`](pim/pim_anycast_rp_rfc4610_register_sync.frasm) | 32 |
| **RIPv2 / RIPng** | [`rip/`](rip/) | UDP `520` / `521` | `rip || ripng` | [`rip_default_frame.frasm`](rip/rip_default_frame.frasm) | [`rip_counting_to_infinity_prevention_holddown.frasm`](rip/rip_counting_to_infinity_prevention_holddown.frasm) | 32 |
| **VRRPv2 / v3** | [`vrrp/`](vrrp/) | IP Proto `112` | `vrrp` | [`vrrp_default_frame.frasm`](vrrp/vrrp_default_frame.frasm) | [`vrrp_gateway_failover_priority_drop.frasm`](vrrp/vrrp_gateway_failover_priority_drop.frasm) | 33 |
| **VXLAN** | [`vxlan/`](vxlan/) | UDP `4789` / `8472` | `vxlan` | [`vxlan_default_frame.frasm`](vxlan/vxlan_default_frame.frasm) | [`vxlan_datacenter_evpn_vtep_probe.frasm`](vxlan/vxlan_datacenter_evpn_vtep_probe.frasm) | 33 |
| **WireGuard** | [`wireguard/`](wireguard/) | UDP `51820` | `wg` | [`wireguard_default_frame.frasm`](wireguard/wireguard_default_frame.frasm) | [`wireguard_cookie_reply_dos_mitigation.frasm`](wireguard/wireguard_cookie_reply_dos_mitigation.frasm) | 32 |

## Protocol Highlights

- **IPsec AH** ([`ah/`](ah/)): Immutable-header integrity with SPI, sequence numbers, and ICV digests.
- **BFD / S-BFD** ([`bfd/`](bfd/)): Sub-second 3.3ms link checks, diagnostic codes, and fast BGP/VRRP failover.
- **BGP-4 / MP-BGP** ([`bgp/`](bgp/)): 2-byte and 4-byte ASN peering, RTBH blackholes, FlowSpec, and notifications.
- **IPsec ESP** ([`esp/`](esp/)): AES-GCM / ChaCha20 IV and ICV fields, anti-replay windows, and tunnel/transport mode.
- **GENEVE** ([`geneve/`](geneve/)): Cloud overlay VNIs and option TLVs for AWS GWLB, Cilium, OVN, and NSX.
- **GRE / NVGRE** ([`gre/`](gre/)): Point-to-point GRE, keys, sequence numbers, ERSPAN II/III, and MPLS-in-GRE.
- **HSRPv1 / v2** ([`hsrp/`](hsrp/)): Active/Standby gateway elections, coup preemption, and IPv6 HSRPv2.
- **ICMP / ICMPv6** ([`icmp/`](icmp/)): Ping, PMTUD Fragmentation Needed (`code 4`), traceroute TTL expiry, and ACL rejections.
- **IGMP** ([`igmp/`](igmp/)): IGMPv1/v2/v3 queries, IPTV channel zaps, SSM joins, and fast-leave probes.
- **IKEv2** ([`ikev2/`](ikev2/)): `sainit`, `auth`, `createchildsa`, NAT-T float to `4500`, DPD, and stateless cookies.
- **IPsec (`ipsec` alias)** ([`ipsec/`](ipsec/)): Alias for `esp` across encrypted gateway tunnels and DSCP-marked VPN queues.
- **MLD** ([`mld/`](mld/)): IPv6 multicast listener queries, reports, and `done` leave messages.
- **NDP** ([`ndp/`](ndp/)): SLAAC router solicitations/advertisements, DAD probes, and anycast mobility.
- **OpenFlow** ([`openflow/`](openflow/)): SDN switch `hello`, `dpid` discovery, `packetin`, and `flowmod` drop/forward rules.
- **OSPFv2 / v3** ([`ospf/`](ospf/)): 5-packet LSDB synchronization, DR/BDR elections, fast timers, and IPv6 OSPFv3.
- **PIM-SM / SSM** ([`pim/`](pim/)): DR priority elections, `(S,G)` joins, Anycast-RP `register`, and graceful shutdown.
- **RIPv2 / RIPng** ([`rip/`](rip/)): Route announcements, tags, default routes, and `metric 16` poison-reverse loops.
- **VRRPv2 / v3** ([`vrrp/`](vrrp/)): Sub-second VIP heartbeats, uplink object tracking drops, and `priority 0` release.
- **VXLAN** ([`vxlan/`](vxlan/)): EVPN L2VNI/L3VNI IRB, ECMP source-port entropy, ARP suppression, and BUM multicast.
- **WireGuard** ([`wireguard/`](wireguard/)): `Noise_IK` handshakes, DoS cookie challenges, roaming, and transport data.

## Notes on Timing and Dual-Stack Behavior

- **IPv4 and IPv6:** Every Layer 3 keyword works across IPv4 and IPv6 endpoints (`icmp` becomes ICMPv6, `ospf` becomes OSPFv3, `rip` becomes RIPng on UDP `521`, and `hsrp` switches to HSRPv2 on UDP `2029`).
- **Post-packet `wait`:** Writing `wait 2ms` on packet 1 pauses 2ms *after* packet 1 before packet 2 is emitted (default gap is `10ms` when `wait` is omitted).
- **2-block quickstarters:** Every `<proto>_default_frame.frasm` sends a single default frame straight inside `compile { ... }` so you can test firewall ACLs or Wireshark dissectors in seconds.
