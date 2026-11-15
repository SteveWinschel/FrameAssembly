# Multi-Host Topology & Feature Scenarios

[← All Examples](../README.md) • [Topologies & Dual-Stack Guide](../../docs/11_topologies_and_dual_stack.md) • [Use-Case Cookbook](../../docs/02_use_cases.md)

This folder holds **106 multi-host and cross-layer `.frasm` scenarios** combining Layer 2 switching, Layer 3 routing and VPNs, Layer 4 transports, QoS markings, dual-stack IPv4/IPv6 addressing, and full enterprise, data center, telecom, security, and OT/ICS topologies.

Preview or compile any topology from the repository root:

```console
$ frameassembly show examples/topologies/branch_snmp_syslog_firewall_audit.frasm
$ frameassembly examples/topologies/ot_factory_vlan_modbus_segmentation.frasm temp/ot_audit.pcap
```

## Quickstarters & Core Mechanics (11)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`minimal_single_frame_baseline.frasm`](minimal_single_frame_baseline.frasm) | Minimal 2-block single TCP SYN frame (`host` + `compile`) | `tcp.flags.syn == 1` |
| [`dual_stack_polymorphic_flow_basic.frasm`](dual_stack_polymorphic_flow_basic.frasm) | Single flow executed over IPv4 and IPv6 host pairs | `tcp.port == 8080` |
| [`dual_stack_polymorphic_flow_with_modifiers.frasm`](dual_stack_polymorphic_flow_with_modifiers.frasm) | Shared dual-stack flow with TTL, DSCP QoS, and wait pacing | `udp` |
| [`dual_stack_loop_block_orchestration.frasm`](dual_stack_loop_block_orchestration.frasm) | Repeated IPv4 and IPv6 flow calls in `compile` | `udp` |
| [`multi_arg_flow_mesh_orchestration.frasm`](multi_arg_flow_mesh_orchestration.frasm) | 5-host east-west microservice mesh orchestration | `tcp \|\| udp` |
| [`multi_loop_staged_load_test.frasm`](multi_loop_staged_load_test.frasm) | Multi-stage traffic burst sequencing in `compile` | `tcp \|\| udp` |
| [`complex_enterprise_network.frasm`](complex_enterprise_network.frasm) | Repeated HTTP sessions, Syslog alerts, and SNMP traps | `snmp \|\| tcp` |
| [`snmp_tri_version_coexistence_audit.frasm`](snmp_tri_version_coexistence_audit.frasm) | SNMPv1, SNMPv2c, and encrypted SNMPv3 side by side | `snmp` |
| [`multicast_explicit_mac_override.frasm`](multicast_explicit_mac_override.frasm) | Custom multicast MAC override vs. auto-derived MACs | `udp` |
| [`complete_dsl_omnibus_reference.frasm`](complete_dsl_omnibus_reference.frasm) | Full-coverage reference across protocols and modifiers | `snmp \|\| tcp \|\| udp` |
| [`complete_dsl_grand_finale_omnibus.frasm`](complete_dsl_grand_finale_omnibus.frasm) | Dual-stack, L2 tags, L3 controls, L4, SNMP, and OT sweep | `snmp \|\| modbus \|\| vlan` |

## Security, Firewall, Monitoring & Zero-Trust (17)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`branch_snmp_syslog_firewall_audit.frasm`](branch_snmp_syslog_firewall_audit.frasm) | Firewall SSH block (`RST ACK`), Syslog, and SNMPv3 SHA-256 trap | `tcp.port == 22 \|\| syslog \|\| snmp` |
| [`topology_dmz_firewall_intrusion_alert.frasm`](topology_dmz_firewall_intrusion_alert.frasm) | External SYN/FIN+PSH+URG scan, block, and SNMP alert | `snmp \|\| tcp \|\| udp` |
| [`topology_dns_amplification_and_mitigation.frasm`](topology_dns_amplification_and_mitigation.frasm) | DNS ANY amplification burst and SNMP mitigation trap | `snmp \|\| tcp \|\| udp` |
| [`topology_ddos_scrubbing_bgp_flowspec_gre_sflow_netflow_dns.frasm`](topology_ddos_scrubbing_bgp_flowspec_gre_sflow_netflow_dns.frasm) | DDoS scrubbing with sFlow/NetFlow, BGP FlowSpec, and GRE | `dns \|\| cflow \|\| sflow \|\| gre` |
| [`topology_secops_honeypot_telnet_ftp_smb_whois_syslog_snmpv3.frasm`](topology_secops_honeypot_telnet_ftp_smb_whois_syslog_snmpv3.frasm) | Deception honeypot across Telnet, FTP, SMB, WHOIS, Syslog, SNMPv3 | `snmp \|\| syslog \|\| ftp \|\| telnet` |
| [`topology_zero_trust_8021x_eapol_radius_dhcp_dns_arp_coa.frasm`](topology_zero_trust_8021x_eapol_radius_dhcp_dns_arp_coa.frasm) | 802.1X EAPOL onboarding, RADIUS CoA, DHCP, DNS, and ARP | `dns \|\| radius \|\| eapol \|\| arp` |
| [`topology_zero_trust_inspection_pipeline.frasm`](topology_zero_trust_inspection_pipeline.frasm) | NGFW, TLS inspection proxy, and Syslog SIEM chain | `syslog \|\| tls \|\| tcp` |
| [`topology_zero_trust_kerberos_ldap_mtls.frasm`](topology_zero_trust_kerberos_ldap_mtls.frasm) | Kerberos ticket grant, LDAP lookup, and mutual TLS access | `tls \|\| kerberos \|\| ldap` |
| [`topology_zero_trust_proxy_inspection.frasm`](topology_zero_trust_proxy_inspection.frasm) | ZTNA policy enforcement with TLS and RADIUS accounting | `radius \|\| tcp \|\| udp` |
| [`topology_enterprise_campus_dot1x_nac.frasm`](topology_enterprise_campus_dot1x_nac.frasm) | Campus 802.1X NAC onboarding via EAPOL, RADIUS, and DHCP | `radius \|\| eapol` |
| [`topology_active_directory_kerberos_ldap_smb_dns_logon.frasm`](topology_active_directory_kerberos_ldap_smb_dns_logon.frasm) | Windows AD workstation logon (DNS SRV, Kerberos, LDAP, SMB) | `dns \|\| kerberos \|\| ldap` |
| [`topology_noc_observability_netflow_ipfix_sflow.frasm`](topology_noc_observability_netflow_ipfix_sflow.frasm) | NOC pipeline exporting NetFlow v9, IPFIX, sFlow, and SNMP | `snmp \|\| syslog \|\| cflow \|\| sflow` |
| [`topology_network_admin_tacacs_ssh_telnet_tftp.frasm`](topology_network_admin_tacacs_ssh_telnet_tftp.frasm) | Bastion admin session using TACACS+ AAA, SSH, Telnet, TFTP | `tacacs \|\| tftp \|\| ssh \|\| telnet` |
| [`topology_devsecops_ci_cd_git_ssh_https_docker_registry_amqp.frasm`](topology_devsecops_ci_cd_git_ssh_https_docker_registry_amqp.frasm) | CI/CD pipeline: SSH Git push, AMQP runner, HTTPS registry | `ssh \|\| http2 \|\| tls` |
| [`topology_pci_dss_payment_gateway_tls_http2_iso8583_postgres_hsm.frasm`](topology_pci_dss_payment_gateway_tls_http2_iso8583_postgres_hsm.frasm) | PCI-DSS payment authorization over TLS 1.3, HTTP/2, Postgres | `http2 \|\| tls \|\| pgsql \|\| tcp` |
| [`topology_healthcare_pacs_dicom_hl7_mllp_tls_nfs_syslog.frasm`](topology_healthcare_pacs_dicom_hl7_mllp_tls_nfs_syslog.frasm) | Hospital PACS imaging over TLS 1.3, NFS, VLAN, and Syslog | `syslog \|\| tls \|\| nfs \|\| vlan` |
| [`topology_vdi_remote_desktop_kerberos_tls_quic_smb_rdp.frasm`](topology_vdi_remote_desktop_kerberos_tls_quic_smb_rdp.frasm) | Enterprise VDI launch with Kerberos SSO, TLS, QUIC, and SMB | `tls \|\| quic \|\| kerberos` |

## Enterprise Campus, Web, Storage & Collaboration (13)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`topology_campus_fhrp_vrrp_hsrp_stp_arp.frasm`](topology_campus_fhrp_vrrp_hsrp_stp_arp.frasm) | Campus distribution FHRP (VRRP + HSRP), RSTP, and ARP | `vrrp \|\| hsrp \|\| arp \|\| stp` |
| [`topology_campus_wifi_roaming_radius_eapol_capwap_dhcp_mdns.frasm`](topology_campus_wifi_roaming_radius_eapol_capwap_dhcp_mdns.frasm) | Enterprise Wi-Fi 6E roaming with EAPOL, RADIUS, DHCP, mDNS | `mdns \|\| radius \|\| eapol` |
| [`topology_three_tier_web_app.frasm`](topology_three_tier_web_app.frasm) | 4-host client, reverse proxy, app tier, and database tier | `tcp.port == 443` |
| [`topology_dual_stack_dns_web_tier.frasm`](topology_dual_stack_dns_web_tier.frasm) | Multi-tier DNS lookup followed by TLS 1.3 and HTTP/2 | `dns \|\| http2 \|\| tls` |
| [`topology_enterprise_email_dns_smtp_imap_pop3.frasm`](topology_enterprise_email_dns_smtp_imap_pop3.frasm) | Mail lifecycle: DNS MX, SMTP submission, IMAP, and POP3 | `dns \|\| smtp \|\| imap \|\| pop` |
| [`topology_database_tier_mysql_postgres_memcached_amqp.frasm`](topology_database_tier_mysql_postgres_memcached_amqp.frasm) | AMQP event broker, Memcached cache, MySQL, and PostgreSQL | `memcache \|\| mysql \|\| pgsql \|\| amqp` |
| [`topology_storage_area_network_smb_nfs_iscsi.frasm`](topology_storage_area_network_smb_nfs_iscsi.frasm) | Converged storage fabric with LACP, SMB3, NFSv4, and FTP | `ftp \|\| nfs \|\| lacp` |
| [`topology_hpc_lustre_storage_lacp_vlan_nfs_ssh_sflow.frasm`](topology_hpc_lustre_storage_lacp_vlan_nfs_ssh_sflow.frasm) | HPC batch fabric with LACP, SSH, NFS storage, and sFlow | `sflow \|\| ssh \|\| nfs \|\| lacp` |
| [`topology_voip_call_with_qos_telemetry.frasm`](topology_voip_call_with_qos_telemetry.frasm) | VoIP call flow across SIP (5060), RTP voice, and SNMP QoS | `snmp \|\| udp` |
| [`topology_dual_stack_voip_qos_telemetry.frasm`](topology_dual_stack_voip_qos_telemetry.frasm) | Dual-stack VoIP SIP signaling (DSCP 26) and RTP (DSCP 46) | `snmp \|\| sip \|\| rtp` |
| [`topology_voip_sip_rtp_stun_vlan_dscp_ef_sbc_trunk.frasm`](topology_voip_sip_rtp_stun_vlan_dscp_ef_sbc_trunk.frasm) | SBC VoIP trunk with VLAN 200, STUN, SIP, and EF-marked RTP | `stun \|\| sip \|\| rtp \|\| vlan` |
| [`topology_webrtc_stun_sip_rtp_sctp_call.frasm`](topology_webrtc_stun_sip_rtp_sctp_call.frasm) | WebRTC media call combining STUN, SIP, RTP, and SCTP | `stun \|\| sip \|\| rtp \|\| sctp` |
| [`topology_smart_home_mdns_ssdp_websocket_tls.frasm`](topology_smart_home_mdns_ssdp_websocket_tls.frasm) | Local mDNS, UPnP SSDP discovery, WebSocket, and TLS | `mdns \|\| websocket \|\| tls \|\| ssdp` |

## Data Center, Cloud-Native & Financial Fabrics (17)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`topology_spine_leaf_datacenter.frasm`](topology_spine_leaf_datacenter.frasm) | Clos spine-leaf eBGP, VXLAN overlay, and SNMP telemetry | `snmp \|\| tcp \|\| udp` |
| [`topology_clos_fabric_lldp_lacp_bgp_bfd.frasm`](topology_clos_fabric_lldp_lacp_bgp_bfd.frasm) | Leaf-spine underlay bringup: LLDP, LACP, BGP, and BFD | `bgp \|\| bfd \|\| lacp \|\| lldp` |
| [`topology_datacenter_vxlan_evpn_underlay.frasm`](topology_datacenter_vxlan_evpn_underlay.frasm) | Data center BGP-EVPN control plane with VXLAN encapsulation | `vxlan \|\| bgp` |
| [`topology_dual_stack_leaf_spine_fabric.frasm`](topology_dual_stack_leaf_spine_fabric.frasm) | Dual-stack IPv4/IPv6 Clos fabric with BGP and VXLAN | `vxlan \|\| bgp` |
| [`topology_sdn_openflow_vxlan_geneve_controller.frasm`](topology_sdn_openflow_vxlan_geneve_controller.frasm) | SDN OpenFlow 1.3 controller managing VXLAN and GENEVE | `vxlan \|\| geneve \|\| openflow_v4` |
| [`topology_ai_gpu_cluster_rocev2_lldp_pcp_bgp_cnp.frasm`](topology_ai_gpu_cluster_rocev2_lldp_pcp_bgp_cnp.frasm) | AI GPU RoCEv2 lossless fabric with LLDP DCBX, VLAN PCP, BGP | `bgp \|\| lldp \|\| vlan \|\| udp` |
| [`topology_kubernetes_pod_service_mesh.frasm`](topology_kubernetes_pod_service_mesh.frasm) | Kubernetes CoreDNS, pod-to-pod service traffic, and SNMP | `snmp \|\| dns \|\| tcp \|\| udp` |
| [`topology_dual_stack_kubernetes_service_mesh.frasm`](topology_dual_stack_kubernetes_service_mesh.frasm) | Dual-stack Kubernetes HTTP/2 and gRPC service mesh | `http2 \|\| grpc` |
| [`topology_cilium_ebpf_geneve_bgp_http2_grpc_mesh.frasm`](topology_cilium_ebpf_geneve_bgp_http2_grpc_mesh.frasm) | Cilium eBPF service mesh with BGP, GENEVE, HTTP/2, gRPC | `http2 \|\| geneve \|\| bgp` |
| [`topology_microservice_http2_grpc_redis_pg.frasm`](topology_microservice_http2_grpc_redis_pg.frasm) | API gateway HTTP/2, gRPC order service, Redis, PostgreSQL | `http2 \|\| resp \|\| pgsql` |
| [`topology_cloud_observability_otel_grpc_http2_prometheus_redis_postgres.frasm`](topology_cloud_observability_otel_grpc_http2_prometheus_redis_postgres.frasm) | OpenTelemetry gRPC OTLP ingest, HTTP/2, Redis, PostgreSQL | `http2 \|\| resp \|\| pgsql` |
| [`topology_multi_region_database_replication_wireguard_postgres_mysql_redis.frasm`](topology_multi_region_database_replication_wireguard_postgres_mysql_redis.frasm) | Multi-region DB replication over WireGuard (PG, MySQL, Redis) | `resp \|\| mysql \|\| pgsql \|\| wg` |
| [`topology_cdn_anycast_bgp_quic_http3_tls_dns_origin.frasm`](topology_cdn_anycast_bgp_quic_http3_tls_dns_origin.frasm) | Anycast CDN edge PoP: BGP, GeoDNS, QUIC/HTTP3, TLS origin | `dns \|\| http2 \|\| tls \|\| quic` |
| [`topology_sase_wireguard_quic_http3_edge.frasm`](topology_sase_wireguard_quic_http3_edge.frasm) | SASE branch WireGuard mesh forwarding DNS and QUIC HTTP/3 | `dns \|\| quic \|\| wg` |
| [`topology_blockchain_validator_p2p_quic_gossip_grpc_jsonrpc.frasm`](topology_blockchain_validator_p2p_quic_gossip_grpc_jsonrpc.frasm) | Validator node NTP sync, QUIC P2P gossip, gRPC, HTTP JSON-RPC | `ntp \|\| http \|\| quic` |
| [`topology_financial_trading_ptp_fix_tcp_multicast.frasm`](topology_financial_trading_ptp_fix_tcp_multicast.frasm) | Trading venue IEEE 1588 PTP sync, market multicast, TCP order | `ptp \|\| vlan \|\| tcp \|\| udp` |
| [`topology_financial_hft_ptp_pim_igmp_udp_fix_execution.frasm`](topology_financial_hft_ptp_pim_igmp_udp_fix_execution.frasm) | Low-latency HFT PTP sync, PIM/IGMP market feed, FIX execution | `ptp \|\| igmp \|\| pim \|\| tcp` |

## WAN, Carrier, 5G & Routing Labs (15)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`topology_wan_ipsec_ikev2_esp_ah_ospf.frasm`](topology_wan_ipsec_ikev2_esp_ah_ospf.frasm) | Site-to-site IPsec VPN (IKEv2, AH, ESP), GRE, and OSPF | `gre \|\| esp \|\| ah \|\| isakmp` |
| [`topology_wan_sdwan_failover_simulation.frasm`](topology_wan_sdwan_failover_simulation.frasm) | SD-WAN circuit failover detected via BFD and SNMP alerts | `snmp \|\| tcp \|\| udp` |
| [`topology_dual_stack_wan_sdwan_failover.frasm`](topology_dual_stack_wan_sdwan_failover.frasm) | Dual-stack SD-WAN IPsec ESP tunnel health checks via BFD | `esp \|\| bfd` |
| [`topology_hybrid_cloud_ipsec_ikev2_bgp_vrrp_hsrp_ha.frasm`](topology_hybrid_cloud_ipsec_ikev2_bgp_vrrp_hsrp_ha.frasm) | Hybrid cloud direct-connect HA with VRRP, HSRP, IKEv2, ESP, BGP | `esp \|\| isakmp \|\| bgp \|\| vrrp` |
| [`topology_retail_branch_sdwan_qinq_dhcp_vrrp_ikev2_http.frasm`](topology_retail_branch_sdwan_qinq_dhcp_vrrp_ikev2_http.frasm) | Retail branch ZTP over QinQ metro, DHCP, VRRP, IKEv2, HTTP | `http \|\| isakmp \|\| vrrp` |
| [`topology_carrier_mpls_vpn_pe_ce.frasm`](topology_carrier_mpls_vpn_pe_ce.frasm) | Carrier BGP/MPLS L3VPN peering between CE and PE routers | `bgp \|\| mpls` |
| [`topology_carrier_mpls_l3vpn_lacp_lldp_ospf_bgp_bfd_frr.frasm`](topology_carrier_mpls_l3vpn_lacp_lldp_ospf_bgp_bfd_frr.frasm) | Carrier MPLS core with LLDP, LACP, OSPF, BGP, and BFD FRR | `icmp \|\| ospf \|\| bgp \|\| bfd` |
| [`topology_isp_bng_qinq_dhcp_radius_mpls.frasm`](topology_isp_bng_qinq_dhcp_radius_mpls.frasm) | ISP BNG subscriber login with QinQ, DHCP, RADIUS, and MPLS | `radius \|\| http` |
| [`topology_submarine_cable_landing_station_bgp_isis_mpls_bfd_netflow.frasm`](topology_submarine_cable_landing_station_bgp_isis_mpls_bfd_netflow.frasm) | Subsea CLS peering with eBGP multihop, MPLS, BFD, NetFlow | `cflow \|\| icmp \|\| bgp \|\| bfd` |
| [`topology_satcom_leo_ground_station_mpls_gre_ospf_bfd_snmpv3.frasm`](topology_satcom_leo_ground_station_mpls_gre_ospf_bfd_snmpv3.frasm) | LEO satellite handover combining BFD, OSPF, GRE, MPLS, SNMPv3 | `snmp \|\| gre \|\| ospf \|\| bfd` |
| [`topology_5g_sa_core_ngap_gtpu_sba.frasm`](topology_5g_sa_core_ngap_gtpu_sba.frasm) | 5G Standalone core with SCTP NGAP, HTTP/2 SBA, and VLANs | `http2 \|\| vlan \|\| udp \|\| sctp` |
| [`topology_5g_n2_n3_n4_sctp_pfcp_gtpu_upf_session.frasm`](topology_5g_n2_n3_n4_sctp_pfcp_gtpu_upf_session.frasm) | 5G PDU session setup across N2 SCTP, N4 UDP, and N3 transport | `vxlan \|\| udp \|\| sctp` |
| [`topology_multicast_iptv_pim_igmp_mld_rtsp.frasm`](topology_multicast_iptv_pim_igmp_mld_rtsp.frasm) | Dual-stack IPTV multicast across PIM-SM, IGMPv3/MLD, RTSP, RTP | `rtp \|\| rtsp \|\| igmp \|\| icmpv6` |
| [`topology_broadcast_smpte2110_ptp_igmp_pim_rtp_rtsp_multicast.frasm`](topology_broadcast_smpte2110_ptp_igmp_pim_rtp_rtsp_multicast.frasm) | Broadcast studio SMPTE ST 2110 with PTP, IGMP/PIM, RTSP, RTP | `ptp \|\| rtp \|\| rtsp \|\| igmp` |
| [`topology_automotive_tsn_ptp_vlan_someip_udp_can_gateway.frasm`](topology_automotive_tsn_ptp_vlan_someip_udp_can_gateway.frasm) | Automotive zonal TSN backbone with IEEE 802.1AS PTP and VLAN | `ptp \|\| vlan \|\| tcp \|\| udp` |

## OT, SCADA & Smart Infrastructure (10)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`ot_factory_vlan_modbus_segmentation.frasm`](ot_factory_vlan_modbus_segmentation.frasm) | Purdue VLAN 110 Modbus poll allowed vs. VLAN 200 write blocked | `(vlan.id == 110 \|\| vlan.id == 200) && modbus` |
| [`topology_industrial_scada_modbus_monitoring.frasm`](topology_industrial_scada_modbus_monitoring.frasm) | HMI Modbus/TCP polling alongside SNMP plant health traps | `snmp \|\| tcp` |
| [`topology_industrial_scada_substation.frasm`](topology_industrial_scada_substation.frasm) | Electrical substation combining Modbus, DNP3, and S7comm | `modbus \|\| dnp3 \|\| s7comm` |
| [`topology_substation_iec62443_modbus_dnp3_s7comm_opcua_syslog.frasm`](topology_substation_iec62443_modbus_dnp3_s7comm_opcua_syslog.frasm) | IEC 62443 substation zones with Modbus, DNP3, S7comm, OPC UA | `syslog \|\| modbus \|\| dnp3 \|\| s7comm` |
| [`topology_purdue_ics_s7comm_eip_opcua.frasm`](topology_purdue_ics_s7comm_eip_opcua.frasm) | Purdue Levels 1–3 factory combining S7comm, EtherNet/IP, OPC UA | `s7comm \|\| enip \|\| opcua \|\| vlan` |
| [`topology_airport_baggage_plc_ethernetip_s7comm_opcua_snmpv2c.frasm`](topology_airport_baggage_plc_ethernetip_s7comm_opcua_snmpv2c.frasm) | Airport BHS PLCs running EtherNet/IP, S7comm, OPC UA, SNMPv2c | `snmp \|\| s7comm \|\| enip \|\| opcua` |
| [`topology_smart_grid_derms_dnp3_modbus_bacnet_ntp_ipfix.frasm`](topology_smart_grid_derms_dnp3_modbus_bacnet_ntp_ipfix.frasm) | Smart grid DERMS combining NTP, DNP3, Modbus, BACnet, IPFIX | `ntp \|\| cflow \|\| modbus \|\| bacnet` |
| [`topology_smart_building_bacnet_coap_mqtt.frasm`](topology_smart_building_bacnet_coap_mqtt.frasm) | Smart building HVAC automation using BACnet/IP, CoAP, and MQTT | `mqtt \|\| coap \|\| whois \|\| bacnet` |
| [`topology_iot_fleet_mqtt_coap_ntp_tls_redis_timeseries.frasm`](topology_iot_fleet_mqtt_coap_ntp_tls_redis_timeseries.frasm) | Industrial IoT telemetry via NTP, CoAP, MQTT over TLS, Redis | `ntp \|\| tls \|\| resp \|\| mqtt` |
| [`topology_autonomous_vehicle_v2x_ptp_ipv6_ndp_udp_mqtt.frasm`](topology_autonomous_vehicle_v2x_ptp_ipv6_ndp_udp_mqtt.frasm) | V2X roadside unit IPv6 NDP, PTP timing, UDP, and MQTT alerts | `ptp \|\| mqtt \|\| icmpv6 \|\| udp` |

## IPv4/IPv6 Addressing, Multicast & QoS Controls (23)

| Scenario | What It Demonstrates | Wireshark Filter |
| :--- | :--- | :--- |
| [`ipv4_multicast_mac_all_hosts.frasm`](ipv4_multicast_mac_all_hosts.frasm) | Auto-derived RFC 1112 MAC `01:00:5e:00:00:01` (`224.0.0.1`) | `udp` |
| [`ipv4_multicast_mac_mdns.frasm`](ipv4_multicast_mac_mdns.frasm) | IPv4 mDNS multicast (`224.0.0.251` -> `01:00:5e:00:00:fb`) | `udp.port == 5353` |
| [`ipv4_multicast_mac_ssdp.frasm`](ipv4_multicast_mac_ssdp.frasm) | IPv4 SSDP multicast (`239.255.255.250` -> `01:00:5e:7f:ff:fa`) | `ssdp` |
| [`ipv4_multicast_mac_vrrp.frasm`](ipv4_multicast_mac_vrrp.frasm) | IPv4 VRRP multicast (`224.0.0.18` -> `01:00:5e:00:00:12`) | `vrrp` |
| [`ipv6_compressed_zero_variations.frasm`](ipv6_compressed_zero_variations.frasm) | Leading, middle, and trailing `::` IPv6 compression formats | `ipv6 && udp` |
| [`ipv6_global_unicast_2001_db8.frasm`](ipv6_global_unicast_2001_db8.frasm) | RFC 3849 global unicast `2001:db8::/32` documentation prefix | `tcp.port == 80` |
| [`ipv6_ipv4_mapped_address.frasm`](ipv6_ipv4_mapped_address.frasm) | RFC 4291 IPv4-mapped IPv6 `::ffff:a.b.c.d` format | `ipv6 && udp` |
| [`ipv6_link_local_fe80.frasm`](ipv6_link_local_fe80.frasm) | Link-local IPv6 `fe80::/10` peer communication | `ipv6 && udp` |
| [`ipv6_loopback_and_unspecified.frasm`](ipv6_loopback_and_unspecified.frasm) | IPv6 `::1` loopback and `::` unspecified edge handling | `ipv6 && udp` |
| [`ipv6_multicast_global_ff0e.frasm`](ipv6_multicast_global_ff0e.frasm) | Global IPv6 multicast `ff0e::101` RFC 2464 MAC derivation | `udp.port == 5004` |
| [`ipv6_multicast_mac_all_nodes.frasm`](ipv6_multicast_mac_all_nodes.frasm) | All-nodes IPv6 multicast `ff02::1` (`33:33:00:00:00:01`) | `ipv6 && udp` |
| [`ipv6_multicast_mac_all_routers.frasm`](ipv6_multicast_mac_all_routers.frasm) | All-routers IPv6 multicast `ff02::2` (`33:33:00:00:00:02`) | `ipv6 && udp` |
| [`ipv6_multicast_site_local_dhcpv6.frasm`](ipv6_multicast_site_local_dhcpv6.frasm) | DHCPv6 server site-local multicast `ff05::1:3` | `udp.port == 547` |
| [`ipv6_multicast_solicited_node.frasm`](ipv6_multicast_solicited_node.frasm) | Solicited-node multicast `ff02::1:ff00:1234` (`33:33:ff:00:12:34`) | `ipv6 && udp` |
| [`l3_dscp_network_control_scavenger.frasm`](l3_dscp_network_control_scavenger.frasm) | DSCP CS6/CS7 control and CS1 scavenger QoS classes | `udp` |
| [`l3_dscp_signaling_and_bulk_data.frasm`](l3_dscp_signaling_and_bulk_data.frasm) | DSCP AF31 signaling, AF21 low-latency, and AF11 bulk queues | `udp` |
| [`l3_dscp_voice_video_ef_af41.frasm`](l3_dscp_voice_video_ef_af41.frasm) | DSCP EF (`46`) voice and AF41 (`34`) video QoS marking | `udp.port == 5004` |
| [`l3_ecn_and_ip_fragmentation.frasm`](l3_ecn_and_ip_fragmentation.frasm) | ECN codepoints (`ect0`, `ce`) and IPv4 `df`, `mf`, `fragoffset` | `udp` |
| [`l3_flowlabel_boundary_values.frasm`](l3_flowlabel_boundary_values.frasm) | IPv6 20-bit flow label boundary tests (`0` and `1048575`) | `ipv6 && udp` |
| [`l3_flowlabel_ecmp_multipath_hashing.frasm`](l3_flowlabel_ecmp_multipath_hashing.frasm) | Diverse IPv6 flow labels for ECMP LAG/equal-cost hashing | `ipv6 && udp` |
| [`l3_flowlabel_ipv4_silent_ignore.frasm`](l3_flowlabel_ipv4_silent_ignore.frasm) | Shared flow with `flowlabel` ignored cleanly on IPv4 runs | `udp` |
| [`l3_ttl_bgp_gtsm_and_zero_edge.frasm`](l3_ttl_bgp_gtsm_and_zero_edge.frasm) | BGP GTSM `ttl 255` security and `ttl 0` boundary edge case | `tcp.port == 179` |
| [`l3_ttl_hop_limits_traceroute.frasm`](l3_ttl_hop_limits_traceroute.frasm) | Traceroute hop-by-hop expiry using `ttl 1`, `ttl 2`, `ttl 3` | `udp.port == 33434` |
