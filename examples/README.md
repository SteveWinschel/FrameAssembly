# FrameAssembly Example Scenarios

[← Main README](../README.md) • [Docs Index](../docs/README.md) • [Use-Case Cookbook](../docs/02_use_cases.md)

This folder holds the `.frasm` scenario files that ship with FrameAssembly, grouped by layer and protocol (`l2/`, `l3/`, `l4/`, `l7/`) plus multi-host `topologies/`. Every file compiles as-is and includes realistic Wireshark display filters right in the header comments.

New in v3.1.0: every one of the 81 protocols now includes a minimal 2-block `<proto>_default_frame.frasm` starter (`host` + `compile`, zero `flow` wrapper) alongside dozens of multi-packet scenarios.

Try any scenario from the repository root:

```console
$ frameassembly show examples/l4/tcp/tcp_default_frame.frasm
$ frameassembly show examples/l7/tls/tls_client_hello_sni_alpn.frasm
$ frameassembly examples/topologies/branch_snmp_syslog_firewall_audit.frasm temp/branch_audit.pcap
```

## Browse by Layer

| Folder | Coverage | Highlight Starting Point |
| :--- | :--- | :--- |
| [**`l2/`**](l2/README.md) | 8 Layer 2 protocols (`arp`, `eapol`, `lacp`, `lldp`, `mpls`, `qinq`, `stp`, `vlan`) | [`l2/vlan/vlan_default_frame.frasm`](l2/vlan/vlan_default_frame.frasm) |
| [**`l3/`**](l3/README.md) | 20 Layer 3 routing, tunnel, VPN, multicast, and discovery protocols | [`l3/bgp/bgp_default_frame.frasm`](l3/bgp/bgp_default_frame.frasm) |
| [**`l4/`**](l4/README.md) | 3 Layer 4 transports (`tcp`, `udp`, `sctp`) | [`l4/tcp/tcp_default_frame.frasm`](l4/tcp/tcp_default_frame.frasm) |
| [**`l7/`**](l7/README.md) | 50 Layer 7 monitoring, infrastructure, web, auth, DB, and OT protocols | [`l7/snmp/snmpv3/snmp3_default_frame.frasm`](l7/snmp/snmpv3/snmp3_default_frame.frasm) |
| [**`topologies/`**](topologies/README.md) | 106 multi-host enterprise, DC, WAN, zero-trust, OT, IPv6, and QoS labs | [`topologies/branch_snmp_syslog_firewall_audit.frasm`](topologies/branch_snmp_syslog_firewall_audit.frasm) |

## Monitoring and SNMPv3 (Checkmk, Zabbix, PRTG)

Trap storms, encrypted polls, and alerts that should page your on-call engineer.

| Scenario file | What it shows |
| :--- | :--- |
| [`l7/snmp/snmpv3/snmpv3_auth_sha256_priv_aes_trap.frasm`](l7/snmp/snmpv3/snmpv3_auth_sha256_priv_aes_trap.frasm) | Encrypted `authPriv` trap using SHA-256 and AES |
| [`l7/snmp/snmpv3/snmpv3_auth_sha256_priv_aes_get_response.frasm`](l7/snmp/snmpv3/snmpv3_auth_sha256_priv_aes_get_response.frasm) | Authenticated, encrypted get with its response |
| [`l7/snmp/snmpv3/snmpv3_auth_sha1_nopriv_getbulk_interfaces.frasm`](l7/snmp/snmpv3/snmpv3_auth_sha1_nopriv_getbulk_interfaces.frasm) | Interface table poll with `getbulk` |
| [`l7/snmp/snmpv3/snmpv3_auth_md5_priv_des_trap.frasm`](l7/snmp/snmpv3/snmpv3_auth_md5_priv_des_trap.frasm) | Legacy MD5 and DES trap for older gear |
| [`topologies/snmp_tri_version_coexistence_audit.frasm`](topologies/snmp_tri_version_coexistence_audit.frasm) | SNMPv1, v2c and v3 side by side in one capture |
| [`topologies/branch_snmp_syslog_firewall_audit.frasm`](topologies/branch_snmp_syslog_firewall_audit.frasm) | SSH block followed by RFC 5424 syslog alert and SNMPv3 SHA-256 trap |
| [`l7/syslog/syslog_all_eight_severity_levels.frasm`](l7/syslog/syslog_all_eight_severity_levels.frasm) | One syslog event per severity level |

## Firewall, VLAN and Segmentation

Stateful rules, trunks, and what should be dropped.

| Scenario file | What it shows |
| :--- | :--- |
| [`l4/tcp/tcp_default_frame.frasm`](l4/tcp/tcp_default_frame.frasm) | Minimal 2-block TCP SYN starter (`host` + `compile`, zero `flow`) |
| [`l4/tcp/tcp_3_way_handshake.frasm`](l4/tcp/tcp_3_way_handshake.frasm) | Complete handshake with automatic sequence numbers |
| [`l4/tcp/tcp_firewall_acl_blocked_port_scan.frasm`](l4/tcp/tcp_firewall_acl_blocked_port_scan.frasm) | Mixed ACL probe: HTTPS allow, Telnet RST, silent drop, ICMP block |
| [`l4/tcp/tcp_closed_port_rst_ack_rejection.frasm`](l4/tcp/tcp_closed_port_rst_ack_rejection.frasm) | Closed port answered with RST and ACK |
| [`l4/tcp/tcp_ack_firewall_rule_probe.frasm`](l4/tcp/tcp_ack_firewall_rule_probe.frasm) | ACK probe against a stateful rule set |
| [`l2/vlan/vlan_basic_access_tag.frasm`](l2/vlan/vlan_basic_access_tag.frasm) | Single 802.1Q tag on an access port |
| [`l2/vlan/vlan_boundary_max_4094_trunk.frasm`](l2/vlan/vlan_boundary_max_4094_trunk.frasm) | Highest legal VLAN ID on a trunk |
| [`l2/qinq/qinq_carrier_double_tag_trunk.frasm`](l2/qinq/qinq_carrier_double_tag_trunk.frasm) | Dual-stack S-VLAN + C-VLAN trunk carrying HTTPS and DNS |
| [`l2/qinq/qinq_metro_ethernet_dual_stack.frasm`](l2/qinq/qinq_metro_ethernet_dual_stack.frasm) | Provider double tags carrying IPv4 and IPv6 |
| [`topologies/topology_dmz_firewall_intrusion_alert.frasm`](topologies/topology_dmz_firewall_intrusion_alert.frasm) | DMZ traffic that ends in an intrusion alert |

## IDS, NDR and Shadow IT Detection

Captures for Suricata, Zeek and Snort rule testing.

| Scenario file | What it shows |
| :--- | :--- |
| [`l7/tls/tls_client_hello_sni_alpn.frasm`](l7/tls/tls_client_hello_sni_alpn.frasm) | TLS hello with a server name and ALPN list |
| [`l7/tls/tls_sni_unrecognized_name_alert.frasm`](l7/tls/tls_sni_unrecognized_name_alert.frasm) | Server rejects an unknown SNI with an alert |
| [`l7/dns/dns_nxdomain_rcode3_error.frasm`](l7/dns/dns_nxdomain_rcode3_error.frasm) | NXDOMAIN reply for a suspicious lookup |
| [`l7/ssdp/ssdp_and_whois_discovery.frasm`](l7/ssdp/ssdp_and_whois_discovery.frasm) | UPnP discovery plus WHOIS in one run |
| [`l4/tcp/tcp_fin_stealth_scan.frasm`](l4/tcp/tcp_fin_stealth_scan.frasm) | FIN scan pattern for scan-detection rules |
| [`l4/udp/udp_dns_ntp_syslog_soc_baseline.frasm`](l4/udp/udp_dns_ntp_syslog_soc_baseline.frasm) | Compact DNS, NTP, and Syslog SIEM baseline |
| [`topologies/topology_secops_honeypot_telnet_ftp_smb_whois_syslog_snmpv3.frasm`](topologies/topology_secops_honeypot_telnet_ftp_smb_whois_syslog_snmpv3.frasm) | Honeypot touched over several protocols |

## Routing, Data Center and EVPN

Control-plane traffic for labs you do not want to build.

| Scenario file | What it shows |
| :--- | :--- |
| [`l3/bgp/bgp_blackhole_community_rtbh_trigger.frasm`](l3/bgp/bgp_blackhole_community_rtbh_trigger.frasm) | BGP blackhole community trigger |
| [`l3/bgp/bgp4_ipv6_peering.frasm`](l3/bgp/bgp4_ipv6_peering.frasm) | BGP session over IPv6 |
| [`l3/ospf/ospf_full_adjacency_five_packet_types.frasm`](l3/ospf/ospf_full_adjacency_five_packet_types.frasm) | All five OSPF packet types in order |
| [`l3/vxlan/vxlan_arp_suppression_evpn_proxy_reply.frasm`](l3/vxlan/vxlan_arp_suppression_evpn_proxy_reply.frasm) | EVPN proxy ARP reply inside VXLAN |
| [`topologies/topology_datacenter_vxlan_evpn_underlay.frasm`](topologies/topology_datacenter_vxlan_evpn_underlay.frasm) | Leaf and spine VXLAN underlay |
| [`topologies/topology_campus_fhrp_vrrp_hsrp_stp_arp.frasm`](topologies/topology_campus_fhrp_vrrp_hsrp_stp_arp.frasm) | Campus gateway redundancy and spanning tree |

## OT and SCADA

Industrial protocols for conduit and policy checks.

| Scenario file | What it shows |
| :--- | :--- |
| [`l7/modbus/modbus_default_frame.frasm`](l7/modbus/modbus_default_frame.frasm) | Smallest Modbus/TCP request |
| [`topologies/ot_factory_vlan_modbus_segmentation.frasm`](topologies/ot_factory_vlan_modbus_segmentation.frasm) | Purdue VLAN 110 Modbus allow vs. VLAN 200 write blocked |
| [`l7/dnp3/dnp3_analog_output_select_before_operate_group41.frasm`](l7/dnp3/dnp3_analog_output_select_before_operate_group41.frasm) | Select-before-operate analog output |
| [`l7/bacnet/bacnet_read_property_analog_input.frasm`](l7/bacnet/bacnet_read_property_analog_input.frasm) | BACnet ReadProperty on an analog input |
| [`l7/ethernetip/ethernetip_register_session.frasm`](l7/ethernetip/ethernetip_register_session.frasm) | EtherNet/IP session registration |
| [`l7/opcua/opcua_browse_address_space_objects_folder.frasm`](l7/opcua/opcua_browse_address_space_objects_folder.frasm) | OPC UA browse of the Objects folder |
| [`topologies/topology_industrial_scada_substation.frasm`](topologies/topology_industrial_scada_substation.frasm) | Substation with several OT protocols |

## Where Each Scenario Fits

* Monitoring tools: replay the SNMP and syslog captures at your collector and check that alerts fire.
* Firewalls: compile the TCP and VLAN files, replay them through the device, and compare what comes out the other side.
* Detection engineering: feed the TLS, DNS and scan captures to `suricata -r` or Zeek and review the logs.
* Routing labs: use the BGP, OSPF and VXLAN files to check dissectors or monitoring before touching production.
* OT: replay the Modbus, DNP3 and OPC UA files across a SPAN port to validate conduit rules.

Need a different protocol? The [protocol lookup table](../docs/README.md#find-a-protocol-all-81) lists one example statement for every supported protocol, and each protocol folder here contains dozens of variations.
