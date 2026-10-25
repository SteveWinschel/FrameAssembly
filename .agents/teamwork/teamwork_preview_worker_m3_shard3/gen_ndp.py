#!/usr/bin/env python3
"""Generate 12 new verified NDP examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/ndp/ndp_dad_duplicate_address_detection.fasm": """// PROMPT: IPv6 Duplicate Address Detection (DAD) Neighbor Solicitation verifying address uniqueness.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, NEIGHBOR_SOLICIT, TARGET, COMPILE

// INSTRUCTION: Define bootstrapping host initiating DAD probe.
HOST dad_probing_node { IP fe80::dad:1 MAC 00:50:56:00:da:01 }

// INSTRUCTION: Define solicited-node multicast destination for candidate address.
HOST dad_solicited_node { IP ff02::1:ff34:5678 MAC 33:33:ff:34:56:78 }

// INSTRUCTION: Define DAD Neighbor Solicitation packet targeting candidate IPv6 2001:db8::3456:78.
FLOW dad_probe_flow(src, dst) {
    src -> dst NDP NEIGHBOR_SOLICIT TARGET 2001:db8::3456:78
}

// INSTRUCTION: Compile block executing DAD verification probe.
COMPILE {
    dad_probe_flow(dad_probing_node, dad_solicited_node)
}
""",

    "examples/l3/ndp/ndp_router_advert_prefix_information.fasm": """// PROMPT: IPv6 Router Advertisement publishing default router lifetime and reachability parameters.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, ROUTER_ADVERT, ROUTER_LIFETIME, SLLA, COMPILE

// INSTRUCTION: Define default gateway advertising network presence.
HOST edge_ra_router { IP fe80::1 MAC 00:1c:73:00:00:01 }

// INSTRUCTION: Define all-nodes multicast address.
HOST all_ipv6_nodes { IP ff02::1 MAC 33:33:00:00:00:01 }

// INSTRUCTION: Define Router Advertisement flow with 1800 second lifetime and SLLA option.
FLOW router_advert_flow(gw, nodes) {
    gw -> nodes NDP ROUTER_ADVERT ROUTER_LIFETIME 1800 SLLA 00:1c:73:00:00:01
}

// INSTRUCTION: Compile block executing periodic Router Advertisement.
COMPILE {
    router_advert_flow(edge_ra_router, all_ipv6_nodes)
}
""",

    "examples/l3/ndp/ndp_gratuitous_neighbor_advertisement.fasm": """// PROMPT: Unsolicited gratuitous Neighbor Advertisement announcing updated target link-layer address.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, NEIGHBOR_ADVERT, TARGET, TLLA, COMPILE

// INSTRUCTION: Define virtual machine completing live migration with new MAC address.
HOST migrated_vm_node { IP fe80::a00:20ff:fe1e:50a2 MAC 00:50:56:99:88:77 }

// INSTRUCTION: Define all-nodes broadcast listener.
HOST all_nodes_mcast { IP ff02::1 MAC 33:33:00:00:00:01 }

// INSTRUCTION: Define unsolicited gratuitous NA broadcasting updated link-layer binding.
FLOW gratuitous_na_flow(vm, all) {
    vm -> all NDP NEIGHBOR_ADVERT TARGET 2001:db8:1::100 TLLA 00:50:56:99:88:77
}

// INSTRUCTION: Compile block transmitting gratuitous Neighbor Advertisement.
COMPILE {
    gratuitous_na_flow(migrated_vm_node, all_nodes_mcast)
}
""",

    "examples/l3/ndp/ndp_vlan_tagged_host_solicitation.fasm": """// PROMPT: 802.1Q tagged Neighbor Solicitation and Advertisement on enterprise access VLAN 100.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, NDP, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, TARGET, SLLA, TLLA, VLAN, COMPILE

// INSTRUCTION: Define enterprise accounting workstation on VLAN 100.
HOST acct_workstation { IP fe80::ac:10 MAC 00:25:90:11:22:33 }

// INSTRUCTION: Define local department server on VLAN 100.
HOST acct_fileserver { IP fe80::ac:20 MAC 00:25:90:44:55:66 }

// INSTRUCTION: Define 802.1Q tagged NDP resolution flow.
FLOW vlan_ndp_resolution(ws, srv) {
    ws -> srv NDP NEIGHBOR_SOLICIT TARGET 2001:db8:100::20 SLLA 00:25:90:11:22:33 VLAN 100
    ws <- srv NDP NEIGHBOR_ADVERT TARGET 2001:db8:100::20 TLLA 00:25:90:44:55:66 VLAN 100
}

// INSTRUCTION: Compile block executing VLAN tagged NDP exchange.
COMPILE {
    vlan_ndp_resolution(acct_workstation, acct_fileserver)
}
""",

    "examples/l3/ndp/ndp_qinq_metro_subscriber_discovery.fasm": """// PROMPT: Dual-tagged QinQ Neighbor Advertisement traversing broadband metro access ring.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, NEIGHBOR_ADVERT, TARGET, TLLA, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define metro subscriber optical network unit (ONU).
HOST metro_subscriber_onu { IP fe80::0001 MAC 00:1e:67:aa:bb:cc }

// INSTRUCTION: Define provider broadband network gateway.
HOST provider_bng_gw { IP ff02::1 MAC 33:33:00:00:00:01 }

// INSTRUCTION: Define QinQ encapsulated Neighbor Advertisement flow.
FLOW qinq_ndp_flow(onu, bng) {
    onu -> bng NDP NEIGHBOR_ADVERT TARGET 2001:db8:cafe::10 TLLA 00:1e:67:aa:bb:cc QINQ 500 INNER_VLAN 102
}

// INSTRUCTION: Compile block executing QinQ Neighbor Advertisement.
COMPILE {
    qinq_ndp_flow(metro_subscriber_onu, provider_bng_gw)
}
""",

    "examples/l3/ndp/ndp_mpls_transport_neighbor_resolution.fasm": """// PROMPT: NDP resolution packet encapsulated across MPLS label switched path with label 300.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, NEIGHBOR_SOLICIT, TARGET, SLLA, MPLS, COMPILE

// INSTRUCTION: Define ingress label edge router.
HOST mpls_ler_node { IP fe80::101 MAC 00:1f:6d:10:01:01 }

// INSTRUCTION: Define egress router destination.
HOST mpls_egress_dst { IP ff02::1:ff00:2 MAC 33:33:ff:00:00:02 }

// INSTRUCTION: Define MPLS encapsulated Neighbor Solicitation flow.
FLOW mpls_ndp_flow(ler, dst) {
    ler -> dst NDP NEIGHBOR_SOLICIT TARGET 2001:db8:99::2 SLLA 00:1f:6d:10:01:01 MPLS 300
}

// INSTRUCTION: Compile block executing MPLS transported NDP discovery.
COMPILE {
    mpls_ndp_flow(mpls_ler_node, mpls_egress_dst)
}
""",

    "examples/l3/ndp/ndp_hoplimit_strict_enforcement.fasm": """// PROMPT: Router Solicitation with strict IPv6 Hop Limit 255 verification per RFC 4861.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, ROUTER_SOLICIT, SLLA, TTL, COMPILE

// INSTRUCTION: Define newly attached IPv6 client device.
HOST unconfigured_client { IP fe80::707:1 MAC 00:14:22:77:88:99 }

// INSTRUCTION: Define all-routers multicast destination ff02::2.
HOST all_routers_dst { IP ff02::2 MAC 33:33:00:00:00:02 }

// INSTRUCTION: Define Router Solicitation ensuring strict TTL 255 per specification.
FLOW router_solicit_strict_ttl(client, rtrs) {
    client -> rtrs NDP ROUTER_SOLICIT SLLA 00:14:22:77:88:99 TTL 255
}

// INSTRUCTION: Compile block executing strict TTL Router Solicitation.
COMPILE {
    router_solicit_strict_ttl(unconfigured_client, all_routers_dst)
}
""",

    "examples/l3/ndp/ndp_looped_keepalive_neighbor_polling.fasm": """// PROMPT: Periodic Neighbor Solicitation keepalive burst inside a COMPILE LOOP.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, NEIGHBOR_SOLICIT, TARGET, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define health monitor checking host reachability.
HOST health_monitor_node { IP fe80::beef:10 MAC 00:0c:29:11:22:33 }

// INSTRUCTION: Define monitored database host.
HOST monitored_db_node { IP fe80::beef:20 MAC 00:0c:29:44:55:66 }

// INSTRUCTION: Define periodic reachability probe flow.
FLOW ndp_reachability_probe(mon, db) {
    mon -> db NDP NEIGHBOR_SOLICIT TARGET 2001:db8:88::20 WAIT 15ms
}

// INSTRUCTION: Compile loop executing 5 reachability confirmation queries.
COMPILE {
    LOOP 5 {
        ndp_reachability_probe(health_monitor_node, monitored_db_node)
    }
}
""",

    "examples/l3/ndp/ndp_dscp_control_plane_advertisement.fasm": """// PROMPT: Router Advertisement marked with Network Control DSCP Class Selector 6.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, ROUTER_ADVERT, ROUTER_LIFETIME, DSCP, COMPILE

// INSTRUCTION: Define enterprise aggregation gateway router.
HOST agg_gw_router { IP fe80::ac01:1 MAC 00:26:88:aa:11:01 }

// INSTRUCTION: Define link-local all-nodes multicast address.
HOST all_link_nodes { IP ff02::1 MAC 33:33:00:00:00:01 }

// INSTRUCTION: Define control plane prioritized Router Advertisement flow.
FLOW ra_control_plane_flow(gw, nodes) {
    gw -> nodes NDP ROUTER_ADVERT ROUTER_LIFETIME 3600 DSCP 48
}

// INSTRUCTION: Compile block transmitting prioritized Router Advertisement.
COMPILE {
    ra_control_plane_flow(agg_gw_router, all_link_nodes)
}
""",

    "examples/l3/ndp/ndp_data_center_tor_neighbor_exchange.fasm": """// PROMPT: Top-of-Rack leaf switch resolving spine switch IPv6 neighbor cache entry.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, NDP, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, TARGET, SLLA, TLLA, COMPILE

// INSTRUCTION: Define Data Center Leaf 1 switch.
HOST leaf_sw_1 { IP fe80::1001 MAC 52:54:00:10:01:01 }

// INSTRUCTION: Define Data Center Spine 1 switch.
HOST spine_sw_1 { IP fe80::2001 MAC 52:54:00:20:01:01 }

// INSTRUCTION: Define fabric point-to-point NDP resolution flow.
FLOW dc_fabric_ndp_exchange(leaf, spine) {
    leaf -> spine NDP NEIGHBOR_SOLICIT TARGET 2001:db8:dc::2001 SLLA 52:54:00:10:01:01
    leaf <- spine NDP NEIGHBOR_ADVERT TARGET 2001:db8:dc::2001 TLLA 52:54:00:20:01:01
}

// INSTRUCTION: Compile block executing data center fabric neighbor discovery.
COMPILE {
    dc_fabric_ndp_exchange(leaf_sw_1, spine_sw_1)
}
""",

    "examples/l3/ndp/ndp_wireless_roaming_neighbor_update.fasm": """// PROMPT: Roaming tablet asserting presence on enterprise wireless controller via Neighbor Advertisement.
// TOKENS: HOST, IP, MAC, FLOW, ->, NDP, NEIGHBOR_ADVERT, TARGET, TLLA, COMPILE

// INSTRUCTION: Define corporate roaming tablet.
HOST roaming_tablet_device { IP fe80::7b1:1 MAC b8:27:eb:11:22:33 }

// INSTRUCTION: Define wireless LAN controller default router.
HOST wlan_controller_gw { IP ff02::1 MAC 33:33:00:00:00:01 }

// INSTRUCTION: Define wireless handoff Neighbor Advertisement flow.
FLOW wireless_roaming_na(client, wlc) {
    client -> wlc NDP NEIGHBOR_ADVERT TARGET 2001:db8:feed::50 TLLA b8:27:eb:11:22:33
}

// INSTRUCTION: Compile block executing wireless roaming advertisement.
COMPILE {
    wireless_roaming_na(roaming_tablet_device, wlan_controller_gw)
}
""",

    "examples/l3/ndp/ndp_secure_link_local_gateway_reachability.fasm": """// PROMPT: Secure IPv6 link-local gateway address resolution with full SLLA and TLLA validation.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, NDP, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, TARGET, SLLA, TLLA, COMPILE

// INSTRUCTION: Define secure enclave client workstation.
HOST enclave_client_host { IP fe80::e01:10 MAC 00:08:74:aa:bb:01 }

// INSTRUCTION: Define security boundary link-local gateway.
HOST enclave_boundary_gw { IP fe80::e01:1 MAC 00:08:74:aa:bb:fe }

// INSTRUCTION: Define secure link-local resolution handshake.
FLOW enclave_ndp_handshake(cli, gw) {
    cli -> gw NDP NEIGHBOR_SOLICIT TARGET fe80::e01:1 SLLA 00:08:74:aa:bb:01
    cli <- gw NDP NEIGHBOR_ADVERT TARGET fe80::e01:1 TLLA 00:08:74:aa:bb:fe
}

// INSTRUCTION: Compile block executing enclave neighbor discovery.
COMPILE {
    enclave_ndp_handshake(enclave_client_host, enclave_boundary_gw)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 NDP files generated and verified successfully.")
