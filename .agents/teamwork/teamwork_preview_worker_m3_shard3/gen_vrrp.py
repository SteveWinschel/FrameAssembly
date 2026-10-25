#!/usr/bin/env python3
"""Generate 12 new verified VRRP examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/vrrp/vrrp_preemption_high_priority_master.fasm": """// PROMPT: VRRP master router asserting preemption with high priority 254 and VIP 10.1.1.1 on VRID 10.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, COMPILE

// INSTRUCTION: Define primary core gateway router with preemption priority 254.
HOST vrrp_primary_master { IP 10.1.1.254 }

// INSTRUCTION: Define standard VRRP multicast listener address 224.0.0.18.
HOST vrrp_mcast_group { IP 224.0.0.18 }

// INSTRUCTION: Define high priority VRRP master advertisement flow.
FLOW vrrp_preempt_flow(master, dst) {
    master -> dst VRRP VRID 10 PRIORITY 254 VIP 10.1.1.1
}

// INSTRUCTION: Compile block executing master preemption advertisement.
COMPILE {
    vrrp_preempt_flow(vrrp_primary_master, vrrp_mcast_group)
}
""",

    "examples/l3/vrrp/vrrp_backup_low_priority_heartbeat.fasm": """// PROMPT: VRRP backup gateway monitoring virtual router with low priority 50 on VRID 10.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, COMPILE

// INSTRUCTION: Define secondary backup gateway router.
HOST vrrp_secondary_backup { IP 10.1.1.253 }

// INSTRUCTION: Define VRRP multicast destination.
HOST vrrp_mcast_dest { IP 224.0.0.18 }

// INSTRUCTION: Define low priority backup heartbeat advertisement flow.
FLOW vrrp_backup_flow(backup, dst) {
    backup -> dst VRRP VRID 10 PRIORITY 50 VIP 10.1.1.1
}

// INSTRUCTION: Compile block executing backup router heartbeat.
COMPILE {
    vrrp_backup_flow(vrrp_secondary_backup, vrrp_mcast_dest)
}
""",

    "examples/l3/vrrp/vrrp_subsecond_fast_failover_interval.fasm": """// PROMPT: Aggressive fast failover VRRP tuning with 20 centisecond (200ms) advertisement interval.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, ADV_INT, VIP, COMPILE

// INSTRUCTION: Define high availability fast failover router.
HOST ha_fast_router { IP 172.16.50.254 }

// INSTRUCTION: Define standard VRRP multicast group.
HOST vrrp_fast_mcast { IP 224.0.0.18 }

// INSTRUCTION: Define sub-second advertisement interval flow with ADV_INT 20.
FLOW vrrp_fast_timer(rtr, dst) {
    rtr -> dst VRRP VRID 25 PRIORITY 220 ADV_INT 20 VIP 172.16.50.1
}

// INSTRUCTION: Compile block executing fast failover VRRP advertisement.
COMPILE {
    vrrp_fast_timer(ha_fast_router, vrrp_fast_mcast)
}
""",

    "examples/l3/vrrp/vrrp_ipv6_vrrpv3_master_advertisement.fasm": """// PROMPT: Pure IPv6 VRRPv3 master router advertising virtual IPv6 gateway to ff02::12.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, COMPILE

// INSTRUCTION: Define IPv6 VRRPv3 master router on link-local interface.
HOST vrrp3_v6_master { IP fe80::100:1 }

// INSTRUCTION: Define IPv6 VRRP all-routers multicast address ff02::12.
HOST vrrp3_v6_mcast { IP ff02::12 }

// INSTRUCTION: Define IPv6 VRRPv3 master advertisement flow with virtual link-local VIP.
FLOW vrrp3_v6_advert_flow(master, dst) {
    master -> dst VRRP VRID 1 PRIORITY 200 VIP fe80::1
}

// INSTRUCTION: Compile block executing IPv6 VRRPv3 master advertisement.
COMPILE {
    vrrp3_v6_advert_flow(vrrp3_v6_master, vrrp3_v6_mcast)
}
""",

    "examples/l3/vrrp/vrrp_ipv6_vrrpv3_backup_failover.fasm": """// PROMPT: IPv6 VRRPv3 backup node transmitting takeover advertisement during failover.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, COMPILE

// INSTRUCTION: Define IPv6 secondary backup node taking over active master role.
HOST vrrp3_v6_backup { IP fe80::100:2 }

// INSTRUCTION: Define IPv6 VRRP multicast destination.
HOST vrrp3_all_nodes { IP ff02::12 }

// INSTRUCTION: Define failover takeover advertisement flow with Priority 150.
FLOW vrrp3_failover_flow(backup, dst) {
    backup -> dst VRRP VRID 1 PRIORITY 150 VIP fe80::1
}

// INSTRUCTION: Compile block executing IPv6 VRRPv3 backup takeover.
COMPILE {
    vrrp3_failover_flow(vrrp3_v6_backup, vrrp3_all_nodes)
}
""",

    "examples/l3/vrrp/vrrp_vlan_tagged_virtual_gateway.fasm": """// PROMPT: 802.1Q tagged VRRP master advertisement transmitting on voice VLAN 120.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define voice gateway router.
HOST voice_gw_router { IP 10.120.1.254 }

// INSTRUCTION: Define voice VLAN VRRP multicast destination.
HOST voice_vrrp_mcast { IP 224.0.0.18 }

// INSTRUCTION: Define VLAN 120 tagged VRRP advertisement flow with high priority PCP.
FLOW vrrp_voice_vlan_flow(gw, dst) {
    gw -> dst VRRP VRID 12 PRIORITY 180 VIP 10.120.1.1 VLAN 120 PCP 6 DEI 0
}

// INSTRUCTION: Compile block executing VLAN tagged VRRP advertisement.
COMPILE {
    vrrp_voice_vlan_flow(voice_gw_router, voice_vrrp_mcast)
}
""",

    "examples/l3/vrrp/vrrp_qinq_metro_resilience_advertisement.fasm": """// PROMPT: Carrier Ethernet dual-tagged QinQ VRRP heartbeat across redundant uplinks.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define metro edge access gateway.
HOST metro_edge_gw { IP 192.168.100.254 }

// INSTRUCTION: Define carrier provider edge listener.
HOST carrier_pe_listener { IP 224.0.0.18 }

// INSTRUCTION: Define QinQ encapsulated VRRP heartbeat flow on service VLAN 900 and customer VLAN 45.
FLOW vrrp_qinq_flow(gw, pe) {
    gw -> pe VRRP VRID 45 PRIORITY 150 VIP 192.168.100.1 QINQ 900 INNER_VLAN 45
}

// INSTRUCTION: Compile block executing carrier QinQ VRRP heartbeat.
COMPILE {
    vrrp_qinq_flow(metro_edge_gw, carrier_pe_listener)
}
""",

    "examples/l3/vrrp/vrrp_mpls_core_redundancy_heartbeat.fasm": """// PROMPT: VRRP failover redundancy signaling encapsulated across MPLS core network.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, MPLS, COMPILE

// INSTRUCTION: Define provider edge redundancy gateway.
HOST mpls_pe_redundancy_gw { IP 172.24.0.254 }

// INSTRUCTION: Define MPLS core multicast listener.
HOST mpls_core_mcast_dst { IP 224.0.0.18 }

// INSTRUCTION: Define MPLS labeled VRRP advertisement flow with label 4096.
FLOW vrrp_mpls_flow(gw, dst) {
    gw -> dst VRRP VRID 50 PRIORITY 210 VIP 172.24.0.1 MPLS 4096
}

// INSTRUCTION: Compile block executing MPLS transported VRRP heartbeat.
COMPILE {
    vrrp_mpls_flow(mpls_pe_redundancy_gw, mpls_core_mcast_dst)
}
""",

    "examples/l3/vrrp/vrrp_looped_master_heartbeat_burst.fasm": """// PROMPT: Steady-state VRRP master advertisement heartbeats inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, ADV_INT, VIP, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define master core gateway router.
HOST master_core_gw { IP 10.0.0.254 }

// INSTRUCTION: Define standard VRRP multicast listener address.
HOST vrrp_peers_dst { IP 224.0.0.18 }

// INSTRUCTION: Define periodic 10ms heartbeat burst flow.
FLOW vrrp_loop_heartbeat(gw, dst) {
    gw -> dst VRRP VRID 1 PRIORITY 100 ADV_INT 100 VIP 10.0.0.1 WAIT 10ms
}

// INSTRUCTION: Compile loop executing 5 VRRP master heartbeats.
COMPILE {
    LOOP 5 {
        vrrp_loop_heartbeat(master_core_gw, vrrp_peers_dst)
    }
}
""",

    "examples/l3/vrrp/vrrp_dscp_network_control_priority.fasm": """// PROMPT: VRRP master advertisement marked with DSCP Class Selector 6 for control plane prioritization.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, DSCP, TTL, COMPILE

// INSTRUCTION: Define enterprise campus core gateway.
HOST campus_core_gw { IP 172.18.1.254 }

// INSTRUCTION: Define VRRP multicast destination address.
HOST vrrp_mcast_addr { IP 224.0.0.18 }

// INSTRUCTION: Define DSCP CS6 prioritized VRRP advertisement flow.
FLOW vrrp_dscp_flow(gw, dst) {
    gw -> dst VRRP VRID 8 PRIORITY 160 VIP 172.18.1.1 DSCP 48 TTL 255
}

// INSTRUCTION: Compile block executing DSCP prioritized VRRP advertisement.
COMPILE {
    vrrp_dscp_flow(campus_core_gw, vrrp_mcast_addr)
}
""",

    "examples/l3/vrrp/vrrp_multi_vrid_load_sharing.fasm": """// PROMPT: Dual active-active VRRP gateway setup load sharing traffic across VRID 1 and VRID 2.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, COMPILE

// INSTRUCTION: Define gateway router A serving as master for VRID 1.
HOST gw_router_a { IP 192.168.1.254 }

// INSTRUCTION: Define gateway router B serving as master for VRID 2.
HOST gw_router_b { IP 192.168.1.253 }

// INSTRUCTION: Define multi-VRID advertisement flow alternating virtual gateway responsibilities.
FLOW vrrp_load_share_flow(gw_a, gw_b) {
    gw_a -> gw_b VRRP VRID 1 PRIORITY 200 VIP 192.168.1.1
    gw_b -> gw_a VRRP VRID 2 PRIORITY 200 VIP 192.168.1.2
}

// INSTRUCTION: Compile block executing active-active VRRP load sharing.
COMPILE {
    vrrp_load_share_flow(gw_router_a, gw_router_b)
}
""",

    "examples/l3/vrrp/vrrp_data_center_evpn_gateway_redundancy.fasm": """// PROMPT: Data center leaf switches synchronizing virtual gateway IP 10.250.0.1 via VRRP.
// TOKENS: HOST, IP, FLOW, ->, VRRP, VRID, PRIORITY, VIP, COMPILE

// INSTRUCTION: Define Data Center Leaf Switch 1.
HOST dc_leaf_sw_1 { IP 10.250.0.254 }

// INSTRUCTION: Define Data Center Leaf Switch 2 peer.
HOST dc_leaf_sw_2 { IP 10.250.0.253 }

// INSTRUCTION: Define DC gateway synchronization flow.
FLOW dc_vrrp_sync_flow(sw1, sw2) {
    sw1 -> sw2 VRRP VRID 50 PRIORITY 120 VIP 10.250.0.1
}

// INSTRUCTION: Compile block executing data center EVPN gateway VRRP advertisement.
COMPILE {
    dc_vrrp_sync_flow(dc_leaf_sw_1, dc_leaf_sw_2)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 VRRP files generated and verified successfully.")
