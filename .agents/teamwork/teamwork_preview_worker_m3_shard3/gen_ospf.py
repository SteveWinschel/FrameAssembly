#!/usr/bin/env python3
"""Generate 12 new verified OSPF examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/ospf/ospf_point_to_point_link_hello.fasm": """// PROMPT: OSPF Hello packets over point-to-point leased line between core routers with Area 0.
// TOKENS: HOST, IP, FLOW, ->, <-, OSPF, HELLO, ROUTER_ID, AREA_ID, COMPILE

// INSTRUCTION: Define core router 1 on WAN leased line.
HOST core_ospf_r1 { IP 10.254.0.1 }

// INSTRUCTION: Define core router 2 on WAN leased line.
HOST core_ospf_r2 { IP 10.254.0.2 }

// INSTRUCTION: Define point-to-point OSPF Hello discovery flow in backbone Area 0.
FLOW ospf_p2p_hello(r1, r2) {
    r1 -> r2 OSPF HELLO ROUTER_ID 10.254.0.1 AREA_ID 0
    r1 <- r2 OSPF HELLO ROUTER_ID 10.254.0.2 AREA_ID 0
}

// INSTRUCTION: Compile block executing OSPF point-to-point Hello exchange.
COMPILE {
    ospf_p2p_hello(core_ospf_r1, core_ospf_r2)
}
""",

    "examples/l3/ospf/ospf_nssa_area_border_hello.fasm": """// PROMPT: OSPF Area Border Router advertising adjacency on Not-So-Stubby Area (NSSA) Area 10.
// TOKENS: HOST, IP, FLOW, ->, OSPF, HELLO, ROUTER_ID, AREA_ID, HELLO_INTERVAL, DEAD_INTERVAL, COMPILE

// INSTRUCTION: Define Area Border Router in NSSA area.
HOST abr_nssa_router { IP 172.19.10.1 }

// INSTRUCTION: Define All-OSPF-Routers multicast group.
HOST ospf_all_routers_grp { IP 224.0.0.5 }

// INSTRUCTION: Define NSSA Area 10 Hello advertisement with standard 10s/40s intervals.
FLOW ospf_nssa_hello(abr, mcast) {
    abr -> mcast OSPF HELLO ROUTER_ID 172.19.10.1 AREA_ID 10 HELLO_INTERVAL 10 DEAD_INTERVAL 40
}

// INSTRUCTION: Compile block executing NSSA Area border Hello transmission.
COMPILE {
    ospf_nssa_hello(abr_nssa_router, ospf_all_routers_grp)
}
""",

    "examples/l3/ospf/ospf_link_state_request_sync.fasm": """// PROMPT: OSPF router synchronizing database via Link State Request (LSR) packet.
// TOKENS: HOST, IP, FLOW, ->, OSPF, LSR, ROUTER_ID, AREA_ID, COMPILE

// INSTRUCTION: Define OSPF neighbor loading missing LSAs.
HOST ospf_loading_neighbor { IP 192.168.200.2 }

// INSTRUCTION: Define OSPF designated router peer.
HOST ospf_dr_peer { IP 192.168.200.1 }

// INSTRUCTION: Define Link State Request synchronization flow.
FLOW ospf_lsr_sync_flow(nbr, dr) {
    nbr -> dr OSPF LSR ROUTER_ID 192.168.200.2 AREA_ID 0
}

// INSTRUCTION: Compile block executing OSPF LSR packet transmission.
COMPILE {
    ospf_lsr_sync_flow(ospf_loading_neighbor, ospf_dr_peer)
}
""",

    "examples/l3/ospf/ospf_link_state_update_flooding.fasm": """// PROMPT: OSPF Designated Router flooding topology updates via Link State Update (LSU).
// TOKENS: HOST, IP, FLOW, ->, OSPF, LSU, ROUTER_ID, AREA_ID, COMPILE

// INSTRUCTION: Define OSPF Designated Router flooding LSA updates.
HOST ospf_designated_rtr { IP 10.10.0.1 }

// INSTRUCTION: Define All-OSPF-Routers multicast address.
HOST all_ospf_routers_dst { IP 224.0.0.5 }

// INSTRUCTION: Define Link State Update flooding transmission flow.
FLOW ospf_lsu_flood_flow(dr, dst) {
    dr -> dst OSPF LSU ROUTER_ID 10.10.0.1 AREA_ID 0
}

// INSTRUCTION: Compile block executing LSU flooding.
COMPILE {
    ospf_lsu_flood_flow(ospf_designated_rtr, all_ospf_routers_dst)
}
""",

    "examples/l3/ospf/ospf_link_state_acknowledgement.fasm": """// PROMPT: OSPF neighbor acknowledging received LSAs via Link State Acknowledgment (LSACK).
// TOKENS: HOST, IP, FLOW, ->, OSPF, LSACK, ROUTER_ID, AREA_ID, COMPILE

// INSTRUCTION: Define OSPF acknowledging peer node.
HOST ospf_ack_peer { IP 172.22.1.2 }

// INSTRUCTION: Define All-DR-Routers multicast destination 224.0.0.6.
HOST ospf_all_dr_mcast { IP 224.0.0.6 }

// INSTRUCTION: Define LSACK confirmation flow acknowledging update delivery.
FLOW ospf_lsack_flow(peer, dr) {
    peer -> dr OSPF LSACK ROUTER_ID 172.22.1.2 AREA_ID 0
}

// INSTRUCTION: Compile block executing OSPF Link State Acknowledgment.
COMPILE {
    ospf_lsack_flow(ospf_ack_peer, ospf_all_dr_mcast)
}
""",

    "examples/l3/ospf/ospf_vlan_tagged_trunk_peering.fasm": """// PROMPT: OSPF routing adjacency established across 802.1Q tagged routing VLAN 50.
// TOKENS: HOST, IP, FLOW, ->, <-, OSPF, HELLO, ROUTER_ID, AREA_ID, VLAN, COMPILE

// INSTRUCTION: Define campus distribution switch A.
HOST dist_switch_a { IP 10.50.0.1 }

// INSTRUCTION: Define campus distribution switch B.
HOST dist_switch_b { IP 10.50.0.2 }

// INSTRUCTION: Define 802.1Q tagged OSPF Hello peering flow.
FLOW ospf_vlan_peering(sw_a, sw_b) {
    sw_a -> sw_b OSPF HELLO ROUTER_ID 10.50.0.1 AREA_ID 0 VLAN 50
    sw_a <- sw_b OSPF HELLO ROUTER_ID 10.50.0.2 AREA_ID 0 VLAN 50
}

// INSTRUCTION: Compile block executing VLAN tagged OSPF adjacency.
COMPILE {
    ospf_vlan_peering(dist_switch_a, dist_switch_b)
}
""",

    "examples/l3/ospf/ospf_qinq_metro_interconnect.fasm": """// PROMPT: OSPF Area 0 backbone link traversing metro provider QinQ dual-VLAN infrastructure.
// TOKENS: HOST, IP, FLOW, ->, OSPF, HELLO, ROUTER_ID, AREA_ID, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define core data center OSPF gateway.
HOST dc_ospf_gw { IP 172.16.100.1 }

// INSTRUCTION: Define disaster recovery OSPF gateway.
HOST dr_ospf_gw { IP 172.16.100.2 }

// INSTRUCTION: Define QinQ encapsulated OSPF backbone Hello flow.
FLOW ospf_qinq_hello(dc, dr) {
    dc -> dr OSPF HELLO ROUTER_ID 172.16.100.1 AREA_ID 0 QINQ 1000 INNER_VLAN 40
}

// INSTRUCTION: Compile block executing QinQ metro interconnect Hello.
COMPILE {
    ospf_qinq_hello(dc_ospf_gw, dr_ospf_gw)
}
""",

    "examples/l3/ospf/ospf_mpls_traffic_engineered_core.fasm": """// PROMPT: OSPF routing packets encapsulated within MPLS label stack for core transit.
// TOKENS: HOST, IP, FLOW, ->, OSPF, HELLO, ROUTER_ID, AREA_ID, MPLS, COMPILE

// INSTRUCTION: Define MPLS provider edge router.
HOST mpls_pe_ospf_rtr { IP 10.200.0.1 }

// INSTRUCTION: Define provider core transit router.
HOST mpls_p_core_rtr { IP 10.200.0.2 }

// INSTRUCTION: Define MPLS labeled OSPF Hello flow traversing core label switched path.
FLOW ospf_mpls_hello(pe, p) {
    pe -> p OSPF HELLO ROUTER_ID 10.200.0.1 AREA_ID 0 MPLS 2048
}

// INSTRUCTION: Compile block executing MPLS encapsulated OSPF transmission.
COMPILE {
    ospf_mpls_hello(mpls_pe_ospf_rtr, mpls_p_core_rtr)
}
""",

    "examples/l3/ospf/ospf_fast_convergence_short_dead_timer.fasm": """// PROMPT: Fast convergence sub-second OSPF Hello and Dead interval tuning.
// TOKENS: HOST, IP, FLOW, ->, OSPF, HELLO, ROUTER_ID, AREA_ID, HELLO_INTERVAL, DEAD_INTERVAL, COMPILE

// INSTRUCTION: Define low-latency trading router.
HOST trading_edge_rtr { IP 192.168.12.1 }

// INSTRUCTION: Define trading exchange gateway.
HOST exchange_gw_rtr { IP 224.0.0.5 }

// INSTRUCTION: Define aggressive timer Hello flow with 1s hello and 4s dead interval.
FLOW ospf_fast_timer_flow(src, dst) {
    src -> dst OSPF HELLO ROUTER_ID 192.168.12.1 AREA_ID 0 HELLO_INTERVAL 1 DEAD_INTERVAL 4
}

// INSTRUCTION: Compile block executing fast convergence OSPF Hello.
COMPILE {
    ospf_fast_timer_flow(trading_edge_rtr, exchange_gw_rtr)
}
""",

    "examples/l3/ospf/ospf_looped_hello_keepalive_burst.fasm": """// PROMPT: Continuous OSPF Hello heartbeats inside a COMPILE LOOP maintaining adjacency.
// TOKENS: HOST, IP, FLOW, ->, OSPF, HELLO, ROUTER_ID, AREA_ID, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define core spine router maintaining neighbor adjacency.
HOST spine_ospf_rtr { IP 10.0.1.1 }

// INSTRUCTION: Define All-OSPF-Routers multicast peer.
HOST all_ospf_peers { IP 224.0.0.5 }

// INSTRUCTION: Define periodic OSPF Hello heartbeat flow.
FLOW ospf_hello_heartbeat(spine, peers) {
    spine -> peers OSPF HELLO ROUTER_ID 10.0.1.1 AREA_ID 0 WAIT 20ms
}

// INSTRUCTION: Compile loop executing 4 continuous OSPF Hello bursts.
COMPILE {
    LOOP 4 {
        ospf_hello_heartbeat(spine_ospf_rtr, all_ospf_peers)
    }
}
""",

    "examples/l3/ospf/ospf_designated_router_priority_election.fasm": """// PROMPT: High priority OSPF router asserting Designated Router candidacy with Priority 255.
// TOKENS: HOST, IP, FLOW, ->, OSPF, HELLO, ROUTER_ID, AREA_ID, PRIORITY, COMPILE

// INSTRUCTION: Define primary core switch asserting DR role.
HOST primary_dr_candidate { IP 172.16.0.254 }

// INSTRUCTION: Define multi-access LAN multicast destination.
HOST lan_multicast_dst { IP 224.0.0.5 }

// INSTRUCTION: Define DR priority election Hello flow with Priority 255.
FLOW ospf_dr_election_flow(dr, dst) {
    dr -> dst OSPF HELLO ROUTER_ID 172.16.0.254 AREA_ID 0 PRIORITY 255
}

// INSTRUCTION: Compile block executing DR priority assertion Hello.
COMPILE {
    ospf_dr_election_flow(primary_dr_candidate, lan_multicast_dst)
}
""",

    "examples/l3/ospf/ospf_ipv6_ospfv3_adjacency.fasm": """// PROMPT: Pure IPv6 OSPFv3 Hello exchange across link-local multicast ff02::5.
// TOKENS: HOST, IP, FLOW, ->, <-, OSPF, HELLO, AREA_ID, COMPILE

// INSTRUCTION: Define IPv6 OSPFv3 router 1 on link-local interface.
HOST ospfv3_rtr_1 { IP fe80::1:1 }

// INSTRUCTION: Define IPv6 OSPFv3 router 2 on link-local interface.
HOST ospfv3_rtr_2 { IP fe80::1:2 }

// INSTRUCTION: Define OSPFv3 link-local Hello exchange flow in Area 0.
FLOW ospfv3_hello_flow(r1, r2) {
    r1 -> r2 OSPF HELLO AREA_ID 0
    r1 <- r2 OSPF HELLO AREA_ID 0
}

// INSTRUCTION: Compile block executing IPv6 OSPFv3 adjacency Hello.
COMPILE {
    ospfv3_hello_flow(ospfv3_rtr_1, ospfv3_rtr_2)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 OSPF files generated and verified successfully.")
