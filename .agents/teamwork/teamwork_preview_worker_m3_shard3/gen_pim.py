#!/usr/bin/env python3
"""Generate 12 new verified PIM examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/pim/pim_designated_router_priority_hello.fasm": """// PROMPT: PIM Hello packet advertising custom Designated Router Priority 100 on multi-access LAN.
// TOKENS: HOST, IP, FLOW, ->, PIM, HELLO, DR_PRIORITY, HOLDTIME, COMPILE

// INSTRUCTION: Define core distribution router candidate.
HOST core_pim_dr_node { IP 10.80.1.1 }

// INSTRUCTION: Define All-PIM-Routers multicast destination 224.0.0.13.
HOST all_pim_routers_dst { IP 224.0.0.13 }

// INSTRUCTION: Define PIM Hello flow advertising DR Priority 100 with 105s hold time.
FLOW pim_dr_hello_flow(src, dst) {
    src -> dst PIM HELLO DR_PRIORITY 100 HOLDTIME 105
}

// INSTRUCTION: Compile block executing DR priority Hello transmission.
COMPILE {
    pim_dr_hello_flow(core_pim_dr_node, all_pim_routers_dst)
}
""",

    "examples/l3/pim/pim_rendezvous_point_tree_join.fasm": """// PROMPT: Downstream PIM router subscribing to shared (*,G) multicast tree toward Rendezvous Point.
// TOKENS: HOST, IP, FLOW, ->, PIM, JOIN_PRUNE, GROUP, RP, COMPILE

// INSTRUCTION: Define downstream branch multicast router.
HOST branch_pim_downstream { IP 172.25.1.2 }

// INSTRUCTION: Define upstream Rendezvous Point neighbor router.
HOST upstream_rp_neighbor { IP 172.25.1.1 }

// INSTRUCTION: Define PIM Join flow targeting group 239.255.0.1 via RP 10.0.0.1.
FLOW pim_rp_join_flow(down, up) {
    down -> up PIM JOIN_PRUNE GROUP 239.255.0.1 RP 10.0.0.1
}

// INSTRUCTION: Compile block executing RP shared tree Join.
COMPILE {
    pim_rp_join_flow(branch_pim_downstream, upstream_rp_neighbor)
}
""",

    "examples/l3/pim/pim_shortest_path_tree_switchover.fasm": """// PROMPT: Last-hop router initiating source-specific (S,G) Join toward high-bitrate media server.
// TOKENS: HOST, IP, FLOW, ->, PIM, JOIN_PRUNE, GROUP, SOURCE, HOLDTIME, COMPILE

// INSTRUCTION: Define last-hop receiver router.
HOST last_hop_receiver_rtr { IP 192.168.150.2 }

// INSTRUCTION: Define reverse path forwarding neighbor toward source.
HOST rpf_neighbor_to_source { IP 192.168.150.1 }

// INSTRUCTION: Define Source-Specific Multicast (S,G) Join flow.
FLOW pim_spt_switchover(lhr, rpf) {
    lhr -> rpf PIM JOIN_PRUNE GROUP 232.1.1.1 SOURCE 198.51.100.50 HOLDTIME 210
}

// INSTRUCTION: Compile block executing SPT switchover Join.
COMPILE {
    pim_spt_switchover(last_hop_receiver_rtr, rpf_neighbor_to_source)
}
""",

    "examples/l3/pim/pim_prune_unwanted_branch_signal.fasm": """// PROMPT: Router pruning unneeded multicast distribution tree branch via PIM JOIN_PRUNE message.
// TOKENS: HOST, IP, FLOW, ->, PIM, JOIN_PRUNE, GROUP, SOURCE, COMPILE

// INSTRUCTION: Define leaf distribution router with no active receivers.
HOST leaf_dist_router { IP 10.14.0.2 }

// INSTRUCTION: Define upstream multicast transit router.
HOST upstream_transit_rtr { IP 10.14.0.1 }

// INSTRUCTION: Define PIM prune signaling flow removing branch for group 239.10.10.1.
FLOW pim_prune_branch_flow(leaf, up) {
    leaf -> up PIM JOIN_PRUNE GROUP 239.10.10.1 SOURCE 10.14.100.5
}

// INSTRUCTION: Compile block executing PIM Prune signal.
COMPILE {
    pim_prune_branch_flow(leaf_dist_router, upstream_transit_rtr)
}
""",

    "examples/l3/pim/pim_register_encapsulated_data_burst.fasm": """// PROMPT: First-hop router encapsulating multicast source stream in PIM REGISTER to Rendezvous Point.
// TOKENS: HOST, IP, FLOW, ->, PIM, REGISTER, RP, GROUP, SOURCE, PAYLOAD, COMPILE

// INSTRUCTION: Define first-hop multicast source router.
HOST first_hop_source_rtr { IP 10.33.1.1 }

// INSTRUCTION: Define central Rendezvous Point router.
HOST rendezvous_point_rtr { IP 10.33.254.1 }

// INSTRUCTION: Define PIM Register encapsulation flow carrying video stream packet.
FLOW pim_register_flow(fhr, rp) {
    fhr -> rp PIM REGISTER RP 10.33.254.1 GROUP 239.1.1.100 SOURCE 10.33.1.50 PAYLOAD "RTP_VIDEO_PAYLOAD"
}

// INSTRUCTION: Compile block executing PIM Register encapsulation.
COMPILE {
    pim_register_flow(first_hop_source_rtr, rendezvous_point_rtr)
}
""",

    "examples/l3/pim/pim_vlan_tagged_multicast_peering.fasm": """// PROMPT: PIM neighbor Hello exchange over 802.1Q tagged video delivery VLAN 300.
// TOKENS: HOST, IP, FLOW, ->, <-, PIM, HELLO, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define video headend switch router.
HOST video_headend_rtr { IP 172.16.30.1 }

// INSTRUCTION: Define video distribution core switch.
HOST video_dist_switch { IP 172.16.30.2 }

// INSTRUCTION: Define VLAN 300 tagged PIM Hello peering flow.
FLOW pim_vlan_peering(v_src, v_dst) {
    v_src -> v_dst PIM HELLO VLAN 300 PCP 5 DEI 0
    v_src <- v_dst PIM HELLO VLAN 300 PCP 5 DEI 0
}

// INSTRUCTION: Compile block executing tagged PIM neighbor discovery.
COMPILE {
    pim_vlan_peering(video_headend_rtr, video_dist_switch)
}
""",

    "examples/l3/pim/pim_qinq_carrier_multicast_distribution.fasm": """// PROMPT: PIM multicast signaling transported across provider QinQ dual-VLAN bridge.
// TOKENS: HOST, IP, FLOW, ->, PIM, HELLO, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define enterprise broadcast source gateway.
HOST broadcast_source_gw { IP 192.168.90.1 }

// INSTRUCTION: Define carrier multicast transit gateway.
HOST carrier_transit_gw { IP 192.168.90.2 }

// INSTRUCTION: Define QinQ encapsulated PIM Hello flow on service VLAN 800 and customer VLAN 30.
FLOW pim_qinq_hello_flow(src, gw) {
    src -> gw PIM HELLO QINQ 800 INNER_VLAN 30
}

// INSTRUCTION: Compile block executing carrier QinQ PIM Hello.
COMPILE {
    pim_qinq_hello_flow(broadcast_source_gw, carrier_transit_gw)
}
""",

    "examples/l3/pim/pim_ipv6_pim_sparse_mode_hello.fasm": """// PROMPT: Pure IPv6 PIM-SM Hello packets exchanged on link-local multicast destination ff02::d.
// TOKENS: HOST, IP, FLOW, ->, <-, PIM, HELLO, COMPILE

// INSTRUCTION: Define IPv6 multicast edge router 1.
HOST pim_v6_edge_1 { IP fe80::101:1 }

// INSTRUCTION: Define IPv6 multicast edge router 2.
HOST pim_v6_edge_2 { IP fe80::102:2 }

// INSTRUCTION: Define IPv6 link-local PIM Hello exchange flow.
FLOW pim_v6_hello_flow(r1, r2) {
    r1 -> r2 PIM HELLO
    r1 <- r2 PIM HELLO
}

// INSTRUCTION: Compile block executing IPv6 PIM-SM neighbor discovery.
COMPILE {
    pim_v6_hello_flow(pim_v6_edge_1, pim_v6_edge_2)
}
""",

    "examples/l3/pim/pim_looped_hello_neighbor_liveness.fasm": """// PROMPT: Continuous PIM Hello heartbeats inside a COMPILE LOOP maintaining neighbor adjacency.
// TOKENS: HOST, IP, FLOW, ->, PIM, HELLO, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define campus multicast router keeping neighbor adjacency alive.
HOST campus_pim_rtr { IP 10.77.1.1 }

// INSTRUCTION: Define All-PIM-Routers multicast peer destination.
HOST all_pim_peers_dst { IP 224.0.0.13 }

// INSTRUCTION: Define periodic PIM Hello heartbeat flow.
FLOW pim_liveness_heartbeat(rtr, dst) {
    rtr -> dst PIM HELLO WAIT 30ms
}

// INSTRUCTION: Compile loop executing 4 periodic PIM Hello transmissions.
COMPILE {
    LOOP 4 {
        pim_liveness_heartbeat(campus_pim_rtr, all_pim_peers_dst)
    }
}
""",

    "examples/l3/pim/pim_high_holdtime_wan_stability.fasm": """// PROMPT: WAN edge router negotiating extended Holdtime 210s for high-latency satellite link.
// TOKENS: HOST, IP, FLOW, ->, PIM, HELLO, HOLDTIME, DR_PRIORITY, COMPILE

// INSTRUCTION: Define satellite earth station router.
HOST satellite_wan_rtr { IP 172.31.200.1 }

// INSTRUCTION: Define All-PIM-Routers satellite multicast address.
HOST sat_multicast_dst { IP 224.0.0.13 }

// INSTRUCTION: Define extended holdtime Hello flow configured with 210 seconds.
FLOW pim_sat_hello_flow(sat, dst) {
    sat -> dst PIM HELLO HOLDTIME 210 DR_PRIORITY 10
}

// INSTRUCTION: Compile block executing satellite WAN PIM Hello.
COMPILE {
    pim_sat_hello_flow(satellite_wan_rtr, sat_multicast_dst)
}
""",

    "examples/l3/pim/pim_dscp_network_control_signaling.fasm": """// PROMPT: PIM Join/Prune signaling prioritizing control packets with DSCP Class Selector 6.
// TOKENS: HOST, IP, FLOW, ->, PIM, JOIN_PRUNE, GROUP, SOURCE, DSCP, TTL, COMPILE

// INSTRUCTION: Define high-priority multicast subscriber router.
HOST priority_sub_rtr { IP 10.120.0.2 }

// INSTRUCTION: Define upstream backbone multicast router.
HOST backbone_mcast_rtr { IP 10.120.0.1 }

// INSTRUCTION: Define DSCP CS6 prioritized Join message flow.
FLOW pim_dscp_join_flow(sub, bb) {
    sub -> bb PIM JOIN_PRUNE GROUP 239.50.50.1 SOURCE 10.120.100.10 DSCP 48 TTL 1
}

// INSTRUCTION: Compile block executing prioritized PIM Join signaling.
COMPILE {
    pim_dscp_join_flow(priority_sub_rtr, backbone_mcast_rtr)
}
""",

    "examples/l3/pim/pim_campus_rp_failover_announcement.fasm": """// PROMPT: Secondary Rendezvous Point asserting multicast RP tree coordination.
// TOKENS: HOST, IP, FLOW, ->, PIM, HELLO, DR_PRIORITY, HOLDTIME, COMPILE

// INSTRUCTION: Define secondary backup RP router.
HOST backup_rp_rtr { IP 10.60.0.2 }

// INSTRUCTION: Define All-PIM-Routers campus multicast destination.
HOST campus_pim_mcast { IP 224.0.0.13 }

// INSTRUCTION: Define backup RP Hello assertion with high DR priority 200.
FLOW pim_rp_failover_hello(rp, dst) {
    rp -> dst PIM HELLO DR_PRIORITY 200 HOLDTIME 105
}

// INSTRUCTION: Compile block executing backup RP election Hello.
COMPILE {
    pim_rp_failover_hello(backup_rp_rtr, campus_pim_mcast)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 PIM files generated and verified successfully.")
