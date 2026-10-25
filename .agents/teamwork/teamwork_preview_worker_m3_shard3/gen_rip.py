#!/usr/bin/env python3
"""Generate 12 new verified RIP examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/rip/rip_poison_reverse_unreachable_metric.fasm": """// PROMPT: RIPv2 routing update advertising unreachable network route with infinity metric 16.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, COMPILE

// INSTRUCTION: Define border gateway router detecting link failure.
HOST failed_link_gw { IP 10.15.1.1 }

// INSTRUCTION: Define standard RIPv2 multicast group 224.0.0.9.
HOST rip_all_rtrs_mcast { IP 224.0.0.9 }

// INSTRUCTION: Define poison reverse update advertising failed subnet 10.15.99.0 with metric 16.
FLOW rip_poison_reverse(gw, dst) {
    gw -> dst RIP RESPONSE PREFIX 10.15.99.0 METRIC 16
}

// INSTRUCTION: Compile block executing poison reverse route invalidation.
COMPILE {
    rip_poison_reverse(failed_link_gw, rip_all_rtrs_mcast)
}
""",

    "examples/l3/rip/rip_split_horizon_filtered_update.fasm": """// PROMPT: RIPv2 distribution update advertising branch route with metric 3 and explicit NEXTHOP.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, NEXTHOP, COMPILE

// INSTRUCTION: Define regional distribution router.
HOST reg_dist_router { IP 172.20.1.1 }

// INSTRUCTION: Define branch aggregation router.
HOST branch_agg_peer { IP 172.20.1.2 }

// INSTRUCTION: Define split-horizon filtered route update advertising prefix with designated next hop.
FLOW rip_split_horizon(dist, br) {
    dist -> br RIP RESPONSE PREFIX 172.20.10.0 METRIC 3 NEXTHOP 172.20.1.254
}

// INSTRUCTION: Compile block executing filtered RIP advertisement.
COMPILE {
    rip_split_horizon(reg_dist_router, branch_agg_peer)
}
""",

    "examples/l3/rip/rip_route_tagging_bgp_redistribution.fasm": """// PROMPT: RIPv2 route update carrying autonomous system route tag 65001 for BGP redistribution.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, TAG, COMPILE

// INSTRUCTION: Define autonomous system boundary router (ASBR).
HOST asbr_redist_rtr { IP 192.168.44.1 }

// INSTRUCTION: Define internal RIP peers multicast address.
HOST internal_rip_peers { IP 224.0.0.9 }

// INSTRUCTION: Define route redistribution update tagging external route with AS tag 65001.
FLOW rip_tagging_flow(asbr, peers) {
    asbr -> peers RIP RESPONSE PREFIX 192.168.100.0 METRIC 2 TAG 65001
}

// INSTRUCTION: Compile block executing tagged route advertisement.
COMPILE {
    rip_tagging_flow(asbr_redist_rtr, internal_rip_peers)
}
""",

    "examples/l3/rip/rip_ripng_ipv6_route_advertisement.fasm": """// PROMPT: Pure IPv6 RIPng route advertisement sent to multicast ff02::9 on UDP port 521.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, COMPILE

// INSTRUCTION: Define IPv6 campus router 1 on link-local interface.
HOST ripng_rtr_1 { IP fe80::1001:1 }

// INSTRUCTION: Define standard RIPng all-routers multicast group ff02::9.
HOST ripng_all_routers_dst { IP ff02::9 }

// INSTRUCTION: Define RIPng route table update advertisement flow.
FLOW ripng_advert_flow(rtr, dst) {
    rtr -> dst RIP RESPONSE
}

// INSTRUCTION: Compile block executing IPv6 RIPng route advertisement.
COMPILE {
    ripng_advert_flow(ripng_rtr_1, ripng_all_routers_dst)
}
""",

    "examples/l3/rip/ripng_ipv6_table_request_query.fasm": """// PROMPT: IPv6 branch router soliciting routing table updates via RIPng REQUEST.
// TOKENS: HOST, IP, FLOW, ->, <-, RIP, REQUEST, RESPONSE, COMPILE

// INSTRUCTION: Define newly booted IPv6 edge router.
HOST ripng_edge_boot { IP fe80::e01:1 }

// INSTRUCTION: Define IPv6 core distribution router.
HOST ripng_core_dist { IP fe80::c01:1 }

// INSTRUCTION: Define RIPng table inquiry and response handshake flow.
FLOW ripng_query_exchange(edge, core) {
    edge -> core RIP REQUEST
    edge <- core RIP RESPONSE
}

// INSTRUCTION: Compile block executing RIPng table inquiry.
COMPILE {
    ripng_query_exchange(ripng_edge_boot, ripng_core_dist)
}
""",

    "examples/l3/rip/rip_vlan_tagged_branch_advertisement.fasm": """// PROMPT: 802.1Q tagged RIPv2 update broadcast across branch routing VLAN 20.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, VLAN, COMPILE

// INSTRUCTION: Define branch office routing gateway.
HOST branch_gw_vlan20 { IP 10.20.0.1 }

// INSTRUCTION: Define VLAN 20 broadcast destination.
HOST vlan20_broadcast { IP 224.0.0.9 }

// INSTRUCTION: Define VLAN 20 tagged RIP route update flow.
FLOW rip_vlan_update(gw, dst) {
    gw -> dst RIP RESPONSE PREFIX 10.20.100.0 METRIC 1 VLAN 20
}

// INSTRUCTION: Compile block executing VLAN tagged RIP advertisement.
COMPILE {
    rip_vlan_update(branch_gw_vlan20, vlan20_broadcast)
}
""",

    "examples/l3/rip/rip_qinq_carrier_hosted_branch.fasm": """// PROMPT: Dual-tagged QinQ RIPv2 frame connecting remote retail branch site.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define retail store edge router.
HOST store_edge_rtr { IP 192.168.12.1 }

// INSTRUCTION: Define headquarters aggregation router.
HOST hq_agg_rtr { IP 192.168.12.2 }

// INSTRUCTION: Define QinQ encapsulated RIP update flow on provider VLAN 700 and customer VLAN 12.
FLOW rip_qinq_update(store, hq) {
    store -> hq RIP RESPONSE PREFIX 192.168.50.0 METRIC 2 QINQ 700 INNER_VLAN 12
}

// INSTRUCTION: Compile block executing QinQ hosted branch RIP update.
COMPILE {
    rip_qinq_update(store_edge_rtr, hq_agg_rtr)
}
""",

    "examples/l3/rip/rip_mpls_pe_ce_routing_exchange.fasm": """// PROMPT: Provider Edge (PE) and Customer Edge (CE) exchanging RIP routes across MPLS VPN.
// TOKENS: HOST, IP, FLOW, ->, <-, RIP, REQUEST, RESPONSE, PREFIX, METRIC, MPLS, COMPILE

// INSTRUCTION: Define Customer Edge (CE) router.
HOST cust_edge_rtr { IP 10.10.10.2 }

// INSTRUCTION: Define Provider Edge (PE) router.
HOST prov_edge_rtr { IP 10.10.10.1 }

// INSTRUCTION: Define MPLS VPN PE-CE RIP routing exchange flow.
FLOW rip_mpls_pe_ce(ce, pe) {
    ce -> pe RIP REQUEST MPLS 100
    ce <- pe RIP RESPONSE PREFIX 10.0.0.0 METRIC 1 MPLS 100
}

// INSTRUCTION: Compile block executing MPLS PE-CE RIP exchange.
COMPILE {
    rip_mpls_pe_ce(cust_edge_rtr, prov_edge_rtr)
}
""",

    "examples/l3/rip/rip_looped_periodic_update_cycle.fasm": """// PROMPT: Periodic 30-second RIP update broadcast burst inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define steady-state branch router broadcasting periodic updates.
HOST periodic_branch_rtr { IP 172.16.5.1 }

// INSTRUCTION: Define standard RIPv2 multicast destination.
HOST rip_mcast_target { IP 224.0.0.9 }

// INSTRUCTION: Define periodic route update flow.
FLOW rip_periodic_burst(br, dst) {
    br -> dst RIP RESPONSE PREFIX 172.16.50.0 METRIC 2 WAIT 30ms
}

// INSTRUCTION: Compile loop executing 4 periodic RIP updates.
COMPILE {
    LOOP 4 {
        rip_periodic_burst(periodic_branch_rtr, rip_mcast_target)
    }
}
""",

    "examples/l3/rip/rip_dscp_control_plane_metric_update.fasm": """// PROMPT: RIP route advertisement prioritizing control plane traffic with DSCP CS6.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, DSCP, TTL, COMPILE

// INSTRUCTION: Define campus core distribution router.
HOST campus_core_dist { IP 10.2.0.1 }

// INSTRUCTION: Define RIP multicast listener group.
HOST rip_listener_mcast { IP 224.0.0.9 }

// INSTRUCTION: Define DSCP CS6 prioritized route update flow.
FLOW rip_dscp_update(core, dst) {
    core -> dst RIP RESPONSE PREFIX 10.2.10.0 METRIC 1 DSCP 48 TTL 2
}

// INSTRUCTION: Compile block executing DSCP prioritized RIP advertisement.
COMPILE {
    rip_dscp_update(campus_core_dist, rip_listener_mcast)
}
""",

    "examples/l3/rip/rip_campus_aggregation_multi_prefix.fasm": """// PROMPT: Campus aggregation router announcing multiple subnet prefixes in sequence.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, WAIT, ms, COMPILE

// INSTRUCTION: Define building aggregation switch.
HOST bldg_agg_switch { IP 192.168.1.1 }

// INSTRUCTION: Define floor distribution router.
HOST floor_dist_rtr { IP 192.168.1.254 }

// INSTRUCTION: Define sequential multi-subnet announcement flow.
FLOW rip_multi_prefix_flow(agg, dist) {
    agg -> dist RIP RESPONSE PREFIX 192.168.10.0 METRIC 1 WAIT 2ms
    agg -> dist RIP RESPONSE PREFIX 192.168.20.0 METRIC 1 WAIT 2ms
    agg -> dist RIP RESPONSE PREFIX 192.168.30.0 METRIC 2
}

// INSTRUCTION: Compile block executing multi-prefix route announcement.
COMPILE {
    rip_multi_prefix_flow(bldg_agg_switch, floor_dist_rtr)
}
""",

    "examples/l3/rip/rip_wan_edge_backup_gateway.fasm": """// PROMPT: WAN edge router advertising failover default route with higher metric 5.
// TOKENS: HOST, IP, FLOW, ->, RIP, RESPONSE, PREFIX, METRIC, COMPILE

// INSTRUCTION: Define secondary backup WAN edge gateway.
HOST backup_wan_gw { IP 172.28.0.2 }

// INSTRUCTION: Define internal core router destination.
HOST internal_core_gw { IP 172.28.0.1 }

// INSTRUCTION: Define backup default route advertisement flow with metric 5.
FLOW rip_backup_route_flow(wan, core) {
    wan -> core RIP RESPONSE PREFIX 0.0.0.0 METRIC 5
}

// INSTRUCTION: Compile block executing backup default route advertisement.
COMPILE {
    rip_backup_route_flow(backup_wan_gw, internal_core_gw)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 RIP files generated and verified successfully.")
