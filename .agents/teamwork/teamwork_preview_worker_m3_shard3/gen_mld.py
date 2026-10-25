#!/usr/bin/env python3
"""Generate 12 new verified MLD examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/mld/mld_general_query_periodic_refresh.fasm": """// PROMPT: Periodic MLD General Query sent by IPv6 multicast querier to all-nodes address.
// TOKENS: HOST, IP, FLOW, ->, MLD, QUERY, MAX_RESP_DELAY, COMPILE

// INSTRUCTION: Define IPv6 multicast designated querier router.
HOST mld_querier_rtr { IP fe80::100 }

// INSTRUCTION: Define IPv6 link-local all-nodes multicast group.
HOST mld_all_nodes_grp { IP ff02::1 }

// INSTRUCTION: Define periodic MLD General Query flow with 10-second response delay window.
FLOW mld_periodic_query(q, grp) {
    q -> grp MLD QUERY MAX_RESP_DELAY 10000
}

// INSTRUCTION: Compile block executing periodic General Query transmission.
COMPILE {
    mld_periodic_query(mld_querier_rtr, mld_all_nodes_grp)
}
""",

    "examples/l3/mld/mld_solicited_node_multicast_report.fasm": """// PROMPT: IPv6 host reporting membership in solicited-node multicast address for NDP resolution.
// TOKENS: HOST, IP, FLOW, ->, MLD, REPORT, MULTICAST_ADDR, COMPILE

// INSTRUCTION: Define newly initialized IPv6 workstation.
HOST mld_client_node { IP fe80::5054:ff:fe12:3456 }

// INSTRUCTION: Define IPv6 all-routers destination.
HOST mld_all_routers_dst { IP ff02::2 }

// INSTRUCTION: Define MLD report advertising solicited-node multicast group.
FLOW mld_solicited_report(client, rtrs) {
    client -> rtrs MLD REPORT MULTICAST_ADDR ff02::1:ff12:3456
}

// INSTRUCTION: Compile block transmitting solicited-node MLD report.
COMPILE {
    mld_solicited_report(mld_client_node, mld_all_routers_dst)
}
""",

    "examples/l3/mld/mld_fast_leave_immediate_done.fasm": """// PROMPT: IPv6 set-top box leaving high-definition IPTV channel via MLD Done message.
// TOKENS: HOST, IP, FLOW, ->, MLD, DONE, MULTICAST_ADDR, COMPILE

// INSTRUCTION: Define residential subscriber set-top box.
HOST stb_subscriber_node { IP fe80::211:32ff:fe44:5566 }

// INSTRUCTION: Define IPv6 all-routers multicast address.
HOST all_mld_routers { IP ff02::2 }

// INSTRUCTION: Define fast-leave MLD Done signaling flow for multicast stream.
FLOW mld_fast_leave_flow(stb, rtr) {
    stb -> rtr MLD DONE MULTICAST_ADDR ff0e::4321
}

// INSTRUCTION: Compile block executing immediate group leave.
COMPILE {
    mld_fast_leave_flow(stb_subscriber_node, all_mld_routers)
}
""",

    "examples/l3/mld/mld_low_max_resp_delay_tuning.fasm": """// PROMPT: Low Max Response Delay MLD query for rapid multicast group pruning audit.
// TOKENS: HOST, IP, FLOW, ->, MLD, QUERY, MULTICAST_ADDR, MAX_RESP_DELAY, COMPILE

// INSTRUCTION: Define core distribution router auditing active listeners.
HOST core_dist_rtr { IP fe80::1 }

// INSTRUCTION: Define multicast channel target address.
HOST channel_target_grp { IP ff05::200 }

// INSTRUCTION: Define fast-audit query flow with 1000ms maximum response delay.
FLOW mld_audit_query_flow(core, grp) {
    core -> grp MLD QUERY MULTICAST_ADDR ff05::200 MAX_RESP_DELAY 1000
}

// INSTRUCTION: Compile block executing group-specific audit query.
COMPILE {
    mld_audit_query_flow(core_dist_rtr, channel_target_grp)
}
""",

    "examples/l3/mld/mld_vlan_tagged_subscriber_query.fasm": """// PROMPT: 802.1Q tagged MLD query on subscriber multicast delivery VLAN 200.
// TOKENS: HOST, IP, FLOW, ->, MLD, QUERY, VLAN, PCP, DEI, MAX_RESP_DELAY, COMPILE

// INSTRUCTION: Define broadband access BNG gateway.
HOST bng_access_gw { IP fe80::b00:1 }

// INSTRUCTION: Define subscriber broadcast listener.
HOST sub_listener { IP ff02::1 }

// INSTRUCTION: Define VLAN 200 tagged MLD query with high PCP priority.
FLOW mld_vlan_query_flow(bng, sub) {
    bng -> sub MLD QUERY VLAN 200 PCP 6 DEI 0 MAX_RESP_DELAY 5000
}

// INSTRUCTION: Compile block executing tagged MLD query.
COMPILE {
    mld_vlan_query_flow(bng_access_gw, sub_listener)
}
""",

    "examples/l3/mld/mld_qinq_broadband_report_aggregation.fasm": """// PROMPT: Dual-tagged QinQ MLD Report originating from customer premise equipment (CPE).
// TOKENS: HOST, IP, FLOW, ->, MLD, REPORT, MULTICAST_ADDR, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define enterprise branch customer premise equipment.
HOST enterprise_cpe { IP fe80::ca01:1 }

// INSTRUCTION: Define metro provider edge aggregation router.
HOST metro_pe_router { IP ff02::2 }

// INSTRUCTION: Define double-tagged QinQ MLD report joining corporate webcast.
FLOW mld_qinq_report_flow(cpe, pe) {
    cpe -> pe MLD REPORT MULTICAST_ADDR ff08::8080 QINQ 100 INNER_VLAN 25
}

// INSTRUCTION: Compile block executing QinQ encapsulated MLD report.
COMPILE {
    mld_qinq_report_flow(enterprise_cpe, metro_pe_router)
}
""",

    "examples/l3/mld/mld_multihop_hoplimit_verification.fasm": """// PROMPT: Strict IPv6 Hop Limit verification (TTL 1) on MLD General Query per RFC 2710.
// TOKENS: HOST, IP, FLOW, ->, MLD, QUERY, TTL, COMPILE

// INSTRUCTION: Define local link IPv6 router enforcing single-hop boundary.
HOST link_local_router { IP fe80::beef:1 }

// INSTRUCTION: Define link-local all-nodes multicast destination.
HOST all_nodes_mcast { IP ff02::1 }

// INSTRUCTION: Define MLD query ensuring strict link-local Hop Limit 1.
FLOW mld_hoplimit_flow(rtr, mcast) {
    rtr -> mcast MLD QUERY TTL 1
}

// INSTRUCTION: Compile block enforcing single-hop MLD query transmission.
COMPILE {
    mld_hoplimit_flow(link_local_router, all_nodes_mcast)
}
""",

    "examples/l3/mld/mld_looped_membership_heartbeat.fasm": """// PROMPT: Continuous MLD membership report keepalive heartbeats inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, MLD, REPORT, MULTICAST_ADDR, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define IP camera streaming telemetry node.
HOST ip_camera_sensor { IP fe80::ca3e:1 }

// INSTRUCTION: Define surveillance multicast group target.
HOST security_dvr_grp { IP ff02::2 }

// INSTRUCTION: Define periodic MLD membership confirmation stream.
FLOW mld_camera_heartbeat(cam, dvr) {
    cam -> dvr MLD REPORT MULTICAST_ADDR ff05::5555 WAIT 20ms
}

// INSTRUCTION: Compile loop executing 4 continuous MLD reports.
COMPILE {
    LOOP 4 {
        mld_camera_heartbeat(ip_camera_sensor, security_dvr_grp)
    }
}
""",

    "examples/l3/mld/mld_dscp_network_control_query.fasm": """// PROMPT: MLD query prioritizing control traffic with DSCP Class Selector 6.
// TOKENS: HOST, IP, FLOW, ->, MLD, QUERY, DSCP, COMPILE

// INSTRUCTION: Define campus distribution switch querier.
HOST campus_querier_sw { IP fe80::c001:1 }

// INSTRUCTION: Define campus multicast nodes address.
HOST campus_nodes { IP ff02::1 }

// INSTRUCTION: Define DSCP CS6 prioritized query flow.
FLOW mld_dscp_control_flow(sw, nodes) {
    sw -> nodes MLD QUERY DSCP 48
}

// INSTRUCTION: Compile block executing DSCP prioritized query.
COMPILE {
    mld_dscp_control_flow(campus_querier_sw, campus_nodes)
}
""",

    "examples/l3/mld/mld_enterprise_conference_group_join.fasm": """// PROMPT: Enterprise videoconferencing terminal joining site-local multicast conference group.
// TOKENS: HOST, IP, FLOW, ->, MLD, REPORT, MULTICAST_ADDR, COMPILE

// INSTRUCTION: Define conference room codec terminal.
HOST conf_room_codec { IP fe80::a1b:2c3d:4e5f:6001 }

// INSTRUCTION: Define IPv6 all-routers gateway destination.
HOST all_rtrs_gw { IP ff02::2 }

// INSTRUCTION: Define MLD report subscribing to conference stream ff02::1:3.
FLOW conf_join_flow(codec, gw) {
    codec -> gw MLD REPORT MULTICAST_ADDR ff02::1:3
}

// INSTRUCTION: Compile block executing video conference join.
COMPILE {
    conf_join_flow(conf_room_codec, all_rtrs_gw)
}
""",

    "examples/l3/mld/mld_industrial_sensor_telemetry_group.fasm": """// PROMPT: Industrial SCADA sensor advertising membership in site-local multicast group ff05::100.
// TOKENS: HOST, IP, FLOW, ->, MLD, REPORT, MULTICAST_ADDR, TTL, COMPILE

// INSTRUCTION: Define factory floor pressure telemetry transducer.
HOST scada_pressure_sensor { IP fe80::9999:8888:7777:1111 }

// INSTRUCTION: Define plant industrial router address.
HOST plant_mld_router { IP ff02::2 }

// INSTRUCTION: Define MLD report for site-local telemetry group ff05::100.
FLOW scada_telemetry_join(sensor, rtr) {
    sensor -> rtr MLD REPORT MULTICAST_ADDR ff05::100 TTL 1
}

// INSTRUCTION: Compile block executing industrial sensor group join.
COMPILE {
    scada_telemetry_join(scada_pressure_sensor, plant_mld_router)
}
""",

    "examples/l3/mld/mld_dual_querier_election_suppression.fasm": """// PROMPT: Secondary querier observing higher priority querier General Query.
// TOKENS: HOST, IP, FLOW, ->, MLD, QUERY, MAX_RESP_DELAY, COMPILE

// INSTRUCTION: Define primary querier with lower numerical IP address.
HOST primary_querier { IP fe80::1 }

// INSTRUCTION: Define link-local all-nodes group including secondary querier.
HOST all_nodes_link { IP ff02::1 }

// INSTRUCTION: Define querier announcement query asserting active role.
FLOW querier_election_flow(p_q, nodes) {
    p_q -> nodes MLD QUERY MAX_RESP_DELAY 10000
}

// INSTRUCTION: Compile block executing querier election query.
COMPILE {
    querier_election_flow(primary_querier, all_nodes_link)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 MLD files generated and verified successfully.")
