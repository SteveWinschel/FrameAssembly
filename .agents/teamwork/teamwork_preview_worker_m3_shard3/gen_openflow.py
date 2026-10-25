#!/usr/bin/env python3
"""Generate 12 new verified OpenFlow examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/openflow/openflow_features_request_reply_handshake.fasm": """// PROMPT: OpenFlow controller querying datapath capabilities via FEATURES_REQ and FEATURES_REPLY exchange.
// TOKENS: HOST, IP, FLOW, ->, <-, OPENFLOW, TYPE, FEATURES_REQ, FEATURES_REPLY, XID, COMPILE

// INSTRUCTION: Define centralized SDN network controller.
HOST sdn_central_ctrl { IP 10.100.1.10 }

// INSTRUCTION: Define programmable openflow switch datapath.
HOST sdn_openflow_sw { IP 10.100.1.20 }

// INSTRUCTION: Define features negotiation exchange flow on port 6653.
FLOW of_features_handshake(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE FEATURES_REQ XID 101
    ctrl <- sw OPENFLOW TYPE FEATURES_REPLY XID 101
}

// INSTRUCTION: Compile block executing OpenFlow features request and reply.
COMPILE {
    of_features_handshake(sdn_central_ctrl, sdn_openflow_sw)
}
""",

    "examples/l3/openflow/openflow_packet_in_table_miss.fasm": """// PROMPT: OpenFlow datapath forwarding unhandled frame to controller via PACKET_IN message.
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, PACKET_IN, XID, PAYLOAD, COMPILE

// INSTRUCTION: Define edge access switch datapath.
HOST edge_access_sw { IP 172.16.20.2 }

// INSTRUCTION: Define cloud-native SDN controller.
HOST cloud_sdn_ctrl { IP 172.16.20.1 }

// INSTRUCTION: Define PACKET_IN notification carrying buffer miss payload.
FLOW of_packet_in_flow(sw, ctrl) {
    sw -> ctrl OPENFLOW TYPE PACKET_IN XID 2001 PAYLOAD "BUFFER_TABLE_MISS_RAW_FRAME"
}

// INSTRUCTION: Compile block executing PACKET_IN event.
COMPILE {
    of_packet_in_flow(edge_access_sw, cloud_sdn_ctrl)
}
""",

    "examples/l3/openflow/openflow_packet_out_controller_injection.fasm": """// PROMPT: OpenFlow controller sending PACKET_OUT message injecting Ethernet frame onto physical port.
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, PACKET_OUT, XID, PAYLOAD, COMPILE

// INSTRUCTION: Define SDN orchestrator controller.
HOST sdn_orchestrator { IP 192.168.10.1 }

// INSTRUCTION: Define target fabric switch.
HOST fabric_target_sw { IP 192.168.10.100 }

// INSTRUCTION: Define PACKET_OUT frame injection flow.
FLOW of_packet_out_flow(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE PACKET_OUT XID 3050 PAYLOAD "ARP_INJECTED_PACKET_PAYLOAD"
}

// INSTRUCTION: Compile block executing PACKET_OUT transmission.
COMPILE {
    of_packet_out_flow(sdn_orchestrator, fabric_target_sw)
}
""",

    "examples/l3/openflow/openflow_flow_mod_delete_expired.fasm": """// PROMPT: OpenFlow controller modifying switch flow table via FLOW_MOD with custom table ID and priority.
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, FLOW_MOD, XID, TABLE_ID, PRIORITY, COMPILE

// INSTRUCTION: Define enterprise policy controller.
HOST enterprise_policy_ctrl { IP 10.50.1.1 }

// INSTRUCTION: Define campus distribution switch datapath.
HOST campus_dist_sw { IP 10.50.1.254 }

// INSTRUCTION: Define FLOW_MOD rule installation flow targeting table 2 with priority 500.
FLOW of_flow_mod_rule(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE FLOW_MOD XID 4004 TABLE_ID 2 PRIORITY 500
}

// INSTRUCTION: Compile block executing FLOW_MOD instruction.
COMPILE {
    of_flow_mod_rule(enterprise_policy_ctrl, campus_dist_sw)
}
""",

    "examples/l3/openflow/openflow_echo_keepalive_liveness_heartbeat.fasm": """// PROMPT: Bidirectional OpenFlow ECHO_REQ and ECHO_REPLY keepalive exchange verifying channel liveness.
// TOKENS: HOST, IP, FLOW, ->, <-, OPENFLOW, TYPE, ECHO_REQ, ECHO_REPLY, XID, COMPILE

// INSTRUCTION: Define cluster SDN controller node.
HOST cluster_sdn_ctrl { IP 172.28.1.5 }

// INSTRUCTION: Define monitored OpenFlow spine switch.
HOST spine_openflow_sw { IP 172.28.1.15 }

// INSTRUCTION: Define echo keepalive exchange flow with matching XID.
FLOW of_echo_liveness(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE ECHO_REQ XID 9999
    ctrl <- sw OPENFLOW TYPE ECHO_REPLY XID 9999
}

// INSTRUCTION: Compile block executing echo keepalive heartbeat.
COMPILE {
    of_echo_liveness(cluster_sdn_ctrl, spine_openflow_sw)
}
""",

    "examples/l3/openflow/openflow_vlan_tagged_sdn_control_channel.fasm": """// PROMPT: 802.1Q tagged OpenFlow control channel running on out-of-band management VLAN 99.
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, HELLO, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define out-of-band network controller.
HOST oob_sdn_controller { IP 192.168.99.1 }

// INSTRUCTION: Define remote rack switch management interface.
HOST rack_mgmt_switch { IP 192.168.99.20 }

// INSTRUCTION: Define VLAN 99 tagged OpenFlow HELLO flow.
FLOW of_vlan_control_flow(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE HELLO VLAN 99 PCP 5 DEI 0
}

// INSTRUCTION: Compile block executing VLAN tagged OpenFlow session setup.
COMPILE {
    of_vlan_control_flow(oob_sdn_controller, rack_mgmt_switch)
}
""",

    "examples/l3/openflow/openflow_qinq_carrier_transport_sdn.fasm": """// PROMPT: Dual-tagged QinQ OpenFlow session across carrier transport with DSCP EF marking.
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, HELLO, QINQ, INNER_VLAN, DSCP, COMPILE

// INSTRUCTION: Define regional WAN SDN controller.
HOST wan_sdn_controller { IP 10.240.0.1 }

// INSTRUCTION: Define customer edge SDN gateway switch.
HOST ce_sdn_gateway { IP 10.240.0.50 }

// INSTRUCTION: Define QinQ encapsulated OpenFlow session flow.
FLOW of_qinq_carrier_flow(ctrl, ce) {
    ctrl -> ce OPENFLOW TYPE HELLO QINQ 200 INNER_VLAN 50 DSCP 46
}

// INSTRUCTION: Compile block executing carrier QinQ OpenFlow connection.
COMPILE {
    of_qinq_carrier_flow(wan_sdn_controller, ce_sdn_gateway)
}
""",

    "examples/l3/openflow/openflow_ipv6_control_plane_peering.fasm": """// PROMPT: Pure IPv6 OpenFlow 1.3 control channel between cloud controller and virtual switch.
// TOKENS: HOST, IP, FLOW, ->, <-, OPENFLOW, TYPE, HELLO, ECHO_REQ, ECHO_REPLY, XID, COMPILE

// INSTRUCTION: Define IPv6 SDN control plane cluster.
HOST sdn_v6_controller { IP 2001:db8:5d01::1 }

// INSTRUCTION: Define IPv6 programmable virtual switch.
HOST sdn_v6_vswitch { IP 2001:db8:5d01::10 }

// INSTRUCTION: Define IPv6 OpenFlow session setup and echo flow.
FLOW of_ipv6_session_flow(ctrl, vsw) {
    ctrl -> vsw OPENFLOW TYPE HELLO
    ctrl <- vsw OPENFLOW TYPE HELLO
    ctrl -> vsw OPENFLOW TYPE ECHO_REQ XID 1001
    ctrl <- vsw OPENFLOW TYPE ECHO_REPLY XID 1001
}

// INSTRUCTION: Compile block executing IPv6 OpenFlow session.
COMPILE {
    of_ipv6_session_flow(sdn_v6_controller, sdn_v6_vswitch)
}
""",

    "examples/l3/openflow/openflow_looped_stat_polling_cycle.fasm": """// PROMPT: Periodic OpenFlow echo keepalive requests inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, ECHO_REQ, XID, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define telemetry polling SDN controller.
HOST stat_polling_ctrl { IP 172.31.10.1 }

// INSTRUCTION: Define leaf switch datapath.
HOST telemetry_leaf_sw { IP 172.31.10.22 }

// INSTRUCTION: Define periodic echo polling transmission flow.
FLOW of_echo_poll_flow(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE ECHO_REQ XID 5050 WAIT 25ms
}

// INSTRUCTION: Compile loop executing 4 periodic echo polls.
COMPILE {
    LOOP 4 {
        of_echo_poll_flow(stat_polling_ctrl, telemetry_leaf_sw)
    }
}
""",

    "examples/l3/openflow/openflow_multi_table_pipeline_installation.fasm": """// PROMPT: OpenFlow controller configuring table 1 pipeline flow rule with high priority (65535).
// TOKENS: HOST, IP, FLOW, ->, OPENFLOW, TYPE, FLOW_MOD, XID, TABLE_ID, PRIORITY, COMPILE

// INSTRUCTION: Define security enforcement SDN controller.
HOST security_sdn_ctrl { IP 10.180.1.1 }

// INSTRUCTION: Define core pipeline switch.
HOST pipeline_core_sw { IP 10.180.1.2 }

// INSTRUCTION: Define high priority flow table installation flow.
FLOW of_pipeline_flow_mod(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE FLOW_MOD XID 7007 TABLE_ID 1 PRIORITY 65535
}

// INSTRUCTION: Compile block executing pipeline flow table rule installation.
COMPILE {
    of_pipeline_flow_mod(security_sdn_ctrl, pipeline_core_sw)
}
""",

    "examples/l3/openflow/openflow_custom_xid_correlation.fasm": """// PROMPT: OpenFlow transactions with sequential transaction IDs (XID) tracking request responses.
// TOKENS: HOST, IP, FLOW, ->, <-, OPENFLOW, TYPE, ECHO_REQ, ECHO_REPLY, XID, COMPILE

// INSTRUCTION: Define network operating system controller.
HOST nos_ctrl_node { IP 192.168.70.1 }

// INSTRUCTION: Define fabric aggregator switch.
HOST fabric_agg_node { IP 192.168.70.2 }

// INSTRUCTION: Define correlated transaction flow with XID 10001.
FLOW of_xid_tracking_flow(ctrl, sw) {
    ctrl -> sw OPENFLOW TYPE ECHO_REQ XID 10001
    ctrl <- sw OPENFLOW TYPE ECHO_REPLY XID 10001
}

// INSTRUCTION: Compile block executing correlated OpenFlow transaction.
COMPILE {
    of_xid_tracking_flow(nos_ctrl_node, fabric_agg_node)
}
""",

    "examples/l3/openflow/openflow_campus_switch_bootstrap.fasm": """// PROMPT: Freshly booted campus edge switch establishing OpenFlow control session via HELLO and ECHO.
// TOKENS: HOST, IP, FLOW, ->, <-, OPENFLOW, TYPE, HELLO, ECHO_REQ, ECHO_REPLY, XID, COMPILE

// INSTRUCTION: Define centralized campus SDN director.
HOST campus_sdn_director { IP 10.10.10.1 }

// INSTRUCTION: Define newly provisioned campus edge switch.
HOST boot_edge_switch { IP 10.10.10.55 }

// INSTRUCTION: Define switch bootstrap control channel initiation flow.
FLOW of_switch_bootstrap(dir, sw) {
    sw -> dir OPENFLOW TYPE HELLO
    dir -> sw OPENFLOW TYPE HELLO
    dir -> sw OPENFLOW TYPE ECHO_REQ XID 1
    sw -> dir OPENFLOW TYPE ECHO_REPLY XID 1
}

// INSTRUCTION: Compile block executing edge switch bootstrap handshake.
COMPILE {
    of_switch_bootstrap(campus_sdn_director, boot_edge_switch)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 OpenFlow files generated and verified successfully.")
