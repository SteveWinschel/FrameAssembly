#!/usr/bin/env python3
"""Generate 12 new verified IPsec examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/ipsec/ipsec_aes_gcm_authenticated_payload.fasm": """// PROMPT: IPsec ESP tunnel carrying AES-GCM encrypted payload with explicit IV and ICV tags.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, IPSEC, SPI, SEQ, IV, ICV, PAYLOAD, COMPILE

// INSTRUCTION: Define primary data center IPsec security gateway.
HOST dc_sec_gw_alpha { IP 198.51.100.21 MAC 00:50:56:a1:00:01 }

// INSTRUCTION: Define disaster recovery IPsec security gateway.
HOST dr_sec_gw_beta { IP 203.0.113.88 MAC 00:50:56:b2:00:02 }

// INSTRUCTION: Define bidirectional IPsec flow exchanging encrypted blocks.
FLOW ipsec_aes_gcm_exchange(gw_a, gw_b) {
    gw_a -> gw_b IPSEC SPI 500101 SEQ 1 IV "1122334455667788" ICV "aabbccddeeff001122334455" PAYLOAD "encrypted_db_replication_block"
    gw_a <- gw_b IPSEC SPI 500102 SEQ 1 IV "8877665544332211" ICV "ffeeddccbbaa998877665544" PAYLOAD "encrypted_db_replication_ack"
}

// INSTRUCTION: Compile block executing AES-GCM protected tunnel transmission.
COMPILE {
    ipsec_aes_gcm_exchange(dc_sec_gw_alpha, dr_sec_gw_beta)
}
""",

    "examples/l3/ipsec/ipsec_anti_replay_window_advancement.fasm": """// PROMPT: IPsec ESP packet sequence advancing anti-replay verification window.
// TOKENS: HOST, IP, FLOW, ->, IPSEC, SPI, SEQ, WAIT, ms, COMPILE

// INSTRUCTION: Define finance transaction server gateway.
HOST fin_tx_gw { IP 10.160.12.1 }

// INSTRUCTION: Define settlement clearinghouse endpoint.
HOST clearing_hub { IP 10.160.12.254 }

// INSTRUCTION: Define sequenced IPsec transmission testing anti-replay window state.
FLOW ipsec_seq_advancement(src, dst) {
    src -> dst IPSEC SPI 91000 SEQ 1000 WAIT 1ms
    src -> dst IPSEC SPI 91000 SEQ 1001 WAIT 1ms
    src -> dst IPSEC SPI 91000 SEQ 1002 WAIT 1ms
    src -> dst IPSEC SPI 91000 SEQ 1003
}

// INSTRUCTION: Compile block executing sequence advancement.
COMPILE {
    ipsec_seq_advancement(fin_tx_gw, clearing_hub)
}
""",

    "examples/l3/ipsec/ipsec_site_to_site_branch_transit.fasm": """// PROMPT: Enterprise branch-to-headquarters IPsec VPN transit marked with DSCP EF.
// TOKENS: HOST, IP, FLOW, ->, <-, IPSEC, SPI, SEQ, DSCP, TTL, COMPILE

// INSTRUCTION: Define retail branch office security gateway.
HOST branch_store_gw { IP 172.24.10.1 }

// INSTRUCTION: Define corporate headquarters VPN concentrator.
HOST hq_vpn_concentrator { IP 172.24.100.1 }

// INSTRUCTION: Define expedited forwarding IPsec tunnel flow for VoIP traffic.
FLOW branch_hq_ipsec_flow(br, hq) {
    br -> hq IPSEC SPI 65536 SEQ 50 DSCP 46 TTL 64
    br <- hq IPSEC SPI 65537 SEQ 80 DSCP 46 TTL 64
}

// INSTRUCTION: Compile block executing site-to-site branch transit.
COMPILE {
    branch_hq_ipsec_flow(branch_store_gw, hq_vpn_concentrator)
}
""",

    "examples/l3/ipsec/ipsec_ipv6_mobile_node_security.fasm": """// PROMPT: Mobile IPv6 node establishing IPsec protected communication with home agent.
// TOKENS: HOST, IP, FLOW, ->, <-, IPSEC, SPI, SEQ, FLOWLABEL, COMPILE

// INSTRUCTION: Define roaming IPv6 mobile client endpoint.
HOST mobile_ipv6_node { IP 2001:db8:cafe:11::99 }

// INSTRUCTION: Define IPv6 corporate home agent gateway.
HOST home_agent_v6 { IP 2001:db8:cafe:ff::1 }

// INSTRUCTION: Define protected IPv6 IPsec transport maintaining FlowLabel 104857.
FLOW mobile_ipsec_v6_flow(node, ha) {
    node -> ha IPSEC SPI 77701 SEQ 12 FLOWLABEL 104857
    node <- ha IPSEC SPI 77702 SEQ 15 FLOWLABEL 104857
}

// INSTRUCTION: Compile block executing IPv6 mobile node security exchange.
COMPILE {
    mobile_ipsec_v6_flow(mobile_ipv6_node, home_agent_v6)
}
""",

    "examples/l3/ipsec/ipsec_rekeying_soft_lifetime_burst.fasm": """// PROMPT: Periodic IPsec security association heartbeat burst inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, IPSEC, SPI, SEQ, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define banking transactions gateway A.
HOST bank_gw_a { IP 10.220.5.10 }

// INSTRUCTION: Define banking transactions gateway B.
HOST bank_gw_b { IP 10.220.5.20 }

// INSTRUCTION: Define IPsec heartbeat flow verifying tunnel continuity.
FLOW ipsec_heartbeat_flow(g1, g2) {
    g1 -> g2 IPSEC SPI 88000 SEQ 500 WAIT 10ms
}

// INSTRUCTION: Compile loop executing 5 IPsec keepalive packets.
COMPILE {
    LOOP 5 {
        ipsec_heartbeat_flow(bank_gw_a, bank_gw_b)
    }
}
""",

    "examples/l3/ipsec/ipsec_ecn_congestion_experienced.fasm": """// PROMPT: IPsec ESP frame marked with Explicit Congestion Notification Congestion Experienced (ECN 3).
// TOKENS: HOST, IP, FLOW, ->, IPSEC, SPI, SEQ, ECN, DSCP, COMPILE

// INSTRUCTION: Define border router forwarding WAN traffic.
HOST wan_edge_router { IP 192.0.2.14 }

// INSTRUCTION: Define destination security appliance.
HOST sec_appliance_peer { IP 192.0.2.29 }

// INSTRUCTION: Define ECN Congestion Experienced marked IPsec packet flow.
FLOW ipsec_ecn_flow(rtr, sec) {
    rtr -> sec IPSEC SPI 44300 SEQ 77 DSCP 18 ECN 3
}

// INSTRUCTION: Compile block transmitting ECN marked IPsec frame.
COMPILE {
    ipsec_ecn_flow(wan_edge_router, sec_appliance_peer)
}
""",

    "examples/l3/ipsec/ipsec_inter_cloud_vpc_peering.fasm": """// PROMPT: Cloud VPC interconnect over IPv6 IPsec transport with custom SPI parameters.
// TOKENS: HOST, IP, FLOW, ->, <-, IPSEC, SPI, SEQ, COMPILE

// INSTRUCTION: Define AWS cloud virtual gateway endpoint.
HOST aws_transit_gw { IP 2001:db8:a001::1 }

// INSTRUCTION: Define Google Cloud VPN router endpoint.
HOST gcp_cloud_router { IP 2001:db8:b002::2 }

// INSTRUCTION: Define cross-cloud IPsec tunnel synchronization flow.
FLOW cloud_peering_ipsec(aws, gcp) {
    aws -> gcp IPSEC SPI 90123 SEQ 1
    aws <- gcp IPSEC SPI 90124 SEQ 1
}

// INSTRUCTION: Compile block executing cloud VPC interconnect tunnel.
COMPILE {
    cloud_peering_ipsec(aws_transit_gw, gcp_cloud_router)
}
""",

    "examples/l3/ipsec/ipsec_industrial_scada_perimeter.fasm": """// PROMPT: Substation SCADA perimeter gateway protecting RTU telemetry via IPsec ESP.
// TOKENS: HOST, IP, MAC, FLOW, ->, IPSEC, SPI, SEQ, TTL, PAYLOAD, COMPILE

// INSTRUCTION: Define electric grid substation perimeter gateway.
HOST scada_substation_gw { IP 10.99.4.1 MAC 00:1c:73:99:04:01 }

// INSTRUCTION: Define central energy management operations center.
HOST energy_ops_center { IP 10.99.100.10 MAC 00:1c:73:99:64:0a }

// INSTRUCTION: Define SCADA telemetry IPsec encapsulation flow with single-hop TTL.
FLOW scada_ipsec_telemetry(sub, ops) {
    sub -> ops IPSEC SPI 123456 SEQ 42 TTL 32 PAYLOAD "DNP3_IEC61850_TELEMETRY_PAYLOAD"
}

// INSTRUCTION: Compile block executing SCADA telemetry protection.
COMPILE {
    scada_ipsec_telemetry(scada_substation_gw, energy_ops_center)
}
""",

    "examples/l3/ipsec/ipsec_zero_trust_edge_authenticator.fasm": """// PROMPT: Zero Trust network access edge node establishing IPsec channel to policy enforcement point.
// TOKENS: HOST, IP, FLOW, ->, <-, IPSEC, SPI, SEQ, IV, COMPILE

// INSTRUCTION: Define Zero Trust edge connector host.
HOST ztna_edge_connector { IP 172.30.50.15 }

// INSTRUCTION: Define central Policy Enforcement Point gateway.
HOST ztna_pep_gateway { IP 172.30.50.1 }

// INSTRUCTION: Define authenticated ZTNA micro-tunnel initiation flow.
FLOW ztna_ipsec_handshake(edge, pep) {
    edge -> pep IPSEC SPI 314159 SEQ 1 IV "0011223344556677"
    edge <- pep IPSEC SPI 314160 SEQ 1 IV "8899aabbccddeeff"
}

// INSTRUCTION: Compile block executing ZTNA IPsec setup.
COMPILE {
    ztna_ipsec_handshake(ztna_edge_connector, ztna_pep_gateway)
}
""",

    "examples/l3/ipsec/ipsec_remote_access_client_handshake.fasm": """// PROMPT: Remote teleworker establishing IPsec tunnel session to corporate gateway.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, IPSEC, SPI, SEQ, COMPILE

// INSTRUCTION: Define remote worker telecommuting laptop.
HOST teleworker_laptop { IP 192.168.88.50 MAC 00:0c:29:88:50:01 }

// INSTRUCTION: Define enterprise corporate VPN aggregator.
HOST corp_vpn_aggregator { IP 198.51.100.254 MAC 00:0c:29:aa:bb:cc }

// INSTRUCTION: Define bidirectional remote access IPsec exchange.
FLOW remote_access_ipsec(client, vpn) {
    client -> vpn IPSEC SPI 40001 SEQ 1
    client <- vpn IPSEC SPI 40002 SEQ 1
}

// INSTRUCTION: Compile block executing remote access handshake.
COMPILE {
    remote_access_ipsec(teleworker_laptop, corp_vpn_aggregator)
}
""",

    "examples/l3/ipsec/ipsec_high_capacity_core_backbone.fasm": """// PROMPT: High capacity backbone core router IPsec encryption with custom DSCP Class Selector 4.
// TOKENS: HOST, IP, FLOW, ->, IPSEC, SPI, SEQ, DSCP, TTL, COMPILE

// INSTRUCTION: Define Frankfurt core transit router.
HOST core_router_fra { IP 172.18.1.1 }

// INSTRUCTION: Define London core transit router.
HOST core_router_lon { IP 172.18.1.2 }

// INSTRUCTION: Define backbone bulk transport IPsec flow marked with CS4.
FLOW backbone_ipsec_flow(fra, lon) {
    fra -> lon IPSEC SPI 888100 SEQ 9999 DSCP 32 TTL 128
}

// INSTRUCTION: Compile block executing high capacity backbone IPsec transmission.
COMPILE {
    backbone_ipsec_flow(core_router_fra, core_router_lon)
}
""",

    "examples/l3/ipsec/ipsec_failover_redundant_peer.fasm": """// PROMPT: Redundant failover IPsec gateway taking over active tunnel SPI session.
// TOKENS: HOST, IP, FLOW, ->, IPSEC, SPI, SEQ, COMPILE

// INSTRUCTION: Define secondary failover VPN appliance.
HOST failover_vpn_appliance { IP 192.0.2.202 }

// INSTRUCTION: Define remote data center endpoint.
HOST remote_dc_peer { IP 192.0.2.1 }

// INSTRUCTION: Define failover resumption flow carrying state sequence 10001.
FLOW failover_ipsec_flow(sec_app, dc) {
    sec_app -> dc IPSEC SPI 700500 SEQ 10001
}

// INSTRUCTION: Compile block executing failover tunnel transmission.
COMPILE {
    failover_ipsec_flow(failover_vpn_appliance, remote_dc_peer)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 IPsec files generated and verified successfully.")
