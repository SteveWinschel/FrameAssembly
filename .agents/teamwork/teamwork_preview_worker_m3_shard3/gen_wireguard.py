#!/usr/bin/env python3
"""Generate 12 new verified WireGuard examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/wireguard/wireguard_cookie_reply_dos_mitigation.fasm": """// PROMPT: WireGuard concentrator issuing Cookie Reply to mitigate denial-of-service flood.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, COOKIE, RECEIVER, COMPILE

// INSTRUCTION: Define high-capacity WireGuard VPN concentrator under load.
HOST wg_loaded_concentrator { IP 198.51.100.1 }

// INSTRUCTION: Define incoming peer connection endpoint.
HOST wg_incoming_peer { IP 203.0.113.77 }

// INSTRUCTION: Define Cookie Reply transmission flow challenging peer authenticity.
FLOW wg_cookie_mitigation_flow(conc, peer) {
    conc -> peer WIREGUARD TYPE COOKIE RECEIVER 987654321
}

// INSTRUCTION: Compile block executing Cookie challenge reply.
COMPILE {
    wg_cookie_mitigation_flow(wg_loaded_concentrator, wg_incoming_peer)
}
""",

    "examples/l3/wireguard/wireguard_counter_replay_advancement.fasm": """// PROMPT: WireGuard encrypted transport data packet advancing 64-bit transmission counter.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, DATA, RECEIVER, COUNTER, PAYLOAD, COMPILE

// INSTRUCTION: Define enterprise VPN client station.
HOST wg_client_station { IP 10.70.1.15 }

// INSTRUCTION: Define central VPN gateway endpoint.
HOST wg_central_gw { IP 10.70.1.1 }

// INSTRUCTION: Define sequenced WireGuard data transport flow with counter increment.
FLOW wg_data_counter_flow(cli, gw) {
    cli -> gw WIREGUARD TYPE DATA RECEIVER 409600 COUNTER 1050 PAYLOAD "ENCRYPTED_DATABASE_RECORD"
}

// INSTRUCTION: Compile block executing counter advanced data transmission.
COMPILE {
    wg_data_counter_flow(wg_client_station, wg_central_gw)
}
""",

    "examples/l3/wireguard/wireguard_rekeying_initiation_burst.fasm": """// PROMPT: WireGuard peer initiating scheduled session rekeying via Handshake Initiation on UDP 51820.
// TOKENS: HOST, IP, FLOW, ->, <-, WIREGUARD, TYPE, INITIATION, RESPONSE, SENDER, RECEIVER, COMPILE

// INSTRUCTION: Define branch office VPN gateway peer.
HOST wg_branch_peer { IP 172.16.200.1 }

// INSTRUCTION: Define data center VPN gateway peer.
HOST wg_dc_peer { IP 172.16.200.2 }

// INSTRUCTION: Define rekeying handshake exchange establishing fresh key material.
FLOW wg_rekey_exchange(br, dc) {
    br -> dc WIREGUARD TYPE INITIATION SENDER 334455
    br <- dc WIREGUARD TYPE RESPONSE SENDER 778899 RECEIVER 334455
}

// INSTRUCTION: Compile block executing WireGuard session rekeying.
COMPILE {
    wg_rekey_exchange(wg_branch_peer, wg_dc_peer)
}
""",

    "examples/l3/wireguard/wireguard_vlan_tagged_gateway_trunk.fasm": """// PROMPT: WireGuard VPN tunnel terminating on 802.1Q tagged security VLAN 150.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, INITIATION, SENDER, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define corporate security VLAN VPN gateway.
HOST wg_vlan_sec_gw { IP 10.150.0.1 }

// INSTRUCTION: Define remote branch VPN initiator.
HOST wg_branch_initiator { IP 10.150.0.254 }

// INSTRUCTION: Define 802.1Q tagged WireGuard initiation flow with Priority PCP 5.
FLOW wg_vlan_tagged_flow(gw, peer) {
    peer -> gw WIREGUARD TYPE INITIATION SENDER 112233 VLAN 150 PCP 5 DEI 0
}

// INSTRUCTION: Compile block executing tagged WireGuard handshake initiation.
COMPILE {
    wg_vlan_tagged_flow(wg_vlan_sec_gw, wg_branch_initiator)
}
""",

    "examples/l3/wireguard/wireguard_qinq_carrier_vpn_transport.fasm": """// PROMPT: Dual-tagged QinQ carrier transport carrying WireGuard encrypted tunnel.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, DATA, RECEIVER, COUNTER, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define enterprise site router.
HOST enterprise_site_rtr { IP 192.168.188.1 }

// INSTRUCTION: Define carrier provider edge router.
HOST carrier_edge_rtr { IP 192.168.188.2 }

// INSTRUCTION: Define QinQ encapsulated WireGuard data flow on service VLAN 600 and customer VLAN 88.
FLOW wg_qinq_carrier_flow(site, edge) {
    site -> edge WIREGUARD TYPE DATA RECEIVER 55500 COUNTER 42 QINQ 600 INNER_VLAN 88
}

// INSTRUCTION: Compile block executing carrier QinQ WireGuard transmission.
COMPILE {
    wg_qinq_carrier_flow(enterprise_site_rtr, carrier_edge_rtr)
}
""",

    "examples/l3/wireguard/wireguard_mpls_backbone_transit.fasm": """// PROMPT: WireGuard UDP 51820 datagrams traversing MPLS core network with label 7700.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, INITIATION, SENDER, MPLS, COMPILE

// INSTRUCTION: Define MPLS ingress provider edge router.
HOST mpls_wg_ingress { IP 10.222.1.1 }

// INSTRUCTION: Define MPLS core destination router.
HOST mpls_wg_egress { IP 10.222.1.2 }

// INSTRUCTION: Define MPLS labeled WireGuard initiation flow.
FLOW wg_mpls_transit_flow(ing, eg) {
    ing -> eg WIREGUARD TYPE INITIATION SENDER 889900 MPLS 7700
}

// INSTRUCTION: Compile block executing MPLS encapsulated WireGuard transit.
COMPILE {
    wg_mpls_transit_flow(mpls_wg_ingress, mpls_wg_egress)
}
""",

    "examples/l3/wireguard/wireguard_ipv6_transport_encrypted_data.fasm": """// PROMPT: Pure IPv6 WireGuard transport carrying sequenced encrypted data packets.
// TOKENS: HOST, IP, FLOW, ->, <-, WIREGUARD, TYPE, DATA, RECEIVER, COUNTER, COMPILE

// INSTRUCTION: Define IPv6 WireGuard host alpha.
HOST wg_v6_host_alpha { IP 2001:db8:beef:2::10 }

// INSTRUCTION: Define IPv6 WireGuard host beta.
HOST wg_v6_host_beta { IP 2001:db8:beef:2::20 }

// INSTRUCTION: Define bidirectional IPv6 WireGuard data transmission flow.
FLOW wg_v6_data_exchange(a, b) {
    a -> b WIREGUARD TYPE DATA RECEIVER 2001 COUNTER 100
    a <- b WIREGUARD TYPE DATA RECEIVER 1001 COUNTER 50
}

// INSTRUCTION: Compile block executing IPv6 WireGuard data exchange.
COMPILE {
    wg_v6_data_exchange(wg_v6_host_alpha, wg_v6_host_beta)
}
""",

    "examples/l3/wireguard/wireguard_looped_keepalive_burst.fasm": """// PROMPT: Periodic WireGuard authenticated keepalive packet burst inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, DATA, RECEIVER, COUNTER, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define remote mobile worker maintaining tunnel NAT mapping.
HOST roaming_nat_client { IP 192.0.2.77 }

// INSTRUCTION: Define enterprise VPN gateway endpoint.
HOST enterprise_vpn_gw { IP 198.51.100.10 }

// INSTRUCTION: Define periodic WireGuard keepalive burst flow.
FLOW wg_keepalive_burst(cli, gw) {
    cli -> gw WIREGUARD TYPE DATA RECEIVER 12345 COUNTER 0 WAIT 25ms
}

// INSTRUCTION: Compile loop executing 4 periodic WireGuard keepalives.
COMPILE {
    LOOP 4 {
        wg_keepalive_burst(roaming_nat_client, enterprise_vpn_gw)
    }
}
""",

    "examples/l3/wireguard/wireguard_dscp_expedited_forwarding_vpn.fasm": """// PROMPT: WireGuard VPN prioritizing voice/video packets with DSCP Expedited Forwarding (DSCP 46).
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, DATA, RECEIVER, COUNTER, DSCP, TTL, COMPILE

// INSTRUCTION: Define unified communications VoIP server.
HOST voip_media_server { IP 172.20.10.5 }

// INSTRUCTION: Define remote branch VoIP gateway.
HOST branch_voip_gateway { IP 172.20.10.1 }

// INSTRUCTION: Define DSCP EF marked WireGuard voice transport flow.
FLOW wg_voip_ef_flow(src, dst) {
    src -> dst WIREGUARD TYPE DATA RECEIVER 654321 COUNTER 888 DSCP 46 TTL 64
}

// INSTRUCTION: Compile block executing prioritized WireGuard voice packet.
COMPILE {
    wg_voip_ef_flow(voip_media_server, branch_voip_gateway)
}
""",

    "examples/l3/wireguard/wireguard_mobile_roaming_endpoint_migration.fasm": """// PROMPT: WireGuard peer endpoint migration confirming updated external client address.
// TOKENS: HOST, IP, FLOW, ->, <-, WIREGUARD, TYPE, INITIATION, RESPONSE, SENDER, RECEIVER, COMPILE

// INSTRUCTION: Define mobile smartphone roaming to cellular network.
HOST mobile_smartphone { IP 198.51.100.99 }

// INSTRUCTION: Define corporate WireGuard access hub.
HOST corp_wg_access_hub { IP 203.0.113.1 }

// INSTRUCTION: Define roaming re-association handshake flow.
FLOW wg_roaming_migration(phone, hub) {
    phone -> hub WIREGUARD TYPE INITIATION SENDER 991122
    phone <- hub WIREGUARD TYPE RESPONSE SENDER 554433 RECEIVER 991122
}

// INSTRUCTION: Compile block executing mobile roaming re-association.
COMPILE {
    wg_roaming_migration(mobile_smartphone, corp_wg_access_hub)
}
""",

    "examples/l3/wireguard/wireguard_site_to_site_branch_mesh.fasm": """// PROMPT: Site-to-site branch routers establishing direct WireGuard mesh peering.
// TOKENS: HOST, IP, FLOW, ->, <-, WIREGUARD, TYPE, INITIATION, RESPONSE, SENDER, RECEIVER, COMPILE

// INSTRUCTION: Define Branch Office Tokyo gateway.
HOST wg_branch_tokyo { IP 10.210.1.1 }

// INSTRUCTION: Define Branch Office Sydney gateway.
HOST wg_branch_sydney { IP 10.210.2.1 }

// INSTRUCTION: Define mutual branch mesh tunnel establishment flow.
FLOW wg_mesh_peering_flow(tokyo, sydney) {
    tokyo -> sydney WIREGUARD TYPE INITIATION SENDER 70701
    tokyo <- sydney WIREGUARD TYPE RESPONSE SENDER 70702 RECEIVER 70701
}

// INSTRUCTION: Compile block executing direct branch mesh setup.
COMPILE {
    wg_mesh_peering_flow(wg_branch_tokyo, wg_branch_sydney)
}
""",

    "examples/l3/wireguard/wireguard_iot_sensor_gateway_burst.fasm": """// PROMPT: Embedded IoT gateway transmitting encrypted telemetry to cloud WireGuard receiver.
// TOKENS: HOST, IP, FLOW, ->, WIREGUARD, TYPE, DATA, RECEIVER, COUNTER, PAYLOAD, COMPILE

// INSTRUCTION: Define environmental IoT sensor gateway.
HOST iot_sensor_node { IP 172.30.99.10 }

// INSTRUCTION: Define cloud IoT telemetry receiver.
HOST cloud_iot_receiver { IP 172.30.99.1 }

// INSTRUCTION: Define telemetry data payload transmission flow.
FLOW wg_iot_telemetry_flow(sensor, cloud) {
    sensor -> cloud WIREGUARD TYPE DATA RECEIVER 90901 COUNTER 1 PAYLOAD "SENSOR_TEMP_HUMIDITY_DATA"
}

// INSTRUCTION: Compile block executing IoT sensor encrypted telemetry.
COMPILE {
    wg_iot_telemetry_flow(iot_sensor_node, cloud_iot_receiver)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 WireGuard files generated and verified successfully.")
