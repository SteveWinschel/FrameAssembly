#!/usr/bin/env python3
"""Generate 12 new verified VXLAN examples."""

from generate_shard3 import write_fasm

FILES = {
    "examples/l3/vxlan/vxlan_multi_tenant_vni_isolation.fasm": """// PROMPT: Multi-tenant data center overlay isolating tenant network segments using VNI 100200.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, COMPILE

// INSTRUCTION: Define tenant hypervisor VTEP gateway 1.
HOST tenant_vtep_1 { IP 10.100.1.1 }

// INSTRUCTION: Define tenant hypervisor VTEP gateway 2.
HOST tenant_vtep_2 { IP 10.100.1.2 }

// INSTRUCTION: Define VXLAN tenant encapsulation flow with VNI 100200.
FLOW vxlan_tenant_flow(v1, v2) {
    v1 -> v2 VXLAN VNI 100200
}

// INSTRUCTION: Compile block executing multi-tenant VXLAN tunnel encapsulation.
COMPILE {
    vxlan_tenant_flow(tenant_vtep_1, tenant_vtep_2)
}
""",

    "examples/l3/vxlan/vxlan_dscp_underlay_qos_preservation.fasm": """// PROMPT: VXLAN underlay transport preserving DSCP AF41 QoS markings for interactive video overlay.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, DSCP, TTL, COMPILE

// INSTRUCTION: Define media streaming VTEP node.
HOST media_vtep_src { IP 172.16.80.1 }

// INSTRUCTION: Define remote media cache VTEP node.
HOST media_vtep_dst { IP 172.16.80.2 }

// INSTRUCTION: Define QoS marked VXLAN tunnel transmission with DSCP AF41 (DSCP 34).
FLOW vxlan_qos_flow(src, dst) {
    src -> dst VXLAN VNI 40001 DSCP 34 TTL 64
}

// INSTRUCTION: Compile block executing DSCP prioritized VXLAN packet.
COMPILE {
    vxlan_qos_flow(media_vtep_src, media_vtep_dst)
}
""",

    "examples/l3/vxlan/vxlan_custom_udp_source_port_entropy.fasm": """// PROMPT: VXLAN packet with customized hash-based UDP source port 54321 for ECMP underlay load balancing.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, SRCPORT, COMPILE

// INSTRUCTION: Define leaf switch VTEP generating ECMP entropy source ports.
HOST ecmp_leaf_vtep { IP 192.168.220.10 }

// INSTRUCTION: Define destination leaf switch VTEP.
HOST ecmp_spine_peer { IP 192.168.220.20 }

// INSTRUCTION: Define VXLAN transmission flow with entropy source port 54321.
FLOW vxlan_entropy_flow(src, dst) {
    src -> dst VXLAN VNI 20000 SRCPORT 54321
}

// INSTRUCTION: Compile block executing ECMP hashed VXLAN delivery.
COMPILE {
    vxlan_entropy_flow(ecmp_leaf_vtep, ecmp_spine_peer)
}
""",

    "examples/l3/vxlan/vxlan_ipv6_underlay_enterprise_overlay.fasm": """// PROMPT: Pure IPv6 underlay transport encapsulating VNI 50000 enterprise overlay frames.
// TOKENS: HOST, IP, FLOW, ->, <-, VXLAN, VNI, COMPILE

// INSTRUCTION: Define IPv6 underlay VTEP hypervisor A.
HOST vtep6_hv_a { IP 2001:db8:dc01::1 }

// INSTRUCTION: Define IPv6 underlay VTEP hypervisor B.
HOST vtep6_hv_b { IP 2001:db8:dc01::2 }

// INSTRUCTION: Define bidirectional IPv6 VXLAN overlay flow with VNI 50000.
FLOW vxlan_v6_enterprise(a, b) {
    a -> b VXLAN VNI 50000
    a <- b VXLAN VNI 50000
}

// INSTRUCTION: Compile block executing IPv6 underlay VXLAN exchange.
COMPILE {
    vxlan_v6_enterprise(vtep6_hv_a, vtep6_hv_b)
}
""",

    "examples/l3/vxlan/vxlan_vlan_tagged_vtep_underlay.fasm": """// PROMPT: VXLAN underlay packet transported across 802.1Q tagged data center transit VLAN 800.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, VLAN, PCP, DEI, COMPILE

// INSTRUCTION: Define rack server VTEP endpoint.
HOST rack_vtep_server { IP 10.80.0.10 }

// INSTRUCTION: Define aggregation leaf VTEP endpoint.
HOST agg_leaf_vtep { IP 10.80.0.1 }

// INSTRUCTION: Define VLAN 800 tagged VXLAN underlay flow.
FLOW vxlan_vlan_underlay(srv, leaf) {
    srv -> leaf VXLAN VNI 12000 VLAN 800 PCP 4 DEI 0
}

// INSTRUCTION: Compile block executing VLAN tagged VXLAN encapsulation.
COMPILE {
    vxlan_vlan_underlay(rack_vtep_server, agg_leaf_vtep)
}
""",

    "examples/l3/vxlan/vxlan_qinq_metro_inter_dc_tunnel.fasm": """// PROMPT: Metro data center interconnect tunneling VXLAN through dual-tagged QinQ carrier backbone.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, QINQ, INNER_VLAN, COMPILE

// INSTRUCTION: Define West Data Center border VTEP gateway.
HOST west_dc_border_vtep { IP 172.29.1.1 }

// INSTRUCTION: Define East Data Center border VTEP gateway.
HOST east_dc_border_vtep { IP 172.29.1.2 }

// INSTRUCTION: Define QinQ encapsulated DCI VXLAN flow on provider VLAN 1000 and customer VLAN 80.
FLOW vxlan_qinq_dci_flow(w, e) {
    w -> e VXLAN VNI 90000 QINQ 1000 INNER_VLAN 80
}

// INSTRUCTION: Compile block executing carrier QinQ VXLAN inter-DC tunnel.
COMPILE {
    vxlan_qinq_dci_flow(west_dc_border_vtep, east_dc_border_vtep)
}
""",

    "examples/l3/vxlan/vxlan_mpls_underlay_datacenter_interconnect.fasm": """// PROMPT: VXLAN overlay packet traversing MPLS-based DCI core with label 5000.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, MPLS, COMPILE

// INSTRUCTION: Define ingress DCI edge router VTEP.
HOST dci_ingress_vtep { IP 10.210.0.1 }

// INSTRUCTION: Define egress DCI edge router VTEP.
HOST dci_egress_vtep { IP 10.210.0.2 }

// INSTRUCTION: Define MPLS labeled VXLAN packet flow.
FLOW vxlan_mpls_dci(ing, eg) {
    ing -> eg VXLAN VNI 75000 MPLS 5000
}

// INSTRUCTION: Compile block executing MPLS encapsulated VXLAN transmission.
COMPILE {
    vxlan_mpls_dci(dci_ingress_vtep, dci_egress_vtep)
}
""",

    "examples/l3/vxlan/vxlan_looped_keepalive_probe_burst.fasm": """// PROMPT: Continuous VXLAN tunnel keepalive heartbeat probes inside a COMPILE LOOP.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, PAYLOAD, WAIT, ms, COMPILE, LOOP

// INSTRUCTION: Define hypervisor node A monitoring tunnel health.
HOST hv_node_alpha { IP 192.168.111.1 }

// INSTRUCTION: Define hypervisor node B monitoring tunnel health.
HOST hv_node_beta { IP 192.168.111.2 }

// INSTRUCTION: Define periodic VXLAN probe heartbeat flow.
FLOW vxlan_probe_burst(a, b) {
    a -> b VXLAN VNI 1001 PAYLOAD "VTEP_LIVENESS_PROBE_ECHO" WAIT 15ms
}

// INSTRUCTION: Compile loop executing 4 continuous VXLAN keepalive probes.
COMPILE {
    LOOP 4 {
        vxlan_probe_burst(hv_node_alpha, hv_node_beta)
    }
}
""",

    "examples/l3/vxlan/vxlan_high_vni_boundary_encapsulation.fasm": """// PROMPT: VXLAN tunnel encapsulating maximum 24-bit VNI boundary identifier (16777215).
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, COMPILE

// INSTRUCTION: Define boundary test VTEP generator.
HOST vtep_boundary_gen { IP 10.99.99.1 }

// INSTRUCTION: Define boundary test VTEP receiver.
HOST vtep_boundary_rec { IP 10.99.99.2 }

// INSTRUCTION: Define maximum 24-bit VNI boundary transmission flow.
FLOW vxlan_max_vni_flow(gen, rec) {
    gen -> rec VXLAN VNI 16777215
}

// INSTRUCTION: Compile block executing 24-bit VNI boundary test.
COMPILE {
    vxlan_max_vni_flow(vtep_boundary_gen, vtep_boundary_rec)
}
""",

    "examples/l3/vxlan/vxlan_dont_fragment_pmtud_handling.fasm": """// PROMPT: VXLAN underlay packet with Don't Fragment (DF) flag set for Path MTU Discovery.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, DF, TTL, COMPILE

// INSTRUCTION: Define PMTUD probing VTEP gateway.
HOST pmtud_vtep_gw { IP 172.17.0.1 }

// INSTRUCTION: Define remote VTEP terminating endpoint.
HOST pmtud_remote_vtep { IP 172.17.0.2 }

// INSTRUCTION: Define DF flag enabled VXLAN underlay transmission flow.
FLOW vxlan_pmtud_flow(gw, rem) {
    gw -> rem VXLAN VNI 30303 DF TTL 64
}

// INSTRUCTION: Compile block executing PMTUD enabled VXLAN encapsulation.
COMPILE {
    vxlan_pmtud_flow(pmtud_vtep_gw, pmtud_remote_vtep)
}
""",

    "examples/l3/vxlan/vxlan_kubernetes_cni_overlay_packet.fasm": """// PROMPT: Kubernetes CNI pod-to-pod network overlay communication encapsulated over VNI 4096.
// TOKENS: HOST, IP, FLOW, ->, <-, VXLAN, VNI, PAYLOAD, COMPILE

// INSTRUCTION: Define Kubernetes worker node 1 running source pod.
HOST k8s_worker_1 { IP 10.244.1.1 }

// INSTRUCTION: Define Kubernetes worker node 2 running destination pod.
HOST k8s_worker_2 { IP 10.244.2.1 }

// INSTRUCTION: Define pod-to-pod CNI overlay exchange flow on VNI 4096.
FLOW k8s_cni_overlay_flow(w1, w2) {
    w1 -> w2 VXLAN VNI 4096 PAYLOAD "HTTP_GET_POD_REST_API"
    w1 <- w2 VXLAN VNI 4096 PAYLOAD "HTTP_200_POD_REST_RESP"
}

// INSTRUCTION: Compile block executing container overlay communication.
COMPILE {
    k8s_cni_overlay_flow(k8s_worker_1, k8s_worker_2)
}
""",

    "examples/l3/vxlan/vxlan_storage_replication_nvme_over_fabrics.fasm": """// PROMPT: High-priority storage cluster replication traffic encapsulated across dedicated VNI 8888.
// TOKENS: HOST, IP, FLOW, ->, VXLAN, VNI, DSCP, PAYLOAD, COMPILE

// INSTRUCTION: Define primary storage array controller VTEP.
HOST primary_nvme_vtep { IP 192.168.250.1 }

// INSTRUCTION: Define replica storage array controller VTEP.
HOST replica_nvme_vtep { IP 192.168.250.2 }

// INSTRUCTION: Define storage replication block transfer flow marked with DSCP EF (DSCP 46).
FLOW vxlan_nvme_replication(p, r) {
    p -> r VXLAN VNI 8888 DSCP 46 PAYLOAD "NVME_FABRICS_WRITE_COMMAND_BLOCK"
}

// INSTRUCTION: Compile block executing storage replication over VXLAN.
COMPILE {
    vxlan_nvme_replication(primary_nvme_vtep, replica_nvme_vtep)
}
"""
}

if __name__ == "__main__":
    for path, code in FILES.items():
        write_fasm(path, code)
    print("All 12 VXLAN files generated and verified successfully.")
