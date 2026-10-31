# Multi-Protocol Network Topologies & Dual-Stack Scenarios

FrameAssembly can model complete multi-tier network architectures in a single `.fasm` file by combining three features:
1. **Multi-host `flow` signatures:** Pass 3 to 8+ hosts into a single flow (`flow onboarding(laptop, sw, radius, nms)`) to capture client-to-server, east-west, and out-of-band management traffic in chronological order.
2. **Dual-stack IPv4 / IPv6 flow reuse:** Run the same `flow` inside `compile` first with IPv4 `host` definitions and then with IPv6 `host` definitions—automatically switching between IPv4 (`0x0800`) and IPv6 (`0x86DD`) framing and checksums.
3. **Microsecond-to-second `wait` steps & `loop` bursts:** Synthesize realistic protocol timers, RTP media bursts, and telemetry exports.

*(Browse **104 additional full-stack `.fasm` topologies** in [`examples/topologies/`](../examples/topologies/).)*

---

## 1. EVPN-VXLAN Leaf-Spine Data Center Fabric (`LLDP` + `BFD` + `BGP` + `VXLAN` + `IPFIX`)

Brings up a Spine-Leaf underlay via LLDP neighbor discovery, 50ms BFD liveness, and eBGP peering, transmits a 4-packet VXLAN East-West burst, and exports an IPFIX flow record to a fabric collector:

```frameassembly
host spine_01  { ip 10.255.0.1    mac 00:1c:73:00:00:01 }
host leaf_01   { ip 10.255.0.11   mac 00:1c:73:00:01:01 }
host leaf_02   { ip 10.255.0.12   mac 00:1c:73:00:01:02 }
host collector { ip 10.255.100.50 mac 00:1c:73:00:99:50 }

flow underlay_bringup(spine, leaf) {
    spine -> leaf lldp chassis_id "spine-01.dc1" port_id "Ethernet1/1" ttl 120 sysname "spine-01" wait 1ms
    spine <- leaf lldp chassis_id "leaf-01.dc1" port_id "Ethernet49/1" ttl 120 sysname "leaf-01" wait 2ms

    spine <- leaf bfd state 3 my_disc 101 your_disc 1 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 2ms
    spine -> leaf bfd state 3 my_disc 1 your_disc 101 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 2ms

    spine <- leaf bgp open asn 65101 holdtime 90 bgpid 10.255.0.11 ttl 255 wait 2ms
    spine -> leaf bgp open asn 65000 holdtime 90 bgpid 10.255.0.1 ttl 255 wait 2ms
    spine <- leaf bgp keepalive ttl 255 wait 2ms
    spine <- leaf bgp update asn 65101 prefix "10.254.1.1/32" nexthop 10.255.0.11 ttl 255 wait 5ms
}

flow vxlan_east_west(vtep1, vtep2) {
    vtep1 -> vtep2 vxlan vni 10100 dscp 26 df payload "EAST_WEST_TENANT_RPC" wait 2ms
}

flow export_telemetry(leaf, col) {
    leaf -> col ipfix seq 1 domain_id 100 srcip 10.255.0.11 dstip 10.255.0.12 proto 17 packets 4 octets 512
}

compile {
    underlay_bringup(spine_01, leaf_01)
    loop 4 {
        vxlan_east_west(leaf_01, leaf_02)
    }
    export_telemetry(leaf_01, collector)
}
```

---

## 2. Campus Zero-Trust 802.1X NAC Onboarding (`EAPOL` + `RADIUS` + `DHCP` + `ARP` + `SNMP3`)

Models a corporate laptop authenticating on an access switch port, receiving a DHCPv4 lease, broadcasting a Gratuitous ARP check, and triggering an encrypted SNMPv3 compliance notification:

```frameassembly
host workstation { ip 10.10.50.100 mac 00:22:44:66:88:aa }
host access_sw   { ip 10.10.50.1   mac 00:11:22:33:44:01 }
host radius_srv  { ip 10.10.1.10   mac 00:11:22:33:44:10 }
host nms_srv     { ip 10.10.1.20   mac 00:11:22:33:44:20 }

flow campus_dot1x_onboarding(ws, sw, aaa, nms) {
    ws -> sw eapol version 2 type start wait 2ms
    ws <- sw eapol version 2 type eap_packet eap_code 1 eap_id 1 eap_method 1 wait 2ms
    ws -> sw eapol version 2 type eap_packet eap_code 2 eap_id 1 eap_method 1 identity "eng-laptop-42" wait 2ms

    sw -> aaa radius access_request id 42 user "eng-laptop-42" nas_ip 10.10.50.1 wait 5ms
    sw <- aaa radius access_accept id 42 framed_ip 10.10.50.100 wait 2ms
    ws <- sw eapol version 2 type eap_packet eap_code 3 eap_id 1 wait 5ms

    ws -> sw dhcp discover txid 0xabcdef01 chaddr 00:22:44:66:88:aa wait 5ms
    ws <- sw dhcp offer txid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 router 10.10.50.1 dns_server 10.10.1.53 subnet_mask 255.255.255.0 lease_time 43200 wait 5ms
    ws -> sw dhcp request txid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 wait 5ms
    ws <- sw dhcp ack txid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 router 10.10.50.1 dns_server 10.10.1.53 subnet_mask 255.255.255.0 lease_time 43200 wait 5ms

    ws -> sw arp gratuitous sha 00:22:44:66:88:aa spa 10.10.50.100 tpa 10.10.50.100 wait 2ms
    sw -> nms snmp3 inform user "nac_auditor" engineid "80001f88801122334455" engineboots 5 enginetime 3600 auth sha256 "AuditAuthKey2026!" priv aes "AuditPrivKey2026!" reqid 500 varbind 1.3.6.1.2.1.1.5.0 string "access-sw-floor2" varbind 1.3.6.1.2.1.2.2.1.8.12 int 1
}

compile {
    campus_dot1x_onboarding(workstation, access_sw, radius_srv, nms_srv)
}
```

---

## 3. Dual-Stack Cloud Microservice Mesh (`DNS` + `TCP` + `TLS` + `GRPC` + `REDIS` + `POSTGRES`)

Runs a single 4-tier service mesh transaction across **both IPv4 and IPv6** cluster networks without duplicating flow logic:

```frameassembly
host ingress_v4 { ip 10.244.1.10 }
host coredns_v4 { ip 10.96.0.10 }
host orders_v4  { ip 10.244.2.20 }
host storage_v4 { ip 10.244.3.30 }

host ingress_v6 { ip fd00:10:244:1::10 }
host coredns_v6 { ip fd00:10:96::10 }
host orders_v6  { ip fd00:10:244:2::20 }
host storage_v6 { ip fd00:10:244:3::30 }

flow service_mesh_checkout(gw, dns, svc, db) {
    gw -> dns dns query txid 901 qname "orders.prod.svc.cluster.local" qtype "A" wait 1ms
    gw <- dns dns response txid 901 qname "orders.prod.svc.cluster.local" qtype "A" rdata "10.244.2.20" wait 1ms

    gw -> svc tcp syn srcport 51051 dstport 50051 wait 1ms
    gw <- svc tcp syn ack wait 1ms
    gw -> svc tcp ack wait 1ms
    gw -> svc tls client_hello sni "orders.prod.svc.cluster.local" ciphersuite 4865 alpn "h2" wait 2ms
    gw <- svc tls server_hello ciphersuite 4865 alpn "h2" wait 2ms
    gw -> svc grpc service "commerce.OrderService" method "CreateOrder" payload "sku=NVME-4TB&qty=2" wait 2ms

    svc -> db redis cmd "GET" args "inventory:NVME-4TB" wait 1ms
    svc <- db redis reply_type "BULK" value "42" wait 1ms
    svc -> db postgres sql "INSERT INTO orders (sku, qty) VALUES ('NVME-4TB', 2);" wait 2ms
    svc <- db postgres command_complete ready_for_query payload "INSERT 0 1" wait 2ms

    gw <- svc grpc service "commerce.OrderService" method "CreateOrder" grpc_status 0 payload "order_id=90042"
}

compile {
    service_mesh_checkout(ingress_v4, coredns_v4, orders_v4, storage_v4)
    service_mesh_checkout(ingress_v6, coredns_v6, orders_v6, storage_v6)
}
```

---

## 4. IEC 62443 Substation & Industrial DMZ Conduit (`MODBUS` + `DNP3` + `S7COMM` + `OPCUA` + `SYSLOG`)

Combines priority-tagged Level 1–2 PLC/RTU polling (`VLAN 110 PCP 6`) with OPC UA historian push and Syslog SIEM auditing across the Level 3.5 Industrial DMZ (`VLAN 120`):

```frameassembly
host substation_hmi { ip 172.22.10.5   mac 00:1b:21:22:0a:05 }
host bay_rtu        { ip 172.22.10.50  mac 00:a0:c9:22:0a:32 }
host s7_plc         { ip 172.22.10.60  mac 00:0e:8c:22:0a:3c }
host idmz_historian { ip 172.22.20.100 mac 00:50:56:22:14:64 }

flow substation_conduit_telemetry(hmi, rtu, plc, idmz) {
    hmi -> rtu vlan 110 pcp 6 modbus unitid 1 func "READ_HOLDING_REGISTERS" addr 40001 count 8 wait 1ms
    hmi <- rtu vlan 110 pcp 6 modbus unitid 1 func "READ_HOLDING_REGISTERS" count 8 is_response wait 2ms
    hmi -> rtu vlan 110 pcp 6 dnp3 src 1 dst 10 func "READ" group 60 variation 1 wait 2ms
    hmi <- rtu vlan 110 pcp 6 dnp3 src 10 dst 1 func "RESPONSE" group 30 variation 1 wait 2ms
    hmi -> plc vlan 110 pcp 6 s7comm rosctr "JOB" func "READ_VAR" pdu_ref 10 area 0x84 db_num 1 offset 0 count 4 wait 2ms

    hmi -> idmz vlan 120 pcp 4 opcua msg_type "MSG" chunk_type "F" endpoint_url "opc.tcp://idmz:4840" node_id "ns=3;s=Feeder01.kV" wait 2ms
    hmi -> idmz vlan 120 pcp 4 syslog facility 4 severity 5 hostname "sub-hmi-01" app "scada-poller" msg "IEC62443-Conduit: Authorized poll completed"
}

compile {
    substation_conduit_telemetry(substation_hmi, bay_rtu, s7_plc, idmz_historian)
}
```