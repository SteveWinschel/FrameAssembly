# Multi-Host Network Topologies & Dual-Stack Scenarios

Real production incidents rarely involve just two hosts or a single protocol. A single user transaction or network convergence event often spans Layer 2 switching, Layer 3 routing/tunneling, Layer 4 transport handshakes, and multiple Layer 7 services across 4 to 8 devices.

Whether you need an **EVPN-VXLAN leaf-spine fabric pcap**, a **Campus Zero-Trust 802.1X RADIUS NAC onboarding capture**, a **Dual-Stack IPv4/IPv6 Kubernetes service-mesh trace**, a **WAN BFD / OSPF / VRRP / IPsec / MPLS failover pcap**, or an **IEC 62443 OT SCADA substation conduit capture**, FrameAssembly lets you model complete **multi-tier enterprise, data center, WAN, and industrial architectures** in a single `.fasm` file using three core capabilities:

1. **Multi-Host Flows:** Pass 3, 4, or 8+ endpoints into a single `flow(client, switch, radius, firewall, server, siem)` to interleave north-south client traffic, east-west service calls, and out-of-band telemetry in exact chronological order.
2. **Reusable Dual-Stack IPv4 & IPv6 Flows:** Write a `flow` once and run it inside `compile` first with IPv4 `host` definitions and then with IPv6 `host` definitions—automatically switching between IPv4 (`EtherType 0x0800`) and IPv6 (`EtherType 0x86DD`), recomputing IPv4/IPv6 pseudo-header checksums, and deriving multicast MAC addresses per RFC 1112 (`01:00:5e:xx:xx:xx`) and RFC 2464 (`33:33:xx:xx:xx:xx`).
3. **Deterministic `wait` Timers & `loop` Traffic Bursts:** Combine nanosecond-to-minute inter-packet delays (`ns`, `us`, `ms`, `s`, `m`) with `loop <count> { ... }` blocks inside `compile` to generate realistic keepalive cadences, VXLAN/IPsec bursts, and RTP media streams.

> **104 Ready-to-Compile Topologies in `examples/topologies/`:**
> In addition to the 5 reference architectures below, you can browse **104 full-stack `.fasm` scenarios** in [`examples/topologies/`](../examples/topologies/).

---

## Core Architectural Building Blocks

### 1. Multi-Host Flows Across 3 to 8+ Devices

A `flow` header can accept any number of host endpoints. Inside the flow body, every statement specifies which two endpoints are communicating on that line (`ws -> sw`, `sw -> aaa`, `aaa -> siem`):

```text
flow branch_transaction(client, edge_fw, app_srv, siem) {
    client  -> app_srv tcp syn dstport 443 wait 1ms
    edge_fw -> siem    syslog facility 4 severity 6 msg "Permit TCP 443" wait 1ms
    client  <- app_srv tcp syn ack
}
```

### 2. Dual-Stack IPv4 / IPv6 Reuse & Multicast MAC Derivation

FrameAssembly enforces strict Layer 3 address-family consistency per statement (mixing an IPv4 host and an IPv6 host on the same arrow is rejected with a clear validation error), while allowing the exact same `flow` block to run unmodified over both IPv4 and IPv6:

| Feature | IPv4 Execution (`host { ip 10.x.x.x }`) | IPv6 Execution (`host { ip 2001:db8::x }`) |
| :--- | :--- | :--- |
| **Ethernet EtherType** | `0x0800` (or `0x8100` / `0x88A8` / `0x8847` when tagged) | `0x86DD` (or `0x8100` / `0x88A8` / `0x8847` when tagged) |
| **L3 `ttl <0..255>` & `dscp <0..63>`** | Maps to IPv4 `TTL` and `TOS/DSCP` | Maps to IPv6 `Hop Limit` and `Traffic Class` |
| **L3 `flowlabel <0..1048575>`** | Silently ignored on IPv4 statements | Encoded into the 20-bit IPv6 `Flow Label` field |
| **Multicast Destination MAC** | Auto-derived as `01:00:5e:xx:xx:xx` (RFC 1112) when `mac` is omitted on a `224.0.0.0/4` host | Auto-derived as `33:33:xx:xx:xx:xx` (RFC 2464) when `mac` is omitted on an `ff00::/8` host |
| **UDP Checksum `0x0000` Guard** | RFC 768 checksum | RFC 8200 §8.1 mandatory pseudo-header checksum (`0x0000` mapped to `0xFFFF`) |

### 3. `loop <count> { ... }` Bursts in `compile`

Inside `compile { ... }`, wrap one or more flow calls in `loop <count> { ... }` to repeat traffic bursts while automatically advancing TCP sequence numbers and packet timestamps across iterations:

```text
compile {
    underlay_bringup(spine_01, leaf_01)
    loop 10 {
        vxlan_east_west_burst(leaf_01, leaf_02)
    }
}
```

---

## 1. EVPN-VXLAN Leaf-Spine Data Center Fabric (`LLDP` + `BFD` + `BGP` + `VXLAN` + `IPFIX`)

**Scenario:** Models a data center fabric link bring-up between a Spine switch (`spine_01`) and two ToR Leaf VTEPs (`leaf_01`, `leaf_02`), followed by an East-West VXLAN tenant burst and an IPFIX flow telemetry export to a fabric collector:
1. **Layer 2 Link Discovery (`LLDP`):** Spine and Leaf exchange chassis/port capabilities and system names.
2. **Sub-Second Failure Detection (`BFD`):** 50ms (`50000` $\mu\text{s}$) BFD Control sessions reach State `3` (`Up`) with `TTL 255` GTSM protection.
3. **Underlay Routing (`BGP`):** eBGP `OPEN` (`ASN 65101` $\leftrightarrow$ `ASN 65000`), `KEEPALIVE`, and `/32` VTEP loopback `UPDATE` advertisement.
4. **Overlay Data Plane (`VXLAN`):** A 4-packet `loop` burst encapsulating tenant traffic in `VNI 10100` with `DSCP 26` (`AF31`) and the IPv4 Don't Fragment (`DF`) bit set for Path MTU validation.
5. **Fabric Visibility (`IPFIX`):** `leaf_01` exports a CFlow/IPFIX v10 accounting record summarizing the 4-packet VXLAN burst to `collector` on UDP port `4739`.

```frameassembly
host spine_01  { ip 10.255.0.1    mac 00:1c:73:00:00:01 }
host leaf_01   { ip 10.255.0.11   mac 00:1c:73:00:01:01 }
host leaf_02   { ip 10.255.0.12   mac 00:1c:73:00:01:02 }
host collector { ip 10.255.100.50 mac 00:1c:73:00:99:50 }

flow underlay_bringup(spine, leaf) {
    // 1. IEEE 802.1AB LLDP neighbor discovery on point-to-point fabric link
    spine -> leaf lldp chassis_id "spine-01.dc1" port_id "Ethernet1/1" ttl 120 sysname "spine-01" sysdesc "Arista EOS 4.32" wait 1ms
    spine <- leaf lldp chassis_id "leaf-01.dc1" port_id "Ethernet49/1" ttl 120 sysname "leaf-01" sysdesc "Arista EOS 4.32" wait 2ms

    // 2. RFC 5880 BFD 50ms timers (State 3 = Up, Multiplier = 3, TTL = 255)
    spine <- leaf bfd state 3 my_disc 101 your_disc 1 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 2ms
    spine -> leaf bfd state 3 my_disc 1 your_disc 101 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 2ms

    // 3. RFC 4271 eBGP peering and VTEP loopback /32 route advertisement
    spine <- leaf bgp open asn 65101 holdtime 90 bgpid 10.255.0.11 ttl 255 wait 2ms
    spine -> leaf bgp open asn 65000 holdtime 90 bgpid 10.255.0.1 ttl 255 wait 2ms
    spine <- leaf bgp keepalive ttl 255 wait 1ms
    spine -> leaf bgp keepalive ttl 255 wait 2ms
    spine <- leaf bgp update asn 65101 prefix "10.254.1.11/32" nexthop 10.255.0.11 ttl 255 wait 5ms
}

flow vxlan_east_west(vtep1, vtep2) {
    // RFC 7348 VXLAN UDP 4789 overlay frame (VNI 10100, DSCP AF31 = 26, Don't Fragment)
    vtep1 -> vtep2 vxlan vni 10100 dscp 26 df payload "EAST_WEST_TENANT_RPC_FRAME" wait 2ms
}

flow export_fabric_telemetry(leaf, col) {
    // RFC 7011 IPFIX v10 flow record reporting the 4 VXLAN packets (512 octets)
    leaf -> col ipfix seq 1 domain_id 100 srcip 10.255.0.11 dstip 10.255.0.12 proto 17 srcport 49152 dstport 4789 packets 4 octets 512
}

compile {
    underlay_bringup(spine_01, leaf_01)
    loop 4 {
        vxlan_east_west(leaf_01, leaf_02)
    }
    export_fabric_telemetry(leaf_01, collector)
}
```

---

## 2. Campus Zero-Trust 802.1X NAC Port Onboarding (`EAPOL` + `RADIUS` + `DHCP` + `ARP` + `SNMP3`)

**Scenario:** Captures the complete lifecycle of an employee workstation plugging into a Zero-Trust campus switch port across 4 network tiers (`workstation`, `access_sw`, `radius_srv`, and `nms_srv`):
1. **802.1X Supplicant Handshake (`EAPOL`):** The laptop sends `EAPOL-Start`, responds to the switch's `EAP-Request/Identity` (`eap_code 1, eap_method 1`), and awaits port authorization.
2. **AAA Policy Verification (`RADIUS`):** The switch relays the identity to the RADIUS server (`Access-Request` on UDP `1812`) and receives `Access-Accept` with the assigned `Framed-IP-Address`, then sends `EAP-Success` (`eap_code 3`) to open the switch port.
3. **IPv4 Address Assignment (`DHCP`):** Full 4-packet `DORA` exchange (`Discover` $\rightarrow$ `Offer` $\rightarrow$ `Request` $\rightarrow$ `Ack`) assigning `10.10.50.100/24`.
4. **Duplicate Address Detection (`ARP`):** The workstation broadcasts a Gratuitous ARP (`SPA == TPA == 10.10.50.100`).
5. **Encrypted NMS Audit (`SNMP3`):** The switch sends an authenticated and AES-128-CFB encrypted `SNMPv3 InformRequest` (`SHA256` + `AES`) to the NMS reporting `ifOperStatus = up(1)` on port 12.

```frameassembly
host workstation { ip 10.10.50.100 mac 00:22:44:66:88:aa }
host access_sw   { ip 10.10.50.1   mac 00:11:22:33:44:01 }
host radius_srv  { ip 10.10.1.10   mac 00:11:22:33:44:10 }
host nms_srv     { ip 10.10.1.20   mac 00:11:22:33:44:20 }

flow campus_dot1x_onboarding(ws, sw, aaa, nms) {
    // 1. IEEE 802.1X EAPOL Start and EAP-Identity exchange
    ws -> sw eapol version 2 type start wait 2ms
    ws <- sw eapol version 2 type eap_packet eap_code 1 eap_id 1 eap_method 1 wait 2ms
    ws -> sw eapol version 2 type eap_packet eap_code 2 eap_id 1 eap_method 1 identity "eng-laptop-42" wait 2ms

    // 2. RADIUS Access-Request / Access-Accept and EAP-Success (eap_code 3)
    sw -> aaa radius access_request id 42 user "eng-laptop-42" nas_ip 10.10.50.1 wait 5ms
    sw <- aaa radius access_accept id 42 framed_ip 10.10.50.100 wait 2ms
    ws <- sw eapol version 2 type eap_packet eap_code 3 eap_id 1 wait 5ms

    // 3. DHCPv4 DORA lease acquisition (Discover -> Offer -> Request -> Ack)
    ws -> sw dhcp discover txid 0xabcdef01 chaddr 00:22:44:66:88:aa wait 5ms
    ws <- sw dhcp offer txid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 router 10.10.50.1 dns_server 10.10.1.53 subnet_mask 255.255.255.0 lease_time 43200 wait 5ms
    ws -> sw dhcp request txid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 wait 5ms
    ws <- sw dhcp ack txid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 router 10.10.50.1 dns_server 10.10.1.53 subnet_mask 255.255.255.0 lease_time 43200 wait 5ms

    // 4. RFC 5227 Gratuitous ARP announcement
    ws -> sw arp gratuitous sha 00:22:44:66:88:aa spa 10.10.50.100 tpa 10.10.50.100 wait 2ms

    // 5. SNMPv3 USM authPriv (HMAC-SHA-256 + AES-128) Inform to NMS
    sw -> nms snmp3 inform user "nac_auditor" engineid "80001f88801122334455" engineboots 5 enginetime 3600 auth sha256 "AuditAuthKey2026!" priv aes "AuditPrivKey2026!" reqid 500 varbind 1.3.6.1.2.1.1.5.0 string "access-sw-floor2" varbind 1.3.6.1.2.1.2.2.1.8.12 int 1
}

compile {
    campus_dot1x_onboarding(workstation, access_sw, radius_srv, nms_srv)
}
```

---

## 3. Dual-Stack IPv4 & IPv6 Cloud Service Mesh (`DNS` + `TCP` + `TLS` + `GRPC` + `REDIS` + `POSTGRES`)

**Scenario:** Demonstrates **reusable dual-stack IPv4 and IPv6 flow generation**. A single 4-tier Kubernetes service-mesh flow (`service_mesh_checkout`) models:
1. CoreDNS service discovery (`DNS`)
2. Explicit 3-way TCP handshake (`SYN` $\rightarrow$ `SYN ACK` $\rightarrow$ `ACK`) on port `50051`
3. mTLS 1.3 negotiation with SNI and ALPN `"h2"` (`TLS`)
4. Unary gRPC `CreateOrder` call (`GRPC`)
5. East-west Redis inventory cache lookup (`REDIS`) and PostgreSQL SQL order insert (`POSTGRES`)

In `compile`, calling `service_mesh_checkout` first with the `_v4` hosts and then with the `_v6` hosts generates both the complete IPv4 cluster trace and the complete IPv6 cluster trace in one PCAPNG file.

```frameassembly
// IPv4 Kubernetes Pod & Service Endpoints
host ingress_v4 { ip 10.244.1.10 }
host coredns_v4 { ip 10.96.0.10 }
host orders_v4  { ip 10.244.2.20 }
host storage_v4 { ip 10.244.3.30 }

// IPv6 Kubernetes Pod & Service Endpoints
host ingress_v6 { ip fd00:10:244:1::10 }
host coredns_v6 { ip fd00:10:96::10 }
host orders_v6  { ip fd00:10:244:2::20 }
host storage_v6 { ip fd00:10:244:3::30 }

flow service_mesh_checkout(gw, dns, svc, db) {
    // 1. Internal service discovery via CoreDNS
    gw -> dns dns query txid 901 qname "orders.prod.svc.cluster.local" qtype "A" wait 1ms
    gw <- dns dns response txid 901 qname "orders.prod.svc.cluster.local" qtype "A" rdata "10.244.2.20" wait 1ms

    // 2. TCP 3-way handshake + TLS 1.3 ALPN "h2" + gRPC request on port 50051
    gw -> svc tcp syn srcport 51051 dstport 50051 mss 1460 wscale 7 sack_perm wait 1ms
    gw <- svc tcp syn ack mss 1460 wscale 7 sack_perm wait 1ms
    gw -> svc tcp ack wait 1ms
    gw -> svc tls client_hello sni "orders.prod.svc.cluster.local" ciphersuite 4865 alpn "h2" wait 1ms
    gw <- svc tls server_hello ciphersuite 4865 alpn "h2" wait 1ms
    gw -> svc grpc service "commerce.OrderService" method "CreateOrder" payload "sku=NVME-4TB&qty=2" wait 2ms

    // 3. Server-side Redis cache check (TCP 6379) & PostgreSQL transaction (TCP 5432)
    svc -> db redis get key "inventory:NVME-4TB" wait 1ms
    svc <- db redis reply_type "BULK" value "42" wait 1ms
    svc -> db postgres startup user "orders_app" db "commerce" wait 1ms
    svc <- db postgres auth_ok ready_for_query wait 1ms
    svc -> db postgres query sql "INSERT INTO orders (sku, qty) VALUES ('NVME-4TB', 2);" wait 2ms
    svc <- db postgres command_complete ready_for_query payload "INSERT 0 1" wait 2ms

    // 4. gRPC OK response returned to the ingress gateway
    gw <- svc grpc service "commerce.OrderService" method "CreateOrder" grpc_status 0 payload "order_id=90042" wait 5ms
}

compile {
    // Execute over IPv4 cluster network
    service_mesh_checkout(ingress_v4, coredns_v4, orders_v4, storage_v4)
    // Execute the exact same flow over IPv6 cluster network
    service_mesh_checkout(ingress_v6, coredns_v6, orders_v6, storage_v6)
}
```

---

## 4. WAN Branch Failover & IPsec/MPLS Backhaul (`BFD` + `OSPF` + `VRRP` + `IKEV2`/`ESP` + `QINQ`/`MPLS`)

**Scenario:** Models an enterprise branch office with redundant WAN edge routers (`branch_r1`, `branch_r2`) failing over to an IPsec-over-Metro-Ethernet/MPLS backhaul connected to `hq_hub`:
1. **LAN First-Hop Redundancy (`VRRP`):** `branch_r1` advertises VRRPv3 Group `10` Master ownership (`priority 200`, `vip 10.250.10.1`).
2. **WAN Link Failure & IGP Convergence (`BFD` + `OSPF`):** `branch_r1` signals a BFD `Down` state (`state 1, diag 1`), then floods an Area `0` OSPF Link State Update (`LSU`) to `branch_r2` and receives an `LSACK`.
3. **Carrier QinQ IPsec Tunnel Bring-Up (`QINQ` + `IKEV2`):** `branch_r2` negotiates an IKEv2 Security Association (`SA_INIT` and `AUTH`) with `hq_hub` across a Metro Ethernet IEEE 802.1ad QinQ trunk (`S-VLAN 2100`, `C-VLAN 100`).
4. **MPLS Core Encrypted Data Plane (`MPLS` + `ESP`):** `branch_r2` and `hq_hub` exchange MPLS-labeled (`Label 32100`, `EXP 5`) IPsec `ESP` tunnel packets with explicit Initialization Vectors (`IV`) and Integrity Check Values (`ICV`).

```frameassembly
host branch_r1 { ip 10.250.10.2  mac 00:00:5e:00:01:0a }
host branch_r2 { ip 10.250.10.3  mac 00:1e:be:25:10:03 }
host hq_hub    { ip 172.31.250.1 mac 00:1e:be:31:fa:01 }

flow wan_failover_and_ipsec_mpls(r1, r2, hub) {
    // 1. VRRPv3 LAN gateway advertisement and preemptive priority takeover on VRID 10
    r1 -> r2 vrrp vrid 10 priority 200 adv_int 100 vip 10.250.10.1 version 3 ttl 255 wait 2ms

    // 2. BFD Down notification (state 1, diag 1) triggers OSPF Area 0 LSA flooding
    r1 -> r2 bfd state 1 diag 1 my_disc 501 your_disc 502 min_tx 100000 min_rx 100000 mult 3 ttl 255 wait 2ms
    r2 -> r1 vrrp vrid 10 priority 220 adv_int 100 vip 10.250.10.1 version 3 ttl 255 wait 2ms
    r1 -> r2 ospf hello router_id 10.250.0.1 area_id 0 hello_interval 10 dead_interval 40 priority 100 ttl 1 wait 1ms
    r1 -> r2 ospf lsu router_id 10.250.0.1 area_id 0 ttl 1 wait 1ms
    r1 <- r2 ospf lsack router_id 10.250.0.2 area_id 0 ttl 1 wait 3ms

    // 3. IKEv2 SA_INIT and AUTH negotiation over IEEE 802.1ad QinQ (S-VLAN 2100, C-VLAN 100)
    r2 -> hub qinq 2100 inner_vlan 100 dscp 48 ikev2 exchange sa_init initiator_spi 0x1122334455667788 responder_spi 0 msgid 0 flags 0x08 wait 2ms
    r2 <- hub qinq 2100 inner_vlan 100 dscp 48 ikev2 exchange sa_init initiator_spi 0x1122334455667788 responder_spi 0x99aabbccddeeff00 msgid 0 flags 0x20 wait 2ms
    r2 -> hub qinq 2100 inner_vlan 100 dscp 48 ikev2 exchange auth initiator_spi 0x1122334455667788 responder_spi 0x99aabbccddeeff00 msgid 1 flags 0x08 wait 2ms
    r2 <- hub qinq 2100 inner_vlan 100 dscp 48 ikev2 exchange auth initiator_spi 0x1122334455667788 responder_spi 0x99aabbccddeeff00 msgid 1 flags 0x20 wait 3ms

    // 4. Encrypted IPsec ESP tunnel traffic over MPLS Label 32100 (EXP 5 EF)
    r2 -> hub mpls 32100 exp 5 bos 1 mpls_ttl 60 dscp 46 esp spi 0x00102030 seq 1 iv "1122334455667788" icv "aabbccddeeff001122334455" next_header 4 payload "ENCRYPTED_BRANCH_VOICE_FRAME_1" wait 2ms
    r2 <- hub mpls 32200 exp 5 bos 1 mpls_ttl 60 dscp 46 esp spi 0x00102031 seq 1 iv "8877665544332211" icv "554433221100ffeeddccbbaa" next_header 4 payload "ENCRYPTED_HQ_VOICE_REPLY_1"
}

compile {
    wan_failover_and_ipsec_mpls(branch_r1, branch_r2, hq_hub)
}
```

---

## 5. IEC 62443 Industrial Substation & IDMZ Conduit (`MODBUS` + `DNP3` + `S7COMM` + `OPCUA` + `SYSLOG`)

**Scenario:** Validates a segmented **IEC 62443 / Purdue Model** industrial architecture spanning Level 2 Supervisory HMI (`substation_hmi`), Level 1 Field Controllers (`bay_rtu`, `s7_plc`), and a Level 3.5 Industrial DMZ Historian & SIEM (`idmz_historian`):
1. **Level 1–2 Process VLAN (`VLAN 110, PCP 6`):** The supervisory HMI polls holding registers from `bay_rtu` via `MODBUS` (TCP `502`), executes an IEEE 1815 `DNP3` Class 0 integrity poll (TCP `20000`), and reads Data Block `DB1` from a Siemens PLC via `S7COMM` (TCP `102`).
2. **Level 2–3.5 IDMZ Conduit (`VLAN 120, PCP 4`):** The HMI forwards aggregated telemetry upstream to `idmz_historian` over an `OPCUA` binary session (TCP `4840`) and emits an RFC 5424 `SYSLOG` compliance audit message (UDP `514`).

```frameassembly
host substation_hmi { ip 172.22.10.5   mac 00:1b:21:22:0a:05 }
host bay_rtu        { ip 172.22.10.50  mac 00:a0:c9:22:0a:32 }
host s7_plc         { ip 172.22.10.60  mac 00:0e:8c:22:0a:3c }
host idmz_historian { ip 172.22.20.100 mac 00:50:56:22:14:64 }

flow substation_conduit_telemetry(hmi, rtu, plc, idmz) {
    // 1. Level 1-2 Process VLAN 110 (802.1p PCP 6): Modbus TCP register poll
    hmi -> rtu vlan 110 pcp 6 modbus read_holding_registers txid 1 unitid 1 addr 40001 count 8 wait 1ms
    hmi <- rtu vlan 110 pcp 6 modbus read_holding_registers txid 1 unitid 1 count 8 value 13800 is_response wait 2ms

    // 2. Level 1-2 Process VLAN 110: IEEE 1815 DNP3 Class 0 read & analog input response
    hmi -> rtu vlan 110 pcp 6 dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
    hmi <- rtu vlan 110 pcp 6 dnp3 func "RESPONSE" src 10 dst 1 group 30 variation 1 wait 2ms

    // 3. Level 1-2 Process VLAN 110: Siemens S7comm DB1 variable read
    hmi -> plc vlan 110 pcp 6 s7comm rosctr "JOB" read_var pdu_ref 10 area 0x84 db_num 1 offset 0 count 4 wait 2ms
    hmi <- plc vlan 110 pcp 6 s7comm rosctr "ACK_DATA" read_var pdu_ref 10 count 4 payload "DB1_OK" wait 2ms

    // 4. Level 3.5 IDMZ VLAN 120 (802.1p PCP 4): OPC UA Historian push & Syslog SIEM audit
    hmi -> idmz vlan 120 pcp 4 opcua msg_type "HEL" chunk_type "F" endpoint_url "opc.tcp://172.22.20.100:4840/historian" wait 1ms
    hmi <- idmz vlan 120 pcp 4 opcua msg_type "ACK" chunk_type "F" wait 1ms
    hmi -> idmz vlan 120 pcp 4 opcua msg_type "MSG" chunk_type "F" secure_channel_id 10 token_id 1 seq_num 1 reqid 1 node_id "ns=3;s=Feeder01.BusVoltageKV" payload "138.0" wait 2ms
    hmi -> idmz vlan 120 pcp 4 syslog facility 4 severity 5 hostname "sub-hmi-01" app "scada-poller" msg "IEC62443-Conduit: Authorized Level 1 poll & IDMZ push completed"
}

compile {
    substation_conduit_telemetry(substation_hmi, bay_rtu, s7_plc, idmz_historian)
}
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — Step-by-step introduction to `host`, `flow`, `compile`, and cross-layer modifiers.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — Ready-to-run recipes for firewall testing, SNMP traps, QoS validation, and IDS verification.
- [**Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)**](l2_protocols.md) & [**Layer 3 Control, Tunneling, VPN & Routing Protocols (`l3_protocols.md`)**](l3_protocols.md) — Complete reference for `VLAN`, `QINQ`, `MPLS`, `OSPF`, `BGP`, `BFD`, `VRRP`, `IKEV2`, and `ESP`.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — `TCP`, `UDP`, and `SCTP` 4-tuple state tracking and RFC 7323 options.
- [**Layer 7 Network Management (`l7_snmp.md`)**](l7_snmp.md) & [**Layer 7 Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — `SNMP3`, `RADIUS`, `DHCP`, `DNS`, `SYSLOG`, and `IPFIX`.
- [**Layer 7 Industrial Control Systems & SCADA/OT (`l7_industrial_ot.md`)**](l7_industrial_ot.md) — Complete reference for `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, and `OPCUA`.
- [**`.fasm` File Format & Media Type Specification (`fasm-specification.md`)**](fasm-specification.md) — Normative `text/vnd.frameassembly` media type specification, lexical rules, and `.fasm` extension disambiguation.
