# Multi-Host Topologies & Dual-Stack Scenarios

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Outages never stay politely inside one OSI layer. A ticket arrives saying "the app is slow", and ten minutes later the investigation has touched 802.1X, DNS, a TLS handshake, a gRPC call, a Redis lookup, and a Postgres insert. Nobody changed the firewall rules since Tuesday, which is exactly what everyone says right before someone finds the firewall change from Tuesday.

Reproducing that in a lab means booting a pile of router and server images in GNS3, EVE-NG, or Containerlab, wiring VLAN trunks and VRFs, standing up AAA, and running `tcpdump` on five interfaces while you trigger the failure by hand. FrameAssembly puts the whole multi-device conversation in one `.frasm` file. Build it with `frameassembly topology.frasm`, replay it with `tcpreplay`, inspect it in **Wireshark** or **Suricata**, or run `frameassembly reverse trace.pcap` to turn a real capture into `.frasm` code you can edit.

Three features carry this: multi-host flows, dual-stack reuse, and precise `wait` timers.

> **104 ready-to-compile topologies** live in [`examples/topologies/`](../examples/topologies/). The five below are the reference architectures; the directory has the rest.

---

## Building Blocks

### Multi-Host Flows

A `flow` takes as many endpoints as you give it, and every statement names the two that talk on that line. Pass four hosts in, and `compile` plugs your real `host` definitions into the parameters in left-to-right order. Client traffic, firewall logging, and SIEM telemetry stay in the exact chronological order they happened:

```frameassembly
host workstation  { ip 10.30.0.10 mac 00:1b:21:30:00:0a }
host perimeter_fw { ip 10.30.0.1  mac 00:1b:21:30:00:01 }
host web_srv      { ip 10.30.1.20 mac 00:1b:21:30:01:14 }
host splunk_siem  { ip 10.30.9.50 mac 00:1b:21:30:09:32 }

flow branch_transaction(client, edge_fw, app_srv, siem) {
    client  -> app_srv tcp syn srcport 50443 dstport 443 wait 1ms
    edge_fw -> siem    syslog facility 4 severity 6 msg "Permit TCP 443" wait 1ms
    client  <- app_srv tcp syn ack
}

compile { branch_transaction(workstation, perimeter_fw, web_srv, splunk_siem) }
```

### Dual-Stack Reuse

FrameAssembly checks address-family consistency per statement: an IPv4 host and an IPv6 host on the same line is a validation error. The same `flow`, though, runs unchanged over both families when you call it once with IPv4 hosts and once with IPv6 hosts.

| Feature | IPv4 Execution (`host { ip 10.x.x.x }`) | IPv6 Execution (`host { ip 2001:db8::x }`) |
| :--- | :--- | :--- |
| **EtherType** | `0x0800` (or `0x8100` / `0x88A8` / `0x8847` when tagged) | `0x86DD` (or `0x8100` / `0x88A8` / `0x8847` when tagged) |
| **`ttl <0..255>` and `dscp <0..63>`** | IPv4 `TTL` and `TOS/DSCP` | IPv6 `Hop Limit` and `Traffic Class` |
| **`flowlabel <0..1048575>`** | Silently ignored | Encoded into the 20-bit IPv6 Flow Label |
| **Multicast destination MAC** | `01:00:5e:xx:xx:xx` (RFC 1112) when `mac` is omitted on a `224.0.0.0/4` host | `33:33:xx:xx:xx:xx` (RFC 2464) when `mac` is omitted on an `ff00::/8` host |
| **UDP checksum** | RFC 768 | RFC 8200 §8.1 mandatory pseudo-header checksum (`0x0000` becomes `0xFFFF`) |

### Bursts and Inline Statements in `compile`

Inside `compile { ... }` you can call flows repeatedly and mix in one-off statements. TCP sequence numbers and timestamps keep advancing across all of it, and `wait` accepts `ns`, `us`, `ms`, `s`, and `m`, which is how you get realistic keepalive cadences, VXLAN bursts, and RTP streams:

```frameassembly
host leaf_01   { ip 10.255.0.11   mac 00:1c:73:00:01:01 }
host leaf_02   { ip 10.255.0.12   mac 00:1c:73:00:01:02 }
host collector { ip 10.255.100.50 mac 00:1c:73:00:99:50 }

flow vxlan_east_west(vtep1, vtep2) {
    vtep1 -> vtep2 vxlan vni 10100 dscp 26 df payload "EAST_WEST_TENANT_RPC_FRAME" wait 2ms
}

compile {
    vxlan_east_west(leaf_01, leaf_02)
    vxlan_east_west(leaf_01, leaf_02)
    vxlan_east_west(leaf_01, leaf_02)
    leaf_01 -> collector ipfix seq 1 domainid 100 packets 3 octets 384
}
```

---

## 1. EVPN-VXLAN Leaf-Spine Fabric (`lldp` + `bfd` + `bgp` + `vxlan` + `ipfix`)

**Scenario:** A spine (`spine_01`) brings up a link to a leaf VTEP, the leaf pushes a burst of east-west tenant traffic to a second leaf, and then reports it to a flow collector. It is the sequence you would normally only see after wiring four switches and an EVPN control plane, and after someone has remembered which port is the uplink.
1. **Layer 2 Link Discovery (`lldp`):** Spine and Leaf exchange chassis/port capabilities and system names.
2. **Sub-Second Failure Detection (`bfd`):** 50ms (`50000` µs) BFD Control sessions reach State `3` (`Up`) with `ttl 255` GTSM protection.
3. **Underlay Routing (`bgp`):** eBGP `open` (`asn 65101` ↔ `asn 65000`), `keepalive`, and `/32` VTEP loopback `update` advertisement.
4. **Overlay Data Plane (`vxlan`):** A 3-packet burst encapsulating tenant traffic in `vni 10100` with `dscp 26` (`AF31`) and the IPv4 Don't Fragment (`df`) bit set for Path MTU validation.
5. **Fabric Visibility (`ipfix`):** `leaf_01` exports a CFlow/IPFIX v10 accounting record summarizing the 3-packet VXLAN burst (`384` octets) to `collector` on UDP port `4739`.

```frameassembly
host spine_01  { ip 10.255.0.1    mac 00:1c:73:00:00:01 }
host leaf_01   { ip 10.255.0.11   mac 00:1c:73:00:01:01 }
host leaf_02   { ip 10.255.0.12   mac 00:1c:73:00:01:02 }
host collector { ip 10.255.100.50 mac 00:1c:73:00:99:50 }

flow underlay_bringup(spine, leaf) {
    // 1. IEEE 802.1AB LLDP neighbor discovery on point-to-point fabric link
    spine -> leaf lldp chassisid "spine-01.dc1" portid "Ethernet1/1" ttl 120 sysname "spine-01" sysdesc "Arista EOS 4.32" wait 1ms
    spine <- leaf lldp chassisid "leaf-01.dc1" portid "Ethernet49/1" ttl 120 sysname "leaf-01" sysdesc "Arista EOS 4.32" wait 2ms

    // 2. RFC 5880 BFD 50ms timers (State 3 = Up, Multiplier = 3, TTL = 255)
    spine <- leaf bfd state 3 mydisc 101 yourdisc 1 mintx 50000 minrx 50000 mult 3 ttl 255 wait 2ms
    spine -> leaf bfd state 3 mydisc 1 yourdisc 101 mintx 50000 minrx 50000 mult 3 ttl 255 wait 2ms

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
    // RFC 7011 IPFIX v10 flow record reporting the 3 VXLAN packets (384 octets)
    leaf -> col ipfix seq 1 domainid 100 srcip 10.255.0.11 dstip 10.255.0.12 proto 17 srcport 49152 dstport 4789 packets 3 octets 384
}

compile {
    underlay_bringup(spine_01, leaf_01)
    vxlan_east_west(leaf_01, leaf_02)
    vxlan_east_west(leaf_01, leaf_02)
    vxlan_east_west(leaf_01, leaf_02)
    export_fabric_telemetry(leaf_01, collector)
}
```

---

## 2. Campus Zero-Trust 802.1X NAC Port Onboarding (`eapol` + `radius` + `dhcp` + `arp` + `snmp3`)

**Scenario:** An employee plugs a laptop into a Zero-Trust campus switch port. Four devices take part (`workstation`, `access_sw`, `radius_srv`, `nms_srv`), and the port stays dark until every step succeeds. When it does not, the ticket reads "network is down" and the packet capture is the only witness:
1. **802.1X Supplicant Handshake (`eapol`):** The laptop sends `EAPOL-Start`, responds to the switch's `EAP-Request/Identity` (`eapcode 1, eapmethod 1`), and awaits port authorization.
2. **AAA Policy Verification (`radius`):** The switch relays the identity to the RADIUS server (`accessrequest` on UDP `1812`) and receives `accessaccept` with the assigned `framedip`, then sends `EAP-Success` (`eapcode 3`) to open the switch port.
3. **IPv4 Address Assignment (`dhcp`):** Full 4-packet `DORA` exchange (`discover`, `offer`, `request`, `ack`) assigning `10.10.50.100/24`.
4. **Duplicate Address Detection (`arp`):** The workstation broadcasts a Gratuitous ARP (`sha`, `spa`, and `tpa` announcing `10.10.50.100`).
5. **Encrypted NMS Audit (`snmp3`):** The switch sends an authenticated and AES-128-CFB encrypted SNMPv3 `inform` (`sha256` + `aes`) to the NMS reporting `ifOperStatus = up(1)` on port 12.

```frameassembly
host workstation { ip 10.10.50.100 mac 00:22:44:66:88:aa }
host access_sw   { ip 10.10.50.1   mac 00:11:22:33:44:01 }
host radius_srv  { ip 10.10.1.10   mac 00:11:22:33:44:10 }
host nms_srv     { ip 10.10.1.20   mac 00:11:22:33:44:20 }

flow campus_dot1x_onboarding(ws, sw, aaa, nms) {
    // 1. IEEE 802.1X EAPOL Start and EAP-Identity exchange
    ws -> sw eapol version 2 type start wait 2ms
    ws <- sw eapol version 2 type eappacket eapcode 1 eapid 1 eapmethod 1 wait 2ms
    ws -> sw eapol version 2 type eappacket eapcode 2 eapid 1 eapmethod 1 identity "eng-laptop-42" wait 2ms

    // 2. RADIUS Access-Request / Access-Accept and EAP-Success (eapcode 3)
    sw -> aaa radius accessrequest id 42 user "eng-laptop-42" nasip 10.10.50.1 wait 5ms
    sw <- aaa radius accessaccept id 42 framedip 10.10.50.100 wait 2ms
    ws <- sw eapol version 2 type eappacket eapcode 3 eapid 1 wait 5ms

    // 3. DHCPv4 DORA lease acquisition (Discover -> Offer -> Request -> Ack)
    ws -> sw dhcp discover xid 0xabcdef01 chaddr 00:22:44:66:88:aa wait 5ms
    ws <- sw dhcp offer xid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 router 10.10.50.1 dnsserver 10.10.1.53 subnetmask 255.255.255.0 leasetime 43200 wait 5ms
    ws -> sw dhcp request xid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 wait 5ms
    ws <- sw dhcp ack xid 0xabcdef01 chaddr 00:22:44:66:88:aa yiaddr 10.10.50.100 router 10.10.50.1 dnsserver 10.10.1.53 subnetmask 255.255.255.0 leasetime 43200 wait 5ms

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

## 3. Dual-Stack IPv4 & IPv6 Cloud Service Mesh (`dns` + `tcp` + `tls` + `grpc` + `redis` + `postgres`)

**Scenario:** One Kubernetes checkout flow (`service_mesh_checkout`), written once and run over IPv4 and IPv6. It covers:
1. CoreDNS service discovery (`dns`)
2. Explicit 3-way TCP handshake (`syn`, `syn ack`, `ack`) on port `50051`
3. mTLS 1.3 negotiation with `sni` and `alpn "h2"` (`tls`)
4. Unary gRPC `CreateOrder` call (`grpc`)
5. East-west Redis inventory cache lookup (`redis`) and PostgreSQL SQL order insert (`postgres`)

In `compile`, call `service_mesh_checkout` with the `_v4` hosts, then with the `_v6` hosts. You get the complete IPv4 trace and the complete IPv6 trace in one PCAPNG file, which is handy when the bug only shows up on the family nobody tested.

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

flow service_mesh_checkout(gw, dns_srv, svc, db) {
    // 1. Internal service discovery via CoreDNS
    gw -> dns_srv dns query txid 901 qname "orders.prod.svc.cluster.local" qtype "a" wait 1ms
    gw <- dns_srv dns response txid 901 qname "orders.prod.svc.cluster.local" qtype "a" rdata "10.244.2.20" wait 1ms

    // 2. TCP 3-way handshake + TLS 1.3 ALPN "h2" + gRPC request on port 50051
    gw -> svc tcp syn srcport 51051 dstport 50051 mss 1460 wscale 7 sackperm wait 1ms
    gw <- svc tcp syn ack mss 1460 wscale 7 sackperm wait 1ms
    gw -> svc tcp ack wait 1ms
    gw -> svc tls clienthello sni "orders.prod.svc.cluster.local" ciphersuite 4865 alpn "h2" wait 1ms
    gw <- svc tls serverhello ciphersuite 4865 alpn "h2" wait 1ms
    gw -> svc grpc service "commerce.OrderService" method "CreateOrder" payload "sku=NVME-4TB&qty=2" wait 2ms

    // 3. Server-side Redis cache check (TCP 6379) & PostgreSQL transaction (TCP 5432)
    svc -> db redis get key "inventory:NVME-4TB" wait 1ms
    svc <- db redis replytype "bulk" value "42" wait 1ms
    svc -> db postgres startup user "orders_app" db "commerce" wait 1ms
    svc <- db postgres authok wait 1ms
    svc <- db postgres readyforquery wait 1ms
    svc -> db postgres query sql "INSERT INTO orders (sku, qty) VALUES ('NVME-4TB', 2);" wait 2ms
    svc <- db postgres commandcomplete sql "INSERT 0 1" wait 1ms
    svc <- db postgres readyforquery wait 2ms

    // 4. gRPC OK response returned to the ingress gateway
    gw <- svc grpc service "commerce.OrderService" method "CreateOrder" grpcstatus 0 payload "order_id=90042" wait 5ms
}

compile {
    // Execute over IPv4 cluster network
    service_mesh_checkout(ingress_v4, coredns_v4, orders_v4, storage_v4)
    // Execute the exact same flow over IPv6 cluster network
    service_mesh_checkout(ingress_v6, coredns_v6, orders_v6, storage_v6)
}
```

---

## 4. WAN Branch Failover & IPsec/MPLS Backhaul (`bfd` + `ospf` + `vrrp` + `ikev2`/`esp` + `qinq`/`mpls`)

**Scenario:** A branch office with two WAN edge routers (`branch_r1`, `branch_r2`) loses its primary link and fails over to an IPsec tunnel across a Metro Ethernet and MPLS backhaul to `hq_hub`. Failover tests are usually run on a Friday, by someone who will not be there on Monday:
1. **LAN First-Hop Redundancy (`vrrp`):** `branch_r1` advertises VRRPv3 Group `10` Master ownership (`priority 200`, `vip 10.250.10.1`).
2. **WAN Link Failure & IGP Convergence (`bfd` + `ospf`):** `branch_r1` signals a BFD `Down` state (`state 1, diag 1`), then floods an Area `0` OSPF Link State Update (`lsu`) to `branch_r2` and receives an `lsack`.
3. **Carrier QinQ IPsec Tunnel Bring-Up (`qinq` + `ikev2`):** `branch_r2` negotiates an IKEv2 Security Association (`sainit` and `auth`) with `hq_hub` across a Metro Ethernet IEEE 802.1ad QinQ trunk (`qinq 2100`, `innervlan 100`).
4. **MPLS Core Encrypted Data Plane (`mpls` + `esp`):** `branch_r2` and `hq_hub` exchange MPLS-labeled (`mpls 32100`, `exp 5`) IPsec `esp` tunnel packets with explicit Initialization Vectors (`iv`) and Integrity Check Values (`icv`).

```frameassembly
host branch_r1 { ip 10.250.10.2  mac 00:00:5e:00:01:0a }
host branch_r2 { ip 10.250.10.3  mac 00:1e:be:25:10:03 }
host hq_hub    { ip 172.31.250.1 mac 00:1e:be:31:fa:01 }

flow wan_failover_and_ipsec_mpls(r1, r2, hub) {
    // 1. VRRPv3 LAN gateway advertisement and preemptive priority takeover on VRID 10
    r1 -> r2 vrrp vrid 10 priority 200 advint 100 vip 10.250.10.1 version 3 ttl 255 wait 2ms

    // 2. BFD Down notification (state 1, diag 1) triggers OSPF Area 0 LSA flooding
    r1 -> r2 bfd state 1 diag 1 mydisc 501 yourdisc 502 mintx 100000 minrx 100000 mult 3 ttl 255 wait 2ms
    r2 -> r1 vrrp vrid 10 priority 220 advint 100 vip 10.250.10.1 version 3 ttl 255 wait 2ms
    r1 -> r2 ospf hello routerid 10.250.0.1 areaid 0 hellointerval 10 deadinterval 40 priority 100 ttl 1 wait 1ms
    r1 -> r2 ospf lsu routerid 10.250.0.1 areaid 0 ttl 1 wait 1ms
    r1 <- r2 ospf lsack routerid 10.250.0.2 areaid 0 ttl 1 wait 3ms

    // 3. IKEv2 SA_INIT and AUTH negotiation over IEEE 802.1ad QinQ (S-VLAN 2100, C-VLAN 100)
    r2 -> hub qinq 2100 innervlan 100 dscp 48 ikev2 exchange sainit initiatorspi 0x1122334455667788 responderspi 0 msgid 0 flags 0x08 wait 2ms
    r2 <- hub qinq 2100 innervlan 100 dscp 48 ikev2 exchange sainit initiatorspi 0x1122334455667788 responderspi 0x99aabbccddeeff00 msgid 0 flags 0x20 wait 2ms
    r2 -> hub qinq 2100 innervlan 100 dscp 48 ikev2 exchange auth initiatorspi 0x1122334455667788 responderspi 0x99aabbccddeeff00 msgid 1 flags 0x08 wait 2ms
    r2 <- hub qinq 2100 innervlan 100 dscp 48 ikev2 exchange auth initiatorspi 0x1122334455667788 responderspi 0x99aabbccddeeff00 msgid 1 flags 0x20 wait 3ms

    // 4. Encrypted IPsec ESP tunnel traffic over MPLS Label 32100 (EXP 5 EF)
    r2 -> hub mpls 32100 exp 5 bos 1 mplsttl 60 dscp 46 esp spi 0x00102030 seq 1 iv "1122334455667788" icv "aabbccddeeff001122334455" nextheader 4 payload "ENCRYPTED_BRANCH_VOICE_FRAME_1" wait 2ms
    r2 <- hub mpls 32200 exp 5 bos 1 mplsttl 60 dscp 46 esp spi 0x00102031 seq 1 iv "8877665544332211" icv "554433221100ffeeddccbbaa" nextheader 4 payload "ENCRYPTED_HQ_VOICE_REPLY_1"
}

compile {
    wan_failover_and_ipsec_mpls(branch_r1, branch_r2, hq_hub)
}
```

---

## 5. IEC 62443 Industrial Substation & IDMZ Conduit (`modbus` + `dnp3` + `s7comm` + `opcua` + `syslog`)

**Scenario:** A segmented IEC 62443 / Purdue Model substation: a Level 2 supervisory HMI (`substation_hmi`), Level 1 field controllers (`bay_rtu`, `s7_plc`), and a Level 3.5 industrial DMZ historian and SIEM (`idmz_historian`). None of it needs a live PLC, which is good, because live PLCs have a way of ending up in someone else's budget:
1. **Level 1–2 Process VLAN (`vlan 110, pcp 6`):** The supervisory HMI polls holding registers from `bay_rtu` via `modbus` (TCP `502`), executes an IEEE 1815 `dnp3` Class 0 integrity poll (TCP `20000`), and reads Data Block `DB1` from a Siemens PLC via `s7comm` (TCP `102`).
2. **Level 2–3.5 IDMZ Conduit (`vlan 120, pcp 4`):** The HMI forwards aggregated telemetry upstream to `idmz_historian` over an `opcua` binary session (TCP `4840`) and emits an RFC 5424 `syslog` compliance audit message (UDP `514`).

```frameassembly
host substation_hmi { ip 172.22.10.5   mac 00:1b:21:22:0a:05 }
host bay_rtu        { ip 172.22.10.50  mac 00:a0:c9:22:0a:32 }
host s7_plc         { ip 172.22.10.60  mac 00:0e:8c:22:0a:3c }
host idmz_historian { ip 172.22.20.100 mac 00:50:56:22:14:64 }

flow substation_conduit_telemetry(hmi, rtu, plc, idmz) {
    // 1. Level 1-2 Process VLAN 110 (802.1p PCP 6): Modbus TCP register poll
    hmi -> rtu vlan 110 pcp 6 modbus readholdingregisters txid 1 unitid 1 addr 40001 count 8 wait 1ms
    hmi <- rtu vlan 110 pcp 6 modbus readholdingregisters txid 1 unitid 1 count 8 value 13800 isresponse wait 2ms

    // 2. Level 1-2 Process VLAN 110: IEEE 1815 DNP3 Class 0 read & analog input response
    hmi -> rtu vlan 110 pcp 6 dnp3 read src 1 dst 10 group 60 variation 1 wait 2ms
    hmi <- rtu vlan 110 pcp 6 dnp3 func "response" src 10 dst 1 group 30 variation 1 wait 2ms

    // 3. Level 1-2 Process VLAN 110: Siemens S7comm DB1 variable read
    hmi -> plc vlan 110 pcp 6 s7comm rosctr "job" readvar pduref 10 area 0x84 dbnum 1 offset 0 count 4 wait 2ms
    hmi <- plc vlan 110 pcp 6 s7comm rosctr "ackdata" readvar pduref 10 count 4 payload "DB1_OK" wait 2ms

    // 4. Level 3.5 IDMZ VLAN 120 (802.1p PCP 4): OPC UA Historian push & Syslog SIEM audit
    hmi -> idmz vlan 120 pcp 4 opcua msgtype "hel" chunktype "f" endpointurl "opc.tcp://172.22.20.100:4840/historian" wait 1ms
    hmi <- idmz vlan 120 pcp 4 opcua msgtype "ack" chunktype "f" wait 1ms
    hmi -> idmz vlan 120 pcp 4 opcua msgtype "msg" chunktype "f" securechannelid 10 tokenid 1 seqnum 1 reqid 1 nodeid "ns=3;s=Feeder01.BusVoltageKV" payload "138.0" wait 2ms
    hmi -> idmz vlan 120 pcp 4 syslog facility 4 severity 5 hostname "sub-hmi-01" app "scada-poller" msg "IEC62443-Conduit: Authorized Level 1 poll & IDMZ push completed"
}

compile {
    substation_conduit_telemetry(substation_hmi, bay_rtu, s7_plc, idmz_historian)
}
```
