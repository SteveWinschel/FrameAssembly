# Layer 3 Network, Routing, Tunneling, VPN & FHRP Reference

FrameAssembly supports **20 Layer 3 protocols** across IPv4 (`0x0800`) and IPv6 (`0x86DD`), along with universal IP header modifiers that can be applied to any frame statement.

---

## 1. Universal IPv4 & IPv6 Modifiers

| Modifier | Syntax | Range | Effect on Wire |
| :--- | :--- | :--- | :--- |
| **TTL / Hop Limit** | `TTL <u8>` | `0..255` | IPv4 TTL or IPv6 Hop Limit (`64` default, `255` for GTSM/NDP, `1` for link-local multicast) |
| **DiffServ QoS** | `DSCP <u8>` | `0..63` | 6-bit DSCP (`46` = EF Voice, `34` = AF41 Video, `48` = CS6 Routing Control) |
| **Congestion Bits** | `ECN <u8>` | `0..3` | 2-bit Explicit Congestion Notification (`0`=Non-ECT, `1`=ECT1, `2`=ECT0, `3`=CE) |
| **IPv6 Flow Label** | `FLOWLABEL <u20>`| `0..1048575` | 20-bit IPv6 Flow Label for ECMP hashing (ignored on IPv4 statements) |
| **IPv4 Frag ID** | `IPID <u16>` | `0..65535` | 16-bit IPv4 Identification field for fragment reassembly |
| **Frag Flags** | `DF`, `MF` | Bare flags | Sets IPv4 Don't Fragment (`0x4000`) or More Fragments (`0x2000`) |
| **Frag Offset** | `FRAGOFFSET <u16>`| `0..8191` | 13-bit IPv4 fragment offset in 8-byte units |
| **Inner Protocol** | `NEXT_HEADER <u8>`| `0..255` | Overrides protected inner protocol on IPsec/ESP/AH/IPv6 headers |

---

## 2. Diagnostics & IPv6 Neighbor Discovery (`ICMP` & `NDP`)

* **`ICMP` (Emits ICMPv4 on IPv4 pairs and ICMPv6 with RFC 4443 pseudo-header checksum on IPv6 pairs):**
  * Message types: `ECHO_REQUEST`, `ECHO_REPLY`, `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`.
  * Modifiers: `CODE <u8>` (e.g. `3` = Port Unreachable, `4` = Frag Needed, `13` = Admin Prohibited), `ID <u16>`, `SEQ <u32>`, `GATEWAY <ip>`.
* **`NDP` (IPv6 Neighbor Discovery — RFC 4861, default Hop Limit `255`):**
  * Message types: `ROUTER_SOLICIT`, `ROUTER_ADVERT`, `NEIGHBOR_SOLICIT`, `NEIGHBOR_ADVERT`.
  * Modifiers: `TARGET <ipv6>`, `SLLA <mac>` (Source Link-Layer Address option), `TLLA <mac>` (Target Link-Layer Address option), `ROUTER_LIFETIME <u16>`.

```frameassembly
host client_v4 { ip 192.168.10.50 }
host router_v4 { ip 192.168.10.1 }
host host_v6   { ip 2001:db8:100::50 mac 00:50:56:60:00:50 }
host router_v6 { ip 2001:db8:100::1  mac 00:50:56:60:00:01 }

flow diagnostics_and_slaac(c4, r4, h6, r6) {
    // IPv4 ping, Path MTU Discovery (Code 4), and Redirect
    c4 -> r4 icmp echo_request id 1001 seq 1 payload "IPV4_PROBE" wait 1ms
    c4 <- r4 icmp echo_reply id 1001 seq 1 payload "IPV4_PROBE" wait 1ms
    c4 <- r4 icmp dest_unreach code 4 payload "PMTUD_MTU_1400" wait 1ms
    c4 <- r4 icmp redirect code 1 gateway 192.168.10.254 wait 2ms

    // IPv6 SLAAC Router Solicitation/Advertisement and Neighbor Discovery
    h6 -> r6 ndp router_solicit slla 00:50:56:60:00:50 ttl 255 wait 2ms
    h6 <- r6 ndp router_advert slla 00:50:56:60:00:01 router_lifetime 1800 ttl 255 wait 2ms
    h6 -> r6 ndp neighbor_solicit target 2001:db8:100::1 slla 00:50:56:60:00:50 ttl 255 wait 2ms
    h6 <- r6 ndp neighbor_advert target 2001:db8:100::1 tlla 00:50:56:60:00:01 ttl 255
}

compile {
    diagnostics_and_slaac(client_v4, router_v4, host_v6, router_v6)
}
```

---

## 3. Multicast Group Management (`IGMP` & `MLD`)

| Protocol | Modifiers | Description |
| :--- | :--- | :--- |
| **`IGMP`** | `QUERY`, `REPORT`, `LEAVE`, `V1` / `V2` / `V3` (`VERSION <1..3>`), `GROUP <ipv4>`, `MAX_RESP <u8>` | IPv4 multicast membership query, join report, and fast-leave (`MAX_RESP` in 1/10s) |
| **`MLD`** | `QUERY`, `REPORT`, `DONE`, `MULTICAST_ADDR <ipv6>`, `MAX_RESP_DELAY <u16>` | IPv6 ICMPv6 Multicast Listener Discovery (`MAX_RESP_DELAY` in ms) |

```frameassembly
host rtr_v4 { ip 10.40.1.1 }
host stb_v4 { ip 10.40.1.50 }
host rtr_v6 { ip fe80::1 }
host sub_v6 { ip fe80::50 }

flow multicast_lifecycle(r4, h4, r6, h6) {
    r4 -> h4 igmp version 3 query group 239.255.1.1 max_resp 100 ttl 1 wait 2ms
    r4 <- h4 igmp version 2 report group 239.255.1.1 ttl 1 wait 2ms
    r4 <- h4 igmp version 2 leave group 239.255.1.1 ttl 1 wait 5ms

    r6 -> h6 mld query multicast_addr ff3e::100 max_resp_delay 1000 ttl 1 wait 2ms
    r6 <- h6 mld report multicast_addr ff3e::100 ttl 1 wait 2ms
    r6 <- h6 mld done multicast_addr ff3e::100 ttl 1
}

compile {
    multicast_lifecycle(rtr_v4, stb_v4, rtr_v6, sub_v6)
}
```

---

## 4. Overlay & Underlay Tunneling (`GRE`, `VXLAN`, `GENEVE`)

| Protocol | Default Port / Proto | Modifiers & Behavior |
| :--- | :--- | :--- |
| **`GRE`** | IP Proto `47` | `GRE_KEY <u32>`, `GRE_SEQ <u32>`, `GRE_PROTO <u16>` (`0x0800` IPv4, `0x86DD` IPv6, `0x6558` TEB), `CHECKSUM` |
| **`VXLAN`** | UDP `4789` | `VNI <0..16777215>` (or `VNID`), `SRCPORT <u16>`, `DSTPORT <u16>` (emits a valid inner Ethernet+IPv4+UDP frame if payload is omitted) |
| **`GENEVE`**| UDP `6081` | `VNI <0..16777215>`, `OPT_CLASS <u16>` (e.g. `0x0102` OVN/Cilium, `0x0108` AWS GWLB), `OPT_TYPE <u8>`, `PROTOCOL_TYPE <u16>` |

```frameassembly
host vtep_a { ip 10.200.0.1 }
host vtep_b { ip 10.200.0.2 }

flow fabric_overlays(a, b) {
    a -> b gre gre_key 50010 gre_seq 1 gre_proto 0x0800 checksum payload "GRE_ROUTED_PACKET" wait 1ms
    a -> b vxlan vni 10500 df payload "EVPN_VXLAN_TENANT_FRAME" wait 1ms
    a -> b geneve vni 20800 opt_class 0x0102 opt_type 1 protocol_type 0x6558 payload "CILIUM_GENEVE_FRAME"
}

compile {
    fabric_overlays(vtep_a, vtep_b)
}
```

---

## 5. Cryptographic VPNs (`IKEV2`, `IPSEC`, `ESP`, `AH`, `WIREGUARD`)

| Protocol | Default Port / Proto | Modifiers |
| :--- | :--- | :--- |
| **`IKEV2`** | UDP `500` / `4500` | `SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL`, `EXCHANGE <mode>`, `INITIATOR_SPI <u64>`, `RESPONDER_SPI <u64>`, `MSGID <u32>`, `NEXT_PAYLOAD <u8>` |
| **`IPSEC` / `ESP`**| IP Proto `50` | `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`, `NEXT_HEADER <u8>` (`4`=IPv4, `6`=TCP, `41`=IPv6) |
| **`AH`** | IP Proto `51` | `SPI <u32>`, `SEQ <u32>`, `ICV "<hex>"`, `NEXT_HEADER <u8>` |
| **`WIREGUARD`**| UDP `51820` | `TYPE <INITIATION\|RESPONSE\|COOKIE\|DATA>` (or bare `INITIATION`, `COOKIE`, `DATA`), `SENDER <u32>`, `RECEIVER <u32>`, `COUNTER <u64>` |

```frameassembly
host branch_vpn { ip 198.51.100.10 }
host hq_vpn     { ip 203.0.113.1 }

flow ipsec_and_wireguard(branch, hq) {
    branch -> hq ikev2 sa_init initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0 msgid 0 next_payload 33 wait 2ms
    branch <- hq ikev2 sa_init initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x9988776655440002 msgid 0 next_payload 33 wait 2ms
    branch -> hq esp spi 0x10002001 seq 1 iv "1122334455667788" icv "aabbccddeeff001122334455" next_header 4 payload "ESP_CIPHERTEXT" wait 1ms
    branch <- hq ah spi 0x20003002 seq 1 icv "99887766554433221100ffeeddcc" next_header 4 payload "AH_AUTHENTICATED" wait 5ms

    branch -> hq wireguard type initiation sender 0x10203040 wait 1ms
    branch <- hq wireguard type response sender 0x50607080 receiver 0x10203040 wait 1ms
    branch -> hq wireguard type data receiver 0x50607080 counter 1 payload "WG_TRANSPORT_DATA"
}

compile {
    ipsec_and_wireguard(branch_vpn, hq_vpn)
}
```

---

## 6. Dynamic Routing Protocols (`OSPF`, `BGP`, `RIP`, `PIM`)

| Protocol | Default Port / Proto | Modifiers & Syntax Notes |
| :--- | :--- | :--- |
| **`OSPF`** | IP Proto `89` | `HELLO`, `DBD`, `LSR`, `LSU`, `LSACK`, `ROUTER_ID <ipv4>`, `AREA_ID <u32>` *(integer, e.g. `0` for Area 0.0.0.0)*, `HELLO_INTERVAL <u16>`, `DEAD_INTERVAL <u32>`, `PRIORITY <u8>` |
| **`BGP`** | TCP `179` | `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ASN <u32>`, `HOLDTIME <u16>`, `BGPID <ipv4>`, `PREFIX "<cidr>"` *(quoted CIDR string)*, `NEXTHOP <ip>` |
| **`RIP`** | UDP `520` | `REQUEST`, `RESPONSE`, `PREFIX <ip>` *(unquoted IP address)*, `NEXTHOP <ip>`, `METRIC <1..16>`, `TAG <u16>` |
| **`PIM`** | IP Proto `103` | `HELLO`, `JOIN_PRUNE`, `REGISTER`, `GROUP <ip>`, `SOURCE <ip>`, `RP <ip>`, `HOLDTIME <u16>`, `DR_PRIORITY <u32>` |

```frameassembly
host rtr1 { ip 10.0.0.1 }
host rtr2 { ip 10.0.0.2 }

flow routing_convergence(r1, r2) {
    r1 -> r2 ospf hello router_id 1.1.1.1 area_id 0 hello_interval 10 dead_interval 40 ttl 1 wait 1ms
    r1 <- r2 ospf hello router_id 2.2.2.2 area_id 0 hello_interval 10 dead_interval 40 ttl 1 wait 1ms
    r1 -> r2 bgp open asn 65001 holdtime 90 bgpid 1.1.1.1 ttl 255 wait 1ms
    r1 <- r2 bgp open asn 65002 holdtime 90 bgpid 2.2.2.2 ttl 255 wait 1ms
    r1 <- r2 bgp update asn 65002 prefix "172.16.0.0/12" nexthop 10.0.0.2 ttl 255 wait 1ms
    r1 -> r2 rip response prefix 192.168.50.0 nexthop 10.0.0.1 metric 2 tag 100 ttl 2 wait 1ms
    r1 <- r2 pim join_prune group 239.10.10.1 source 10.1.1.10 rp 10.0.0.1 ttl 1
}

compile {
    routing_convergence(rtr1, rtr2)
}
```

---

## 7. Gateway Redundancy, Fast Failover & SDN (`VRRP`, `HSRP`, `BFD`, `OPENFLOW`)

| Protocol | Default Port / Proto | Modifiers |
| :--- | :--- | :--- |
| **`VRRP`** | IP Proto `112` | `VERSION <2\|3>` (default `3`), `VRID <1..255>`, `PRIORITY <0..255>`, `ADV_INT <u16>`, `VIP <ip>` |
| **`HSRP`** | UDP `1985` | `GROUP <u8>`, `PRIORITY <u8>`, `STATE <u8>` (`16` = Active, `8` = Standby), `HELLOTIME <u8>`, `HOLDTIME <u16>`, `VIP <ip>` |
| **`BFD`** | UDP `3784` | `STATE <0..3>` (`3`=Up, `2`=Init, `1`=Down, `0`=AdminDown), `DIAG <u8>`, `MY_DISC <u32>`, `YOUR_DISC <u32>`, `MIN_TX <u32>` ($\mu$s), `MIN_RX <u32>` ($\mu$s), `MULT <u8>` |
| **`OPENFLOW`**| TCP `6653` | `HELLO`, `FEATURES_REQ`, `FEATURES_REPLY`, `PACKET_IN`, `PACKET_OUT`, `FLOW_MOD`, `ECHO_REQ`, `ECHO_REPLY`, `VERSION <u8>` (`4`=v1.3), `XID <u32>`, `DPID <u64>`, `TABLE_ID <u8>`, `PRIORITY <u16>` |

```frameassembly
host gw_pri { ip 10.10.0.2 }
host gw_sec { ip 10.10.0.3 }

flow gateway_ha_and_openflow(pri, sec) {
    pri -> sec vrrp version 3 vrid 10 priority 200 adv_int 1 vip 10.10.0.1 ttl 255 wait 1ms
    pri -> sec hsrp group 10 priority 150 state 16 hellotime 3 holdtime 10 vip 10.10.0.254 ttl 1 wait 1ms
    pri -> sec bfd state 3 diag 0 my_disc 1001 your_disc 2002 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 2ms
    pri <- sec openflow version 4 features_req xid 101 wait 1ms
    pri -> sec openflow version 4 features_reply xid 101 dpid 0x0000001c73aabbcc
}

compile {
    gateway_ha_and_openflow(gw_pri, gw_sec)
}
```