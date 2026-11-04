# Layer 3 — Routing, Overlays, Tunnels & VPNs (`docs/l3_protocols.md`)

[**Use Cases**](#layer-3-testing-and-security-use-cases) • [**Dual-Stack & IP Headers**](#what-frameassembly-handles-at-layer-3) • [**Diagnostics & Multicast**](#1-diagnostics-neighbor-discovery-and-multicast-icmp-ndp-igmp-mld) • [**Routing, FHRP, BFD & SDN**](#2-dynamic-routing-redundancy-bfd-and-sdn-ospf-bgp-rip-pim-vrrp-hsrp-bfd-openflow) • [**Overlays & Tunnels**](#3-wan-tunnels-and-fabric-overlays-gre-vxlan-geneve) • [**VPNs & IPsec**](#4-ipsec-ikev2-and-wireguard-vpns-ikev2-esp-ipsec-ah-wireguard)

## Why Use FrameAssembly for Layer 3?

Testing Layer 3 routing, overlay fabrics, and VPN gateways usually requires way too much infrastructure for a two-second check.

If you want to verify a BGP FlowSpec or RTBH blackhole filter, reproduce a `1400`-byte GRE/WireGuard Path MTU blackhole, test sub-second `BFD` + `VRRP` failovers, or check that Suricata flags an `IKEv2` NAT-T float to `UDP 4500`, your normal options are rough -> spin up a 6-node virtual router lab, wait 40 seconds for OSPF Dead timers, wrestle `strongSwan` configs, or clamp MTUs on a live interface and hope you don't drop your own SSH session :)

With **FrameAssembly**, you write the exact routing, overlay, or tunnel exchange in a few lines of `.fasm` packet code, compile a clean `.pcap` offline with zero `sudo` or lab VMs, and replay or inspect it with **`tcpreplay`**, **Wireshark** / **`tshark`**, **Suricata**, or **Zeek**:

```frameassembly
host leaf_01  { ip 10.0.1.1 mac 00:1c:73:c1:00:01 }
host spine_01 { ip 10.0.1.0 mac 00:1c:73:c0:00:01 }

flow clos_underlay_check(leaf, spine) {
    // 15ms single-hop BFD session (GTSM TTL 255, DSCP CS6)
    leaf -> spine dscp 48 ttl 255 bfd state 3 my_disc 1001 your_disc 2002 min_tx 15000 min_rx 15000 mult 3 wait 2ms
    leaf <- spine dscp 48 ttl 255 bfd state 3 my_disc 2002 your_disc 1001 min_tx 15000 min_rx 15000 mult 3 wait 2ms

    // 4-byte ASN eBGP prefix update + VXLAN L3VNI 50001 Symmetric IRB packet
    leaf -> spine dscp 48 ttl 1 bgp update asn 4200000001 prefix "10.255.1.11/32" nexthop 10.0.1.1 wait 2ms
    leaf -> spine dscp 26 df ttl 63 vxlan vni 50001 srcport 58001 dstport 4789 payload "EVPN_TYPE5_ROUTED_FLOW"
}

compile { clos_underlay_check(leaf_01, spine_01) }
```

```console
$ frameassembly show clos_check.fasm
$ frameassembly clos_check.fasm -o clos_check.pcap && sudo tcpreplay -i eth0 clos_check.pcap
```

| Protocol | Keyword | Wire Framing / Port | IPv4 & IPv6 | Primary Testing Focus |
| :--- | :--- | :--- | :---: | :--- |
| **ICMP / ICMPv6** | `icmp` | IP Proto `1` / NH `58` | Both | Ping, PMTUD `code 4`, traceroute `time_exceeded`, ACL `code 13` |
| **NDP** | `ndp` | ICMPv6 NH `58` | IPv6 | SLAAC `RS`/`RA`, `DAD` probes, Gratuitous `NA`, RA-Guard |
| **IGMP** | `igmp` | IP Proto `2` | IPv4 | IGMPv1/v2/v3 queries, IPTV channel zaps, market-data SSM joins |
| **MLD** | `mld` | ICMPv6 NH `58` | IPv6 | IPv6 multicast `query`, `report`, and fast-leave `done` |
| **OSPFv2 / v3** | `ospf` | IP Proto `89` | Both | 5-packet LSDB sync, DR/BDR election, fast leaf-spine timers |
| **BGP-4 / MP-BGP**| `bgp` | `TCP 179` | Both | 2B/4B ASNs, EVPN, RTBH blackholes, FlowSpec, `NOTIFICATION` |
| **RIPv2 / RIPng** | `rip` | `UDP 520` / `521` | Both | Route tags, split-horizon poison reverse (`metric 16`), default routes |
| **PIM-SM / SSM** | `pim` | IP Proto `103` | Both | DR priority, `(S,G)` SSM joins, RP `register`, RPT-to-SPT prune |
| **VRRPv2 / v3** | `vrrp` | IP Proto `112` | Both | Sub-second VIP heartbeats, object-track decrements, `prio 0` release |
| **HSRPv1 / v2** | `hsrp` | `UDP 1985` / `2029` | Both | Active/Standby elections, MHSRP load sharing, link-local IPv6 |
| **BFD / S-BFD** | `bfd` | `UDP 3784` / `4784` / `7784`| Both | 3.3ms link checks, multihop VTEP probes, `diag 0..9` teardowns |
| **OpenFlow** | `openflow` | `TCP 6653` (or `6633`) | Both | `HELLO`, `DPID` discovery, `PACKET_IN` punts, `FLOW_MOD` rules |
| **GRE / NVGRE** | `gre` | IP Proto `47` | Both | Routed GRE, `mGRE` DMVPN, `GRETAP` L2, `ERSPAN` II/III, MPLS-in-GRE |
| **VXLAN** | `vxlan` | `UDP 4789` (or `8472`) | Both | EVPN L2VNI/L3VNI IRB, ECMP source-port entropy, BUM multicast |
| **GENEVE** | `geneve` | `UDP 6081` | Both | Cilium, OVN, NSX-T, AWS GWLB, and P4 INT option TLVs |
| **IPsec ESP** | `esp` / `ipsec`| IP Proto `50` | Both | AES-GCM / ChaCha20 `IV`+`ICV`, tunnel/transport mode, anti-replay |
| **IPsec AH** | `ah` | IP Proto `51` | Both | Immutable header `ICV` integrity for `OSPF`, `BGP`, `VRRP`, `PIM` |
| **IKEv2** | `ikev2` | `UDP 500` / `4500` | Both | `SA_INIT`, `AUTH`, NAT-T `4500` float, DPD, stateless cookies, `SKF` |
| **WireGuard** | `wireguard`| `UDP 51820` (customizable) | Both | `Noise_IK` handshakes, `cookie` DDoS challenges, roaming, `UDP 443` |

*Note: `esp` and `ipsec` are interchangeable aliases that both emit RFC 4303 IP Protocol `50` frames (giving you all 20 Layer 3 protocol keywords).*

## Layer 3 Testing and Security Use Cases

### 1. Audit `eBGP` Policies, `OSPF` Adjacencies & `BFD` Fast Fallover Without a Router Lab
Testing whether an edge router honors RFC 7999 Remotely Triggered Black Hole (`RTBH`) announcements, drops peers on max-prefix `NOTIFICATION`, brings up all 5 `OSPF` packet types, or tears down sessions within 45ms when `BFD` expires (`diag 1`) takes one `.fasm` file instead of six VM images:

```frameassembly
host edge_rtr { ip 198.51.100.2 mac 00:1c:73:64:00:02 }
host isp_pe   { ip 198.51.100.1 mac 00:1c:73:64:00:01 }

flow routing_and_bfd_failover(ce, pe) {
    // 1. OSPF fast point-to-point sync (Hello -> DBD -> LSR -> LSU -> LSAck)
    ce -> pe dscp 48 ttl 1 ospf hello router_id 10.0.0.2 area_id 0 hello_interval 1 dead_interval 4 priority 0 wait 2ms
    ce <- pe dscp 48 ttl 1 ospf dbd   router_id 10.0.0.1 area_id 0 wait 2ms
    ce -> pe dscp 48 ttl 1 ospf lsr   router_id 10.0.0.2 area_id 0 wait 2ms
    ce <- pe dscp 48 ttl 1 ospf lsu   router_id 10.0.0.1 area_id 0 payload "router_lsa_seq_0x80000001" wait 2ms
    ce -> pe dscp 48 ttl 1 ospf lsack router_id 10.0.0.2 area_id 0 wait 5ms

    // 2. eBGP 4-byte ASN peering + RFC 7999 RTBH blackhole update
    ce -> pe dscp 48 ttl 1 bgp open asn 4200000010 holdtime 90 bgpid 10.0.0.2 wait 2ms
    ce <- pe dscp 48 ttl 1 bgp open asn 65001      holdtime 90 bgpid 10.0.0.1 wait 2ms
    ce -> pe dscp 48 ttl 1 bgp update asn 4200000010 prefix "203.0.113.200/32" nexthop 192.0.2.1 payload "COMMUNITY_65535_666_BLACKHOLE" wait 5ms

    // 3. BFD Control Detection Time Expired (state 1, diag 1) -> BGP Cease NOTIFICATION
    ce -> pe dscp 48 ttl 255 bfd state 1 diag 1 my_disc 17901 your_disc 0 min_tx 1000000 min_rx 1000000 mult 3 wait 2ms
    ce <- pe dscp 48 ttl 1 bgp notification payload "CEASE_BFD_SESSION_DOWN"
}

compile { routing_and_bfd_failover(edge_rtr, isp_pe) }
```

### 2. Validate Cloud-Native `GENEVE` & `VXLAN` Overlays (`Cilium`, `AWS GWLB`, `EVPN`)
Overlay bugs hide inside outer UDP source-port ECMP hashes and inner option TLVs. Craft **Cilium** security identity headers, **AWS Gateway Load Balancer (`GWLB`)** inspection hairpins (`opt_class 264`), **OVN/NSX-T** critical options (`opt_type >= 128`), and **EVPN-VXLAN** Symmetric IRB frames directly:

```frameassembly
host compute_nve { ip 10.244.0.11 mac 00:16:3e:60:81:0b }
host inspect_nve { ip 10.244.0.50 mac 02:a1:b2:60:81:32 }

flow cloud_overlay_inspection(nve, fw) {
    // 1. Cilium eBPF GENEVE pod-to-pod frame (opt_class 267, TEB 0x6558)
    nve -> fw df dscp 18 ttl 64 geneve vni 2 opt_class 267 opt_type 1 protocol_type 0x6558 srcport 51234 dstport 6081 payload "CILIUM_ID_42105_HTTP_GET" wait 2ms

    // 2. AWS GWLB appliance hairpin (opt_class 264, routed IPv4 0x0800)
    nve -> fw df ttl 64 geneve vni 1 opt_class 264 opt_type 1 protocol_type 0x0800 srcport 49800 dstport 6081 payload "AWS_GWLBE_FLOW_COOKIE_IN" wait 1ms
    nve <- fw df ttl 64 geneve vni 1 opt_class 264 opt_type 1 protocol_type 0x0800 srcport 49800 dstport 6081 payload "AWS_GWLBE_FLOW_COOKIE_OK" wait 2ms

    // 3. EVPN-VXLAN L3VNI 50001 Symmetric IRB with varied ECMP entropy source ports
    nve -> fw df dscp 26 ttl 63 vxlan vni 50001 srcport 58001 dstport 4789 payload "EVPN_TYPE5_SUBNET_A_TO_B"
}

compile { cloud_overlay_inspection(compute_nve, inspect_nve) }
```

### 3. Test VPN Concentrators & IDS Rules (`IKEv2` NAT-T, `ESP` Anti-Replay & `WireGuard` Cookies)
Reproducing VPN edge cases—like an `IKEv2` session floating from `UDP 500` to `UDP 4500` behind NAT, out-of-order `ESP` sequence numbers hitting a 64-packet anti-replay bitmap, or a `WireGuard` server issuing a Type 3 `cookie` challenge on custom `UDP 443`—requires zero crypto daemons:

```frameassembly
host roaming_cli { ip 198.51.100.88 mac 00:1b:21:51:82:58 }
host vpn_headend { ip 203.0.113.1   mac 00:1b:21:51:82:01 }

flow vpn_edge_cases(cli, gw) {
    // 1. IKEv2 SA_INIT on UDP 500 -> NAT-Traversal port float to UDP 4500
    cli -> gw dscp 48 ikev2 sa_init initiator_spi 111222333 responder_spi 0 msgid 0 flags 8 next_payload 33 srcport 500 dstport 500 wait 5ms
    cli <- gw dscp 48 ikev2 sa_init initiator_spi 111222333 responder_spi 444555666 msgid 0 flags 32 next_payload 33 srcport 500 dstport 500 wait 5ms
    cli -> gw dscp 48 ikev2 informational initiator_spi 111222333 responder_spi 444555666 msgid 1 flags 8 next_payload 46 srcport 4500 dstport 4500 wait 5ms

    // 2. AES-256-GCM IPsec ESP out-of-order anti-replay window test (seq 100 -> 103 -> 101)
    cli -> gw df dscp 34 esp spi 410601 seq 100 iv "0000000100000064" icv "102030405060708090a0b0c0d0e0f001" next_header 4 payload "ESP_SEQ_100" wait 2ms
    cli -> gw df dscp 34 esp spi 410601 seq 103 iv "0000000100000067" icv "102030405060708090a0b0c0d0e0f002" next_header 4 payload "ESP_SEQ_103_ADVANCE" wait 2ms
    cli -> gw df dscp 34 esp spi 410601 seq 101 iv "0000000100000065" icv "102030405060708090a0b0c0d0e0f003" next_header 4 payload "ESP_SEQ_101_REORDERED" wait 5ms

    // 3. WireGuard over UDP 443 with DDoS Cookie challenge -> retry -> encrypted DATA
    cli -> gw df wireguard initiation sender 44301 srcport 54321 dstport 443 wait 3ms
    cli <- gw df wireguard cookie receiver 44301 srcport 443 dstport 54321 wait 3ms
    cli -> gw df wireguard initiation sender 44302 srcport 54321 dstport 443 wait 3ms
    cli <- gw df wireguard response sender 44303 receiver 44302 srcport 443 dstport 54321 wait 3ms
    cli -> gw df wireguard data receiver 44303 counter 0 srcport 54321 dstport 443 payload "CHACHA20_FIRST_PKT"
}

compile { vpn_edge_cases(roaming_cli, vpn_headend) }
```

### 4. Debug WAN Path MTU Blackholes (`DF` + `ICMP Code 4`), `ERSPAN` & `VRRP` / `HSRP` Failovers
Silent MTU blackholes over `GRE` tunnels and flapping `VRRP` / `HSRP` gateways are classic Friday-afternoon outages. Script the exact `DF` probe, `ICMP Fragmentation Needed (Code 4)` response, `ERSPAN` mirror stream, and tracked gateway failover:

```frameassembly
host app_srv    { ip 10.88.1.10  mac 00:50:56:88:01:0a }
host wan_pri_gw { ip 10.88.1.2   mac 00:00:5e:00:01:58 }
host wan_sec_gw { ip 10.88.1.3   mac 00:1c:73:88:01:03 }
host ndr_sensor { ip 172.20.99.9 mac 00:25:b5:47:89:09 }

flow pmtud_fhrp_and_erspan(srv, pri, sec, ndr) {
    // 1. Oversized DF ping hits 1400B GRE tunnel limit -> router returns ICMP Type 3 Code 4
    srv -> pri df ttl 64 icmp echo_request id 4410 seq 1 payload "oversized_1472_byte_wan_probe" wait 2ms
    srv <- pri ttl 64 icmp dest_unreach code 4 payload "mtu_1400_exceeded_on_gre0" wait 5ms

    // 2. VRRPv3 object-track priority decrement (130 -> 80) + Backup preemption (100)
    pri -> sec dscp 48 ttl 255 vrrp vrid 88 priority 80  adv_int 20 vip 10.88.1.1 version 3 wait 5ms
    pri <- sec dscp 48 ttl 255 vrrp vrid 88 priority 100 adv_int 20 vip 10.88.1.1 version 3 wait 5ms

    // 3. Secondary gateway mirrors traffic to NDR probe via Cisco ERSPAN Type III (0x22eb)
    sec -> ndr df dscp 16 ttl 64 gre gre_key 301 gre_seq 5001 gre_proto 0x22eb payload "ERSPAN_III_SPAN_FRAME"
}

compile { pmtud_fhrp_and_erspan(app_srv, wan_pri_gw, wan_sec_gw, ndr_sensor) }
```

### 5. Simulate Multicast Feeds (`IGMP`, `MLD`, `PIM-SSM`) & Reactive `OpenFlow` Scrubbing
Whether you are validating ultra-low-latency market-data joins (`232.0.0.0/8` SSM), residential IPTV fast channel zaps over IPv6 `MLD`, or an SDN controller pushing a priority-`65000` `OpenFlow` drop rule after a `PACKET_IN` anomaly, everything stays deterministic:

```frameassembly
host trade_srv { ip 10.200.40.15 mac 00:0f:53:d2:28:0f }
host leaf_ofs  { ip 10.200.40.1  mac 00:1c:73:67:c8:01 }
host sdn_ctrl  { ip 10.254.0.10  mac 00:1c:73:fe:00:0a }

flow multicast_and_sdn_scrub(srv, sw, ctrl) {
    // 1. IGMPv3 SSM join -> upstream PIM-SSM (S,G) Join without an RP
    srv -> sw vlan 200 pcp 6 dscp 48 ttl 1 igmp report group 232.200.1.50 version 3 payload "ALLOW_192.0.2.200" wait 1ms
    sw -> ctrl vlan 200 pcp 6 dscp 48 ttl 1 pim join_prune group 232.200.1.50 source 192.0.2.200 holdtime 60 wait 5ms

    // 2. OpenFlow 1.3 (version 4) PACKET_IN anomaly -> priority 65000 FLOW_MOD drop rule
    sw -> ctrl dscp 48 openflow packet_in version 4 xid 801 table_id 0 payload "syn_flood_sample" wait 5ms
    sw <- ctrl dscp 48 openflow flow_mod  version 4 xid 802 table_id 0 priority 65000 payload "drop_malicious_oxm"
}

compile { multicast_and_sdn_scrub(trade_srv, leaf_ofs, sdn_ctrl) }
```

## What FrameAssembly Handles at Layer 3

* **True Dual-Stack Polymorphism:** Write a `flow` once with `icmp`, `ospf`, `bgp`, `rip`, `pim`, `vrrp`, `hsrp`, `bfd`, `openflow`, `gre`, `vxlan`, `geneve`, `esp`/`ipsec`, `ah`, `ikev2`, or `wireguard` and pass either IPv4 or IPv6 `host` endpoints inside `compile`. FrameAssembly switches between IPv4 (`0x0800`) and IPv6 (`0x86dd`—including `ICMPv6`, `OSPFv3`, `MP-BGP`, `RIPng`, `VRRPv3`, and `HSRPv2` on `UDP 2029`) automatically.
* **Full IPv4 / IPv6 Outer Header Control:** Add `ttl <0..255>` (IPv4 TTL / IPv6 Hop Limit—such as `ttl 255` for GTSM or `ttl 1` for link-local multicast), `dscp <0..63>`, `ecn <0..3>`, `flowlabel <0..1048575>` (20-bit IPv6 ECMP Flow Label), `df`, `ipid <u16>`, `mf`, and `fragoffset <0..8191>` to any statement.
* **Automatic RFC Multicast MACs:** Any `host` with an IPv4 multicast IP (`224.0.0.0/4`, such as `224.0.0.5` OSPF or `224.0.0.18` VRRP) or IPv6 multicast IP (`ff00::/8`, such as `ff02::5` OSPFv3 or `ff02::12` VRRPv3) automatically derives `01:00:5e:xx:xx:xx` or `33:33:xx:xx:xx:xx` when `mac` is omitted.
* **Cross-Layer Stacking:** Combine any Layer 3 protocol with `vlan <id> [pcp <n>] [dei <0|1>]`, `qinq <svid> inner_vlan <cvid>`, or `mpls <label> [exp <n>] [bos <0|1>] [mpls_ttl <n>]` on the exact same line.

## Layer 3 Protocol Reference & Cheat Sheets

### 1. Diagnostics, Neighbor Discovery and Multicast (`ICMP`, `NDP`, `IGMP`, `MLD`)

| Protocol | Sub-Keywords / Types | Key Modifiers | Unit & Wire Notes |
| :--- | :--- | :--- | :--- |
| **`icmp`** | `echo_request`, `echo_reply`, `dest_unreach`, `time_exceeded`, `redirect` | `code <u8>`, `id <u16>`, `seq <u16>`, `gateway <ipv4>` | `code 4` = PMTUD Frag Needed; `code 13` = Admin Prohibited; auto-adapts to ICMPv6 |
| **`ndp`** | `router_solicit`, `router_advert`, `neighbor_solicit`, `neighbor_advert` | `target <ipv6>`, `slla <mac>`, `tlla <mac>`, `router_lifetime <u16>` | Pair with `ttl 255` (RFC 4861 GTSM); `router_lifetime 0` withdraws default router |
| **`igmp`** | `query`, `report`, `leave` | `version <1..3>`, `group <ipv4>`, `max_resp <u8>` | `max_resp` is in **`1/10`s deciseconds** (`100` = `10.0s`, `10` = `1.0s`); `group 0.0.0.0` = General Query |
| **`mld`** | `query`, `report`, `done` | `multicast_addr <ipv6>`, `max_resp_delay <u16>` | `max_resp_delay` is in **milliseconds** (`10000` = `10s`, `500` = `0.5s`); `multicast_addr ::` = General Query |

### 2. Dynamic Routing, Redundancy, BFD and SDN (`OSPF`, `BGP`, `RIP`, `PIM`, `VRRP`, `HSRP`, `BFD`, `OPENFLOW`)

| Protocol | Operations / Types | Modifiers | Common Values & Defaults |
| :--- | :--- | :--- | :--- |
| **`ospf`** | `hello`, `dbd`, `lsr`, `lsu`, `lsack` | `router_id <ipv4>`, `area_id <u32>`, `hello_interval <u16>`, `dead_interval <u32>`, `priority <u8>` | `priority 0` = P2P / DROther; multicast `224.0.0.5` (`ff02::5` OSPFv3) |
| **`bgp`** | `open`, `update`, `notification`, `keepalive` | `asn <u32>`, `holdtime <u16>`, `bgpid <ipv4>`, `prefix "<cidr>"`, `nexthop <ip>` | Supports 2B & 4B ASNs (`4200000001`); `TCP 179`; GTSM `ttl 255` or eBGP `ttl 1` |
| **`rip`** | `request`, `response` | `prefix <ip>`, `metric <1..16>`, `nexthop <ipv4>`, `tag <u16>` | `metric 16` = poison-reverse infinity; IPv4 `UDP 520` (`224.0.0.9`), IPv6 `UDP 521` (`ff02::9`) |
| **`pim`** | `hello`, `join_prune`, `register` | `dr_priority <u32>`, `holdtime <u16>`, `group <ip>`, `source <ip>`, `rp <ip>` | `holdtime 0` = Goodbye; `source` without `rp` = SSM `(S,G)`; `224.0.0.13` / `ff02::d` |
| **`vrrp`** | Advertisement | `vrid <1..255>`, `priority <0..255>`, `vip <ip>`, `version <2\|3>`, `adv_int <u16>` | `adv_int` in **centiseconds** on v3 (`20` = 200ms); `priority 255` owner, `0` shutdown release |
| **`hsrp`** | Hello / Coup / Resign | `group <u16>`, `priority <0..255>`, `state <u8>`, `vip <ip>`, `hellotime <u8>`, `holdtime <u8>` | `state`: `0` Init, `1` Learn, `2` Listen, `4` Speak, `8` Standby, `16` Active |
| **`bfd`** | Control / Echo / S-BFD | `state <0..3>`, `diag <0..9>`, `my_disc <u32>`, `your_disc <u32>`, `min_tx <u32>`, `min_rx <u32>`, `mult <u8>` | `min_tx`/`min_rx` in **microseconds** (`3300` = 3.3ms, `50000` = 50ms); `state 3` = Up |
| **`openflow`**| `[type] hello`, `features_req`, `features_reply`, `echo_req`, `echo_reply`, `packet_in`, `packet_out`, `flow_mod` | `version <1..6>`, `xid <u32>`, `dpid <u64>`, `table_id <u8>`, `priority <u16>` | `version 4` = OpenFlow 1.3 (`1` = OF 1.0, `5` = OF 1.4); `TCP 6653` (override `dstport 6633` for legacy) |

> **Quick Syntax Check (`bgp` vs. `rip` Prefixes & Timer Units):**
> * **`bgp` `prefix` uses quotes** because of the `/mask` slash (`bgp update prefix "10.10.0.0/16" nexthop 10.0.0.1`), whereas **`rip` `prefix` is an unquoted IP** (`rip response prefix 10.10.0.0 metric 2`). All other IP and MAC modifiers (`nexthop`, `bgpid`, `router_id`, `vip`, `target`, `slla`, `tlla`) are unquoted.
> * Watch the RFC timer units: `bfd` `min_tx`/`min_rx` = **microseconds (`us`)**, `mld` `max_resp_delay` = **milliseconds (`ms`)**, `vrrp` v3 `adv_int` = **centiseconds (`1/100`s)**, `igmp` `max_resp` = **deciseconds (`1/10`s)**, and `ospf`/`bgp`/`hsrp`/`pim` timers = **seconds (`s`)**.

#### `BFD` State & Diagnostic Codes (`RFC 5880` / `RFC 6428`)

| `state` | Meaning | `diag` | Diagnostic Reason |
| :---: | :--- | :---: | :--- |
| `0` | `AdminDown` | `0` / `1` | `0` No Diagnostic / `1` Control Detection Time Expired |
| `1` | `Down` | `2` / `3` | `2` Echo Function Failed / `3` Neighbor Signaled Session Down |
| `2` | `Init` | `4` / `5` | `4` Forwarding Plane Reset / `5` Path Down |
| `3` | `Up` | `6`..`9` | `6` Concat Path Down, `7` Admin Down, `8` Rev Concat Down, `9` Misconnectivity |

### 3. WAN Tunnels and Fabric Overlays (`GRE`, `VXLAN`, `GENEVE`)

| Protocol | Modifiers & Aliases | Common Passenger Protocol / Option Values |
| :--- | :--- | :--- |
| **`gre`** | `gre_proto <u16>`, `gre_key <u32>`, `gre_seq <u32>`, `checksum` | `0x0800` (`2048`) IPv4, `0x86dd` (`34525`) IPv6, `0x6558` (`25944`) L2 `GRETAP`/`NVGRE`, `0x8847` (`34887`) MPLS-in-GRE, `0x88be` (`35006`) ERSPAN II, `0x22eb` (`8939`) ERSPAN III, `0x00fe` (`254`) IS-IS CLNS |
| **`vxlan`** | `vni <0..16777215>` (alias `vnid`), `srcport <p>`, `dstport <p>` | Default `UDP 4789` (`dstport 8472` for legacy Linux/Flannel); `vni 1` for RFC 8971 BFD-over-VXLAN |
| **`geneve`** | `vni <0..16777215>` (alias `vnid`), `opt_class <u16>`, `opt_type <u8>`, `protocol_type <u16>` | `opt_class`: `258` (`0x0102`) OVN, `259` (`0x0103`) P4 INT, `260` (`0x0104`) NSX-T, `264` (`0x0108`) AWS GWLB, `267` Cilium; `opt_type >= 128` sets Critical bit; `protocol_type`: `0x6558` L2 TEB, `0x0800` IPv4, `0x86dd` IPv6, `0x8847` MPLS, `0x894f` NSH |

### 4. IPsec, IKEv2 and WireGuard VPNs (`IKEV2`, `ESP` / `IPSEC`, `AH`, `WIREGUARD`)

| Protocol | Sub-Keywords / Exchanges | Modifiers | Wire & Security Notes |
| :--- | :--- | :--- | :--- |
| **`ikev2`** | `[exchange] sa_init`, `auth`, `create_child_sa`, `informational` | `initiator_spi <u64>`, `responder_spi <u64>`, `msgid <u32>`, `flags <u8>`, `next_payload <u8>` | `flags`: `8` Initiator, `32` Response; `next_payload`: `33` SA, `41` Notify/Cookie, `42` Delete, `46` SK, `53` SKF fragment; float to `dstport 4500` for NAT-T |
| **`esp`** / **`ipsec`** | Encrypted SA frame | `spi <u32>`, `seq <u32>`, `iv "<hex>"`, `icv "<hex>"`, `next_header <u8>` | `next_header`: `4` IPv4 tunnel, `41` IPv6 tunnel, `6` TCP, `17` UDP, `47` GRE/DMVPN, `89` OSPF, `132` SCTP, `59` TFC dummy padding |
| **`ah`** | Authenticated header | `spi <u32>`, `seq <u32>`, `icv "<hex>"`, `next_header <u8>` | Authenticates outer IP + upper-layer control protocols (`6` BGP, `89` OSPF, `103` PIM, `112` VRRP, `58` NDP) |
| **`wireguard`**| `[type] initiation`, `response`, `cookie`, `data` | `sender <u32>`, `receiver <u32>`, `counter <u64>` | Default `UDP 51820` (override `dstport 443` or `41641` as needed); omit `payload` on `data` for 0-byte NAT-T `PersistentKeepalive` |

## Inspecting and Replaying Layer 3 Captures

```console
# Inspect BGP ASNs/prefixes, OSPF areas, BFD timers, and VXLAN/GENEVE VNIs in tshark
$ tshark -r clos_check.pcap -T fields -e frame.number -e ip.src -e ip.dst -e bfd.sta -e bgp.type -e vxlan.vni

# Validate Suricata IDS rules against custom IKEv2, WireGuard, or BGP FlowSpec pcaps
$ suricata -r vpn_edge_cases.pcap -k none

# Replay routing, FHRP, or overlay captures onto a lab interface
$ sudo tcpreplay -i eth0 clos_check.pcap
```

## Related Documentation

* [**Getting Started (`getting_started.md`)**](getting_started.md) — `host` / `flow` / `compile` mechanics, IPv4 fragmentation modifiers, and `frameassembly show`.
* [**Real-World Use Cases (`use_cases.md`)**](use_cases.md) — Copy-paste recipes for firewall audits, QoS trunks, SIEM ingest, and OT conduits.
* [**Layer 2 — Switching & Data Link (`l2_protocols.md`)**](l2_protocols.md) — Stack Layer 3 protocols over `vlan`, `qinq`, `mpls`, `arp`, `lacp`, and `stp`.
* [**Layer 4 — Transports (`l4_transports.md`)**](l4_transports.md) — Stateful `tcp` handshakes, `udp`, and `sctp` multi-stream associations.
* [**Layer 7 — SNMPv1 / v2c / v3 (`l7_snmp.md`)**](l7_snmp.md) — Pair routing/link failovers with `snmp2` and encrypted `snmp3` traps.
* [**Layer 7 — Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — Combine fabrics and routers with `netflow`, `ipfix`, `sflow`, `syslog`, `ntp`, `ptp`, and `tacacs`.
* [**Topologies & Dual-Stack (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — End-to-end EVPN-VXLAN Leaf-Spine, WAN failover, and dual-stack captures.