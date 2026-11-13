# Layer 3: Routing, Overlays, Tunnels & VPNs

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Somebody has to test what the edge router does when an eBGP peer announces an RTBH blackhole, or how long OSPF takes to notice a dead neighbor. The honest options are: boot six router VMs and wait for a 40-second Dead timer, or try it on the production edge and keep your CV current. FrameAssembly offers a third option. Write the routing exchange, tunnel, or VPN handshake as `.frasm` code, compile a `.pcap`, and replay it with **`tcpreplay`** or inspect it with **Wireshark** / **`tshark`**, **Suricata**, or **Zeek**.

Every Layer 3 protocol here works over IPv4 and IPv6. Write the `flow` once, pass either kind of `host` into `compile`, and FrameAssembly switches between IPv4 (`0x0800`) and IPv6 (`0x86dd`), including ICMPv6, OSPFv3, MP-BGP, RIPng, VRRPv3, and HSRPv2 on `UDP 2029`.

* **Outer IP header:** add `ttl <0..255>` (IPv4 TTL or IPv6 Hop Limit: `255` for GTSM, `1` for link-local multicast), `dscp <0..63>`, `ecn <0..3>`, `flowlabel <0..1048575>` (the 20-bit IPv6 ECMP label), `df`, `mf`, `ipid <u16>`, and `fragoffset <0..8191>` to any statement.
* **Multicast MACs:** a host with an IPv4 multicast IP (`224.0.0.5` for OSPF, `224.0.0.18` for VRRP) or an IPv6 one (`ff02::5`, `ff02::12`) and no `mac` gets `01:00:5e:xx:xx:xx` or `33:33:xx:xx:xx:xx` automatically.
* **Stacking:** put `vlan <id> [pcp <n>] [dei <0|1>]`, `qinq <svid> innervlan <cvid>`, or `mpls <label> [exp <n>] [bos <0|1>] [mplsttl <n>]` on the same line as any Layer 3 protocol.

| Protocol | Keyword | Wire Framing / Port | IPv4 & IPv6 | Typical Use |
| :--- | :--- | :--- | :---: | :--- |
| **ICMP / ICMPv6** | `icmp` | IP Proto `1` / NH `58` | Both | Ping, PMTUD `code 4`, traceroute `timeexceeded`, ACL `code 13` |
| **NDP** | `ndp` | ICMPv6 NH `58` | IPv6 | SLAAC RS/RA, DAD probes, Gratuitous NA, RA-Guard |
| **IGMP** | `igmp` | IP Proto `2` | IPv4 | IGMPv1/v2/v3 queries, IPTV channel zaps, SSM joins |
| **MLD** | `mld` | ICMPv6 NH `58` | IPv6 | IPv6 multicast `query`, `report`, fast-leave `done` |
| **OSPFv2 / v3** | `ospf` | IP Proto `89` | Both | 5-packet LSDB sync, DR/BDR election, fast timers |
| **BGP-4 / MP-BGP** | `bgp` | `TCP 179` | Both | 2B/4B ASNs, EVPN, RTBH blackholes, FlowSpec, `notification` |
| **RIPv2 / RIPng** | `rip` | `UDP 520` / `521` | Both | Route tags, poison reverse (`metric 16`), default routes |
| **PIM-SM / SSM** | `pim` | IP Proto `103` | Both | DR priority, `(S,G)` SSM joins, RP `register`, RPT-to-SPT prune |
| **VRRPv2 / v3** | `vrrp` | IP Proto `112` | Both | Sub-second VIP heartbeats, object-track decrements, `priority 0` release |
| **HSRPv1 / v2** | `hsrp` | `UDP 1985` / `2029` | Both | Active/Standby elections, MHSRP load sharing, link-local IPv6 |
| **BFD / S-BFD** | `bfd` | `UDP 3784` / `4784` / `7784` | Both | 3.3ms link checks, multihop VTEP probes, `diag 0..9` teardowns |
| **OpenFlow** | `openflow` | `TCP 6653` (or `6633`) | Both | `hello`, `dpid` discovery, `packetin` punts, `flowmod` rules |
| **GRE / NVGRE** | `gre` | IP Proto `47` | Both | Routed GRE, mGRE DMVPN, GRETAP L2, ERSPAN II/III, MPLS-in-GRE |
| **VXLAN** | `vxlan` | `UDP 4789` (or `8472`) | Both | EVPN L2VNI/L3VNI IRB, ECMP source-port entropy, BUM multicast |
| **GENEVE** | `geneve` | `UDP 6081` | Both | Cilium, OVN, NSX-T, AWS GWLB, P4 INT option TLVs |
| **IPsec ESP** | `esp` / `ipsec` | IP Proto `50` | Both | AES-GCM / ChaCha20 `iv` + `icv`, tunnel/transport mode, anti-replay |
| **IPsec AH** | `ah` | IP Proto `51` | Both | Immutable-header `icv` integrity for `ospf`, `bgp`, `vrrp`, `pim` |
| **IKEv2** | `ikev2` | `UDP 500` / `4500` | Both | `sainit`, `auth`, NAT-T float to `4500`, DPD, stateless cookies, SKF |
| **WireGuard** | `wireguard` | `UDP 51820` (customizable) | Both | `Noise_IK` handshakes, `cookie` DDoS challenges, roaming, `UDP 443` |

`esp` and `ipsec` are interchangeable aliases for RFC 4303 IP Protocol `50`, which is how 19 protocols on the wire become 20 keywords.

---

## 1. PMTUD, Neighbor Discovery & Multicast (`icmp`, `ndp`, `igmp`, `mld`)

Silent MTU blackholes are classic Friday-afternoon outages: a `gre` tunnel carries 1400 bytes, the ICMP "Fragmentation Needed" message is filtered somewhere on the path, and TCP stalls with no error anywhere. Script the `df` probe and the `destunreach code 4` reply, and test whether your filters and monitoring notice.

```frameassembly
host app_srv    { ip 10.88.1.10 mac 00:50:56:88:01:0a }
host wan_pri_gw { ip 10.88.1.2  mac 00:00:5e:00:01:58 }

flow pmtud_blackhole(srv, gw) {
    // Oversized DF ping hits the 1400-byte GRE limit; the router answers ICMP Type 3 Code 4
    srv -> gw df ttl 64 icmp echorequest id 4410 seq 1 payload "oversized_1472_byte_wan_probe" wait 2ms
    srv <- gw ttl 64 icmp destunreach code 4 payload "mtu_1400_exceeded_on_gre0"
}

compile { pmtud_blackhole(app_srv, wan_pri_gw) }
```

IPv6 neighbor discovery and multicast listener traffic (RA-Guard, SLAAC, and MLD snooping all want an opinion about this):

```frameassembly
host v6_host   { ip 2001:db8:1::10 mac 00:50:56:60:00:10 }
host v6_router { ip fe80::1        mac 00:50:56:60:00:01 }

flow v6_discovery(h, r) {
    h -> r ttl 255 ndp routersolicit slla 00:50:56:60:00:10 wait 1ms
    h <- r ttl 255 ndp routeradvert routerlifetime 1800 slla 00:50:56:60:00:01 wait 2ms
    h -> r ttl 255 ndp neighborsolicit target 2001:db8:1::10 slla 00:50:56:60:00:10 wait 1ms
    h -> r ttl 1 mld report multicastaddr ff02::1:ff00:10 wait 1ms
    h -> r ttl 1 mld done multicastaddr ff02::1:ff00:10
}

compile { v6_discovery(v6_host, v6_router) }
```

IPTV and market-data joins. An IGMPv3 SSM join lets the leaf build a PIM `(S,G)` tree without an RP:

```frameassembly
host trade_srv { ip 10.200.40.15 mac 00:0f:53:d2:28:0f }
host leaf_ofs  { ip 10.200.40.1  mac 00:1c:73:67:c8:01 }
host upstream  { ip 10.254.0.10  mac 00:1c:73:fe:00:0a }

flow ssm_join(srv, sw, up) {
    srv -> sw vlan 200 pcp 6 dscp 48 ttl 1 igmp report group 232.200.1.50 version 3 payload "ALLOW_192.0.2.200" wait 1ms
    sw -> up vlan 200 pcp 6 dscp 48 ttl 1 pim joinprune group 232.200.1.50 source 192.0.2.200 holdtime 60
}

compile { ssm_join(trade_srv, leaf_ofs, upstream) }
```

### Modifier & Wire Cheat-Sheet: `icmp`, `ndp`, `igmp`, `mld`

| Protocol | Sub-Keywords / Types | Key Modifiers | Unit & Wire Notes |
| :--- | :--- | :--- | :--- |
| **`icmp`** | `echorequest`, `echoreply`, `destunreach`, `timeexceeded`, `redirect` | `code <u8>`, `id <u16>`, `seq <u16>`, `gateway <ipv4>` | `code 4` PMTUD Frag Needed, `code 13` Admin Prohibited; switches to ICMPv6 over IPv6 hosts |
| **`ndp`** | `routersolicit`, `routeradvert`, `neighborsolicit`, `neighboradvert` | `target <ipv6>`, `slla <mac>`, `tlla <mac>`, `routerlifetime <u16>` | Pair with `ttl 255` (RFC 4861 GTSM); `routerlifetime 0` withdraws the default router |
| **`igmp`** | `query`, `report`, `leave` | `version <1..3>`, `group <ipv4>`, `maxresp <u8>` | `maxresp` in deciseconds (`100` = 10.0s); `group 0.0.0.0` = General Query |
| **`mld`** | `query`, `report`, `done` | `multicastaddr <ipv6>`, `maxrespdelay <u16>` | `maxrespdelay` in milliseconds (`10000` = 10s); `multicastaddr ::` = General Query |

---

## 2. Routing, First-Hop Redundancy, BFD & SDN (`bgp`, `ospf`, `rip`, `pim`, `vrrp`, `hsrp`, `bfd`, `openflow`)

The expensive part of routing tests is waiting: Hello intervals, Dead timers, hold timers. `wait` and explicit timer fields compress all of it into one capture.

Whole-OSPF adjacency on a point-to-point link, all five packet types:

```frameassembly
host edge_rtr { ip 198.51.100.2 mac 00:1c:73:64:00:02 }
host isp_pe   { ip 198.51.100.1 mac 00:1c:73:64:00:01 }

flow ospf_p2p_sync(ce, pe) {
    ce -> pe dscp 48 ttl 1 ospf hello routerid 10.0.0.2 areaid 0 hellointerval 1 deadinterval 4 priority 0 wait 2ms
    ce <- pe dscp 48 ttl 1 ospf dbd   routerid 10.0.0.1 areaid 0 wait 2ms
    ce -> pe dscp 48 ttl 1 ospf lsr   routerid 10.0.0.2 areaid 0 wait 2ms
    ce <- pe dscp 48 ttl 1 ospf lsu   routerid 10.0.0.1 areaid 0 payload "router_lsa_seq_0x80000001" wait 2ms
    ce -> pe dscp 48 ttl 1 ospf lsack routerid 10.0.0.2 areaid 0 wait 5ms
}

compile { ospf_p2p_sync(edge_rtr, isp_pe) }
```

eBGP with 4-byte ASNs, an RFC 7999 RTBH blackhole update, and a Cease NOTIFICATION after BFD declares the link dead (`state 1`, `diag 1`):

```frameassembly
host edge_rtr { ip 198.51.100.2 mac 00:1c:73:64:00:02 }
host isp_pe   { ip 198.51.100.1 mac 00:1c:73:64:00:01 }

flow ebgp_rtbh_and_bfd(ce, pe) {
    ce -> pe dscp 48 ttl 1 bgp open asn 4200000010 holdtime 90 bgpid 10.0.0.2 wait 2ms
    ce <- pe dscp 48 ttl 1 bgp open asn 65001      holdtime 90 bgpid 10.0.0.1 wait 2ms
    ce -> pe dscp 48 ttl 1 bgp update asn 4200000010 prefix "203.0.113.200/32" nexthop 192.0.2.1 payload "COMMUNITY_65535_666_BLACKHOLE" wait 5ms

    // BFD Control Detection Time Expired, then BGP tears the session down
    ce -> pe dscp 48 ttl 255 bfd state 1 diag 1 mydisc 17901 yourdisc 0 mintx 1000000 minrx 1000000 mult 3 wait 2ms
    ce <- pe dscp 48 ttl 1 bgp notification payload "CEASE_BFD_SESSION_DOWN"
}

compile { ebgp_rtbh_and_bfd(edge_rtr, isp_pe) }
```

Gateway redundancy. VRRPv3 priority decrement from object tracking, backup preemption, and a RIP poison-reverse withdrawal:

```frameassembly
host wan_pri_gw { ip 10.88.1.2 mac 00:00:5e:00:01:58 }
host wan_sec_gw { ip 10.88.1.3 mac 00:1c:73:88:01:03 }

flow gateway_failover(pri, sec) {
    // Primary drops from 130 to 80 after its tracked uplink fails; backup (100) takes over
    pri -> sec dscp 48 ttl 255 vrrp vrid 88 priority 80  advint 20 vip 10.88.1.1 version 3 wait 5ms
    pri <- sec dscp 48 ttl 255 vrrp vrid 88 priority 100 advint 20 vip 10.88.1.1 version 3 wait 5ms

    // HSRP equivalent: Active state (16) with hellotime 3 and holdtime 10
    pri -> sec ttl 1 hsrp group 10 priority 110 state 16 vip 10.88.1.1 hellotime 3 holdtime 10 wait 5ms

    // RIP poison reverse: metric 16 means unreachable
    pri -> sec ttl 1 rip response prefix 10.10.0.0 metric 16 tag 100
}

compile { gateway_failover(wan_pri_gw, wan_sec_gw) }
```

An OpenFlow 1.3 (`version 4`) `packetin` anomaly answered by a priority-65000 `flowmod` drop rule:

```frameassembly
host leaf_ofs { ip 10.200.40.1 mac 00:1c:73:67:c8:01 }
host sdn_ctrl { ip 10.254.0.10 mac 00:1c:73:fe:00:0a }

flow sdn_scrub(sw, ctrl) {
    sw -> ctrl dscp 48 openflow packetin version 4 xid 801 tableid 0 payload "syn_flood_sample" wait 5ms
    sw <- ctrl dscp 48 openflow flowmod  version 4 xid 802 tableid 0 priority 65000 payload "drop_malicious_oxm"
}

compile { sdn_scrub(leaf_ofs, sdn_ctrl) }
```

### Modifier & Wire Cheat-Sheet: Routing, FHRP, BFD, SDN

| Protocol | Operations / Types | Modifiers | Common Values & Defaults |
| :--- | :--- | :--- | :--- |
| **`ospf`** | `hello`, `dbd`, `lsr`, `lsu`, `lsack` | `routerid <ipv4>`, `areaid <u32>`, `hellointerval <u16>`, `deadinterval <u32>`, `priority <u8>` | `priority 0` = never DR; multicast `224.0.0.5` (`ff02::5` for OSPFv3) |
| **`bgp`** | `open`, `update`, `notification`, `keepalive` | `asn <u32>`, `holdtime <u16>`, `bgpid <ipv4>`, `prefix "<cidr>"`, `nexthop <ip>` | 2B and 4B ASNs (`4200000001`); `TCP 179`; GTSM `ttl 255` or eBGP `ttl 1` |
| **`rip`** | `request`, `response` | `prefix <ip>`, `metric <1..16>`, `nexthop <ipv4>`, `tag <u16>` | `metric 16` = infinity; IPv4 `UDP 520` (`224.0.0.9`), IPv6 `UDP 521` (`ff02::9`) |
| **`pim`** | `hello`, `joinprune`, `register` | `drpriority <u32>`, `holdtime <u16>`, `group <ip>`, `source <ip>`, `rp <ip>` | `holdtime 0` = Goodbye; `source` without `rp` = SSM `(S,G)`; `224.0.0.13` / `ff02::d` |
| **`vrrp`** | Advertisement | `vrid <1..255>`, `priority <0..255>`, `vip <ip>`, `version <2\|3>`, `advint <u16>` | `advint` in centiseconds on v3 (`20` = 200ms); `priority 255` owner, `0` release |
| **`hsrp`** | Hello / Coup / Resign | `group <u16>`, `priority <0..255>`, `state <u8>`, `vip <ip>`, `hellotime <0..255>`, `holdtime <u8>` | `state`: `0` Init, `1` Learn, `2` Listen, `4` Speak, `8` Standby, `16` Active |
| **`bfd`** | Control / Echo / S-BFD | `state <0..3>`, `diag <0..9>`, `mydisc <u32>`, `yourdisc <u32>`, `mintx <u32>`, `minrx <u32>`, `mult <u8>` | `mintx` / `minrx` in microseconds (`3300` = 3.3ms, `50000` = 50ms); `state 3` = Up |
| **`openflow`** | `hello`, `featuresreq`, `featuresreply`, `echoreq`, `echoreply`, `packetin`, `packetout`, `flowmod` | `version <1..6>`, `xid <u32>`, `dpid <u64>`, `tableid <u8>`, `priority <u16>` | `version 4` = OpenFlow 1.3 (`1` = 1.0, `5` = 1.4); `TCP 6653` (`dstport 6633` for legacy) |

The units differ per protocol, and that is where the bugs hide: `bfd` timers are microseconds, `mld` `maxrespdelay` is milliseconds, `vrrp` v3 `advint` is centiseconds, `igmp` `maxresp` is deciseconds, and `ospf`, `bgp`, `hsrp`, `pim` timers are seconds. Also note `bgp` `prefix` is quoted (`"10.10.0.0/16"`, because of the slash) while `rip` `prefix` is a bare IP (`10.10.0.0`). Every other IP and MAC modifier (`nexthop`, `bgpid`, `routerid`, `vip`, `target`, `slla`, `tlla`) is unquoted.

| `state` | Meaning | `diag` | Diagnostic Reason |
| :---: | :--- | :---: | :--- |
| `0` | AdminDown | `0` / `1` | No Diagnostic / Control Detection Time Expired |
| `1` | Down | `2` / `3` | Echo Function Failed / Neighbor Signaled Session Down |
| `2` | Init | `4` / `5` | Forwarding Plane Reset / Path Down |
| `3` | Up | `6`..`9` | `6` Concat Path Down, `7` Admin Down, `8` Reverse Concat Path Down, `9` Misconnectivity |

---

## 3. Fabric Overlays & Tunnels (`vxlan`, `geneve`, `gre`)

Overlay bugs hide in two places: the outer UDP source port that feeds ECMP hashing, and the inner option TLVs nobody decodes. Send those directly instead of deploying a CNI plugin to find out.

Cloud-native `geneve`: a Cilium pod-to-pod frame and an AWS Gateway Load Balancer hairpin:

```frameassembly
host compute_nve { ip 10.244.0.11 mac 00:16:3e:60:81:0b }
host inspect_nve { ip 10.244.0.50 mac 02:a1:b2:60:81:32 }

flow cloud_overlay_inspection(nve, fw) {
    // Cilium eBPF frame (optclass 267, Transparent Ethernet Bridging 0x6558)
    nve -> fw df dscp 18 ttl 64 geneve vni 2 optclass 267 opttype 1 protocoltype 0x6558 srcport 51234 dstport 6081 payload "CILIUM_ID_42105_HTTP_GET" wait 2ms

    // AWS GWLB appliance hairpin (optclass 264, routed IPv4 0x0800)
    nve -> fw df ttl 64 geneve vni 1 optclass 264 opttype 1 protocoltype 0x0800 srcport 49800 dstport 6081 payload "AWS_GWLBE_FLOW_COOKIE_IN" wait 1ms
    nve <- fw df ttl 64 geneve vni 1 optclass 264 opttype 1 protocoltype 0x0800 srcport 49800 dstport 6081 payload "AWS_GWLBE_FLOW_COOKIE_OK"
}

compile { cloud_overlay_inspection(compute_nve, inspect_nve) }
```

EVPN-VXLAN L3VNI 50001 symmetric IRB, with varied source ports for ECMP entropy, and a `gre` ERSPAN III mirror stream to a sensor:

```frameassembly
host leaf_01    { ip 10.0.1.1   mac 00:1c:73:c1:00:01 }
host spine_01   { ip 10.0.1.0   mac 00:1c:73:c0:00:01 }
host ndr_sensor { ip 172.20.99.9 mac 00:25:b5:47:89:09 }

flow fabric_overlays(leaf, spine, ndr) {
    leaf -> spine df dscp 26 ttl 63 vxlan vni 50001 srcport 58001 dstport 4789 payload "EVPN_TYPE5_SUBNET_A_TO_B" wait 1ms
    leaf -> spine df dscp 26 ttl 63 vxlan vni 50001 srcport 58002 dstport 4789 payload "EVPN_TYPE5_SUBNET_A_TO_B" wait 1ms

    // Cisco ERSPAN Type III (protocol 0x22eb) mirror to the NDR probe
    spine -> ndr df dscp 16 ttl 64 gre grekey 301 greseq 5001 greproto 0x22eb payload "ERSPAN_III_SPAN_FRAME"
}

compile { fabric_overlays(leaf_01, spine_01, ndr_sensor) }
```

### Modifier & Wire Cheat-Sheet: `gre`, `vxlan`, `geneve`

| Protocol | Modifiers & Aliases | Common Passenger Protocol / Option Values |
| :--- | :--- | :--- |
| **`gre`** | `greproto <u16>`, `grekey <u32>`, `greseq <u32>`, `checksum` | `0x0800` (`2048`) IPv4, `0x86dd` (`34525`) IPv6, `0x6558` (`25944`) L2 GRETAP/NVGRE, `0x8847` (`34887`) MPLS-in-GRE, `0x88be` (`35006`) ERSPAN II, `0x22eb` (`8939`) ERSPAN III |
| **`vxlan`** | `vni <0..16777215>` (alias `vnid`), `srcport <p>`, `dstport <p>` | Default `UDP 4789` (`dstport 8472` for legacy Linux/Flannel); `vni 1` for RFC 8971 BFD-over-VXLAN |
| **`geneve`** | `vni <0..16777215>` (alias `vnid`), `optclass <u16>`, `opttype <u8>`, `protocoltype <u16>` | `optclass`: `258` (`0x0102`) OVN, `259` (`0x0103`) P4 INT, `260` (`0x0104`) NSX-T, `264` (`0x0108`) AWS GWLB, `267` Cilium; `opttype >= 128` sets the Critical bit; `protocoltype`: `0x6558` L2 TEB, `0x0800` IPv4, `0x86dd` IPv6, `0x8847` MPLS, `0x894f` NSH |

---

## 4. VPN Edge Cases (`ikev2`, `esp` / `ipsec`, `ah`, `wireguard`)

VPN gateways fail in situations that only happen behind NAT, under packet reordering, or when a DDoS filter decides to issue a cookie. Reproducing those with real `strongSwan` configs and real keys is a project. Reproducing them with `.frasm` code is a capture file, and none of it needs a crypto daemon.

An IKEv2 session that starts on `UDP 500` and floats to `UDP 4500` for NAT-T:

```frameassembly
host roaming_cli { ip 198.51.100.88 mac 00:1b:21:51:82:58 }
host vpn_headend { ip 203.0.113.1   mac 00:1b:21:51:82:01 }

flow ikev2_nat_float(cli, gw) {
    cli -> gw dscp 48 ikev2 sainit initiatorspi 111222333 responderspi 0 msgid 0 flags 8 nextpayload 33 srcport 500 dstport 500 wait 5ms
    cli <- gw dscp 48 ikev2 sainit initiatorspi 111222333 responderspi 444555666 msgid 0 flags 32 nextpayload 33 srcport 500 dstport 500 wait 5ms
    cli -> gw dscp 48 ikev2 informational initiatorspi 111222333 responderspi 444555666 msgid 1 flags 8 nextpayload 46 srcport 4500 dstport 4500
}

compile { ikev2_nat_float(roaming_cli, vpn_headend) }
```

ESP out-of-order delivery against a 64-packet anti-replay window (sequence 100, 103, then 101), and an `ah` header protecting an OSPF packet:

```frameassembly
host roaming_cli { ip 198.51.100.88 mac 00:1b:21:51:82:58 }
host vpn_headend { ip 203.0.113.1   mac 00:1b:21:51:82:01 }

flow esp_replay_and_ah(cli, gw) {
    cli -> gw df dscp 34 esp spi 410601 seq 100 iv "0000000100000064" icv "102030405060708090a0b0c0d0e0f001" nextheader 4 payload "ESP_SEQ_100" wait 2ms
    cli -> gw df dscp 34 esp spi 410601 seq 103 iv "0000000100000067" icv "102030405060708090a0b0c0d0e0f002" nextheader 4 payload "ESP_SEQ_103_ADVANCE" wait 2ms
    cli -> gw df dscp 34 esp spi 410601 seq 101 iv "0000000100000065" icv "102030405060708090a0b0c0d0e0f003" nextheader 4 payload "ESP_SEQ_101_REORDERED" wait 5ms

    // AH authenticates the outer IP header and an upper-layer control protocol (89 = OSPF)
    cli -> gw ah spi 777001 seq 1 icv "00112233445566778899aabb" nextheader 89 payload "ospf_hello_under_ah"
}

compile { esp_replay_and_ah(roaming_cli, vpn_headend) }
```

WireGuard on `UDP 443` with a DDoS cookie challenge, retry, and encrypted data:

```frameassembly
host roaming_cli { ip 198.51.100.88 mac 00:1b:21:51:82:58 }
host vpn_headend { ip 203.0.113.1   mac 00:1b:21:51:82:01 }

flow wireguard_cookie_retry(cli, gw) {
    cli -> gw df wireguard initiation sender 44301 srcport 54321 dstport 443 wait 3ms
    cli <- gw df wireguard cookie receiver 44301 srcport 443 dstport 54321 wait 3ms
    cli -> gw df wireguard initiation sender 44302 srcport 54321 dstport 443 wait 3ms
    cli <- gw df wireguard response sender 44303 receiver 44302 srcport 443 dstport 54321 wait 3ms
    cli -> gw df wireguard data receiver 44303 counter 0 srcport 54321 dstport 443 payload "CHACHA20_FIRST_PKT"
}

compile { wireguard_cookie_retry(roaming_cli, vpn_headend) }
```

### Modifier & Wire Cheat-Sheet: `ikev2`, `esp` / `ipsec`, `ah`, `wireguard`

| Protocol | Sub-Keywords / Exchanges | Modifiers | Wire & Security Notes |
| :--- | :--- | :--- | :--- |
| **`ikev2`** | `sainit`, `auth`, `createchildsa`, `informational` (also `exchange <name>`) | `initiatorspi <u64>`, `responderspi <u64>`, `msgid <u32>`, `flags <u8>`, `nextpayload <u8>` | `flags`: `8` Initiator, `32` Response; `nextpayload`: `33` SA, `41` Notify/Cookie, `42` Delete, `46` SK, `53` SKF fragment; `dstport 4500` for NAT-T |
| **`esp`** / **`ipsec`** | Encrypted SA frame | `spi <u32>`, `seq <u32>`, `iv "<hex>"`, `icv "<hex>"`, `nextheader <u8>` | `nextheader`: `4` IPv4 tunnel, `41` IPv6 tunnel, `6` TCP, `17` UDP, `47` GRE/DMVPN, `89` OSPF, `132` SCTP, `59` TFC dummy padding |
| **`ah`** | Authenticated header | `spi <u32>`, `seq <u32>`, `icv "<hex>"`, `nextheader <u8>` | Authenticates the outer IP header and upper-layer control traffic (`6` BGP, `89` OSPF, `103` PIM, `112` VRRP, `58` NDP) |
| **`wireguard`** | `initiation`, `response`, `cookie`, `data` | `sender <u32>`, `receiver <u32>`, `counter <u64>` | Default `UDP 51820` (override `dstport 443` or `41641`); omit `payload` on `data` for a 0-byte PersistentKeepalive |

---

## Inspect and Replay

```console
# BGP ASNs and prefixes, BFD timers, VXLAN VNIs
$ tshark -r clos_check.pcap -T fields -e frame.number -e ip.src -e ip.dst -e bfd.sta -e bgp.type -e vxlan.vni

# Run Suricata rules against custom IKEv2, WireGuard, or BGP captures
$ suricata -r vpn_edge_cases.pcap -k none

# Replay onto a lab interface
$ sudo tcpreplay -i eth0 clos_check.pcap
```
