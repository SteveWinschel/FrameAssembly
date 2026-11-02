# Layer 3 Control, Tunneling, VPN, Routing & FHRP Reference

Reproducing a BGP route update, an OSPF adjacency drop, a VRRP/HSRP/BFD gateway failover, or an EVPN-VXLAN, GENEVE, IPsec, or WireGuard tunnel packet usually means spinning up a multi-router lab and writing pages of routing daemon configuration just to capture four packets.

FrameAssembly lets you write those exact Layer 3 control-plane, multicast (`IGMP`/`MLD`/`NDP`), and tunnel packets in `.fasm` code, compile them to `.pcap` with `frameassembly`, and replay or inspect them in seconds with `tcpreplay`, **Wireshark**, or **Suricata**. All **20 Layer 3 protocols** work identically across IPv4 (`EtherType 0x0800`) and IPv6 (`EtherType 0x86DD`), alongside universal IPv4/IPv6 header modifiers (`TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `IPID`, `DF`, `MF`, `FRAGOFFSET`, `NEXT_HEADER`) that can be attached to any statement.

| Category | Protocol | Keyword | Standard | IP Proto / Port | Default Target / Multicast IP | Primary Operational Use Cases |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Diagnostics** | **ICMPv4 / v6** | `ICMP` | RFC 792 / 4443 | IP Proto `1` (v4) / `58` (v6) | Unicast | Ping (`ECHO_REQUEST`/`ECHO_REPLY`), PMTUD (`DEST_UNREACH`), Traceroute (`TIME_EXCEEDED`), `REDIRECT` |
| **IPv6 Neighbor** | **NDP** | `NDP` | RFC 4861 | IPv6 Next Header `58` | `ff02::2` (RS) / `ff02::1:ffxx:xxxx` (NS) | IPv6 SLAAC (`ROUTER_SOLICIT`/`ROUTER_ADVERT`), DAD, and MAC resolution (`NEIGHBOR_SOLICIT`/`ADVERT`) |
| **Multicast Mgmt**| **IGMPv1/v2/v3** | `IGMP` | RFC 1112 / 2236 / 3376 | IP Proto `2` | `224.0.0.1` / `224.0.0.2` / `224.0.0.22` | IPv4 multicast querier polling (`QUERY`), group joins (`REPORT`), fast-leave (`LEAVE`), IGMP Snooping |
| **Multicast Mgmt**| **MLDv1/v2** | `MLD` | RFC 2710 / 3810 | IPv6 Next Header `58` | `ff02::1` / `ff02::2` | IPv6 multicast listener `QUERY`, `REPORT`, and `DONE` for MLD Snooping switches |
| **Overlays** | **GRE** | `GRE` | RFC 2784 / 2890 | IP Proto `47` | Unicast | Point-to-point IP/Ethernet tunnels with optional `GRE_KEY`, `GRE_SEQ`, `GRE_PROTO`, and `CHECKSUM` |
| **Overlays** | **VXLAN** | `VXLAN` | RFC 7348 | UDP `4789` | Unicast / Multicast VTEP | EVPN-VXLAN data center Layer 2/3 overlays with 24-bit `VNI` (`VNID`) |
| **Overlays** | **GENEVE** | `GENEVE` | RFC 8926 | UDP `6081` | Unicast VTEP | Cloud-native overlays (OVN, Cilium, NSX, AWS GWLB) with extensible `OPT_CLASS` / `OPT_TYPE` TLVs |
| **VPN & Crypto** | **IKEv2** | `IKEV2` | RFC 7296 | UDP `500` / `4500` | Unicast | IPsec key negotiation (`SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL`, 64-bit SPIs, `MSGID`) |
| **VPN & Crypto** | **IPsec ESP** | `IPSEC` / `ESP` | RFC 4303 | IP Proto `50` | Unicast | Encrypted IPsec payload (`SPI`, `SEQ`, `IV`, `ICV`, `NEXT_HEADER`) |
| **VPN & Crypto** | **IPsec AH** | `AH` | RFC 4302 | IP Proto `51` | Unicast | Authenticated IP header integrity (`SPI`, `SEQ`, `ICV`, `NEXT_HEADER`) |
| **VPN & Crypto** | **WireGuard** | `WIREGUARD` | Noise_IKpsk2 | UDP `51820` | Unicast | Modern VPN handshake (`INITIATION`, `RESPONSE`, `COOKIE`) and AEAD transport (`DATA`) |
| **Routing** | **OSPFv2 / v3** | `OSPF` | RFC 2328 / 5340 | IP Proto `89` | `224.0.0.5` (v4) / `ff02::5` (v6) | Link-state routing (`HELLO`, `DBD`, `LSR`, `LSU`, `LSACK`, `ROUTER_ID`, `AREA_ID`) |
| **Routing** | **BGP-4** | `BGP` | RFC 4271 | TCP `179` | Unicast Peer | eBGP/iBGP peering (`OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ASN`, `PREFIX`, `NEXTHOP`) |
| **Routing** | **RIPv2 / RIPng**| `RIP` | RFC 2453 / 2080 | UDP `520` (v4) / `521` (v6) | `224.0.0.9` (v4) / `ff02::9` (v6) | Distance-vector route advertisements (`REQUEST`, `RESPONSE`, `PREFIX`, `NEXTHOP`, `METRIC`, `TAG`) |
| **Routing** | **PIM-SM** | `PIM` | RFC 7761 | IP Proto `103` | `224.0.0.13` (v4) / `ff02::d` (v6) | Multicast routing trees (`HELLO`, `JOIN_PRUNE`, `REGISTER`, `GROUP`, `SOURCE`, `RP`) |
| **FHRP & SDN** | **VRRPv2 / v3** | `VRRP` | RFC 3768 / 5798 | IP Proto `112` | `224.0.0.18` (v4) / `ff02::12` (v6) | Vendor-neutral default gateway redundancy (`VRID`, `PRIORITY`, `ADV_INT`, `VIP`) |
| **FHRP & SDN** | **HSRP** | `HSRP` | RFC 2281 | UDP `1985` (v4) / `2029` (v6)| `224.0.0.2` (v4) / `ff02::66` (v6) | Cisco gateway redundancy (`GROUP`, `PRIORITY`, `STATE`, `HELLOTIME`, `HOLDTIME`, `AUTH`, `VIP`) |
| **FHRP & SDN** | **BFD** | `BFD` | RFC 5880 / 5881 | UDP `3784` | Unicast | Sub-second forwarding plane failure detection (`STATE`, `DIAG`, `MY_DISC`, `YOUR_DISC`, `MIN_TX`/`RX`) |
| **FHRP & SDN** | **OpenFlow** | `OPENFLOW` | ONF v1.0–v1.5 | TCP `6653` | Unicast | SDN controller-switch channel (`HELLO`, `FEATURES_REQ`/`REPLY`, `PACKET_IN`/`OUT`, `FLOW_MOD`) |

---

## 1. Universal IPv4 & IPv6 Header Modifiers

Any packet statement that carries an IPv4 or IPv6 header accepts the following universal Layer 3 modifiers. FrameAssembly keeps the keyword surface unified across IPv4 and IPv6 (`TTL` sets IPv4 Time-To-Live on IPv4 pairs and IPv6 Hop Limit on IPv6 pairs; `DSCP` and `ECN` set the IPv4 `TOS` byte or IPv6 `Traffic Class` byte) so that a single `FLOW` works unmodified across both address families.

| Modifier | Syntax | Valid Range | Effect on IPv4 (`0x0800`) | Effect on IPv6 (`0x86DD`) | Default |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TTL / Hop Limit** | `TTL <0..255>` | `0..255` | Sets 8-bit IPv4 Time-To-Live | Sets 8-bit IPv6 Hop Limit | `64` (`255` on `NDP`, `VRRP`, IPv6 `ARP`) |
| **DiffServ QoS** | `DSCP <0..63>` | `0..63` | Sets upper 6 bits of IPv4 `TOS` (`dscp << 2`) | Sets upper 6 bits of IPv6 `Traffic Class` | `0` (`BE`) |
| **ECN Bits** | `ECN <0..3>` | `0..3` | Sets lower 2 bits of IPv4 `TOS` | Sets lower 2 bits of IPv6 `Traffic Class` | `0` (`Non-ECT`) |
| **IPv6 Flow Label** | `FLOWLABEL <0..1048575>` | `0..1048575` (`0xFFFFF`) | Silently ignored (preserves dual-stack flow portability) | Sets 20-bit IPv6 Flow Label for ECMP hashing | `0` |
| **IPv4 Packet ID** | `IPID <0..65535>` | `0..65535` | Sets 16-bit IPv4 Identification field | Ignored on IPv6 | `0` |
| **Don't Fragment** | `DF` | Bare flag | Sets IPv4 Don't Fragment bit (`0x4000`) | Ignored on IPv6 (IPv6 routers never fragment) | Cleared (`0`) |
| **More Fragments** | `MF` | Bare flag | Sets IPv4 More Fragments bit (`0x2000`) | Ignored on IPv6 | Cleared (`0`) |
| **Fragment Offset** | `FRAGOFFSET <0..8191>`| `0..8191` | Sets 13-bit IPv4 offset in 8-byte blocks (`185` = 1480 B) | Ignored on IPv6 | `0` |
| **Inner Next Header**| `NEXT_HEADER <0..255>`| `0..255` | Sets encapsulated inner protocol in `IPSEC`/`ESP`/`AH` | Sets encapsulated inner protocol in `IPSEC`/`ESP`/`AH` | `59` (No Next Hdr) |

### Common DiffServ (`DSCP`) & `ECN` Quick Reference

| PHB Name | `DSCP` Decimal | Hex `TOS` (`ECN 0`) | Typical Traffic Class & Protocol Pairing |
| :--- | :--- | :--- | :--- |
| **Best Effort (`BE` / `CS0`)** | `0` | `0x00` | Standard web traffic (`HTTP`, `HTTPS`, `QUIC`) |
| **Scavenger (`CS1`)** | `8` | `0x20` | Bulk backups, software updates, non-critical replication |
| **High-Throughput (`AF11` / `AF12`)** | `10` / `12` | `0x28` / `0x30` | Enterprise file transfers (`SMB`, `NFS`, `FTP`) |
| **Network Mgmt (`CS2`)** | `16` | `0x40` | Telemetry & AAA (`SNMP1`/`2`/`3`, `NETFLOW`, `IPFIX`, `SFLOW`, `SYSLOG`, `RADIUS`, `TACACS`) |
| **Transactional (`AF21`)** | `18` | `0x48` | Low-latency databases & caches (`POSTGRES`, `MYSQL`, `REDIS`, `LDAP`, `GRPC`) |
| **Call Signaling (`CS3`)** | `24` | `0x60` | VoIP & media control (`SIP`, `RTSP`, `STUN`) |
| **Multimedia / RDMA (`AF31`)** | `26` | `0x68` | Streaming media and lossless data center RoCEv2 RDMA |
| **Interactive Video (`AF41`)** | `34` | `0x88` | Video conferencing and live broadcast feeds |
| **Expedited Forwarding (`EF`)** | `46` | `0xb8` | Real-time VoIP audio (`RTP`) and precision timing (`PTP`, `NTP`) |
| **Internetwork Control (`CS6`)** | `48` | `0xc0` | Routing & FHRP control plane (`OSPF`, `BGP`, `RIP`, `PIM`, `VRRP`, `HSRP`, `BFD`) |
| **Network Control (`CS7`)** | `56` | `0xe0` | Critical fabric control & SDN (`OPENFLOW`) |

> **`ECN` Values (`0..3`):** `0` = Not-ECT (`00`), `1` = ECT(1) (`01`, L4S / Prague), `2` = ECT(0) (`10`, standard ECN-capable transport), `3` = CE (`11`, Congestion Experienced—set by a congested router switch ASIC instead of dropping the packet).

### Example: IPv4 Fragmentation Reassembly & Dual-Stack QoS Markings

```frameassembly
host sender_v4   { ip 10.10.1.10 }
host receiver_v4 { ip 10.10.1.20 }
host sender_v6   { ip 2001:db8:10::10 }
host receiver_v6 { ip 2001:db8:10::20 }

flow ip_fragmentation_and_qos(s4, r4, s6, r6) {
    // 1. Path MTU probe with DF (Don't Fragment) set
    s4 -> r4 df ipid 0x4411 dscp 18 ecn 2 udp srcport 50000 dstport 9000 payload "PMTUD_DF_PROBE_PACKET" wait 1ms

    // 2. Two-fragment IPv4 UDP datagram sharing IPID 0x7788:
    //    Fragment 1: MF set, offset 0 (bytes 0..1479)
    //    Fragment 2: MF cleared, fragoffset 185 (185 * 8 = byte offset 1480)
    s4 -> r4 ipid 0x7788 mf fragoffset 0 udp srcport 50000 dstport 9000 payload "FIRST_FRAGMENT_BODY" wait 500us
    s4 -> r4 ipid 0x7788 fragoffset 185 udp srcport 50000 dstport 9000 payload "FINAL_FRAGMENT_TAIL" wait 2ms

    // 3. IPv6 flow with 20-bit Flow Label, DSCP 46 (EF), ECN 3 (Congestion Experienced), and Hop Limit 255
    s6 -> r6 flowlabel 0xabcde dscp 46 ecn 3 ttl 255 udp srcport 50000 dstport 9000 payload "IPV6_ECMP_EF_FLOW"
}

compile {
    ip_fragmentation_and_qos(sender_v4, receiver_v4, sender_v6, receiver_v6)
}
```

---

## 2. Diagnostics & IPv6 Neighbor Discovery (`ICMP` & `NDP`)

Half of real-world network troubleshooting comes down to ICMP and IPv6 Neighbor Discovery—figuring out whether a firewall silently swallowed a Path MTU Discovery (`PMTUD`) `Fragmentation Needed` / `Packet Too Big` error, how a traceroute hop expires, or why an IPv6 host ignored a SLAAC Router Advertisement. With `ICMP` and `NDP`, you can script every diagnostic control message and neighbor solicitation across IPv4 and IPv6 in a few lines of code.

### 2.1 Internet Control Message Protocol (`ICMP` — RFC 792 / RFC 4443)
`ICMP` is completely dual-stack:
* When used with **IPv4 hosts**, FrameAssembly emits **RFC 792 ICMPv4** (`IP Protocol 1`) with an RFC 1071 header+payload checksum.
* When used with **IPv6 hosts**, FrameAssembly automatically emits **RFC 4443 ICMPv6** (`IPv6 Next Header 58`) and calculates the mandatory 40-byte IPv6 pseudo-header checksum.

| Modifier | Syntax | IPv4 Wire Value | IPv6 Wire Value | Description & Default |
| :--- | :--- | :--- | :--- | :--- |
| **Echo Request** | `ECHO_REQUEST` | `Type 8, Code 0` | `Type 128, Code 0` | Default message type when omitted (`ping`) |
| **Echo Reply** | `ECHO_REPLY` | `Type 0, Code 0` | `Type 129, Code 0` | Ping response carrying matching `ID` and `SEQ` |
| **Dest Unreachable**| `DEST_UNREACH` | `Type 3` | `Type 1` | Firewall reject / routing failure / PMTUD (`CODE 4` v4, `CODE 2` Packet Too Big raw `TYPE 2` v6) |
| **Time Exceeded** | `TIME_EXCEEDED`| `Type 11` | `Type 3` | Traceroute hop expiration (`CODE 0` TTL expired in transit, `CODE 1` fragment reassembly timeout) |
| **Redirect** | `REDIRECT` | `Type 5` | `Type 137` | Informs host of a better first-hop router (`GATEWAY <ipv4>`) |
| **Raw Type / Code** | `TYPE <0..255>`, `CODE <0..255>` | `0..255` | `0..255` | Overrides numeric ICMP Type or Code (e.g. `dest_unreach code 3` Port Unreachable, `code 13` Admin Prohibited) |
| **Echo ID & Seq** | `ID <0..65535>`, `SEQ <0..65535>` | `0..65535` | `0..65535` | 16-bit Echo Identifier (default `0x1234`) and Sequence Number (default `1`) |
| **Redirect Gateway**| `GATEWAY <ipv4>`| 4-byte IPv4 | — | Next-hop router IPv4 address embedded in ICMPv4 `REDIRECT` (`Type 5`) messages |

### 2.2 IPv6 Neighbor Discovery Protocol (`NDP` — RFC 4861)
`NDP` replaces IPv4 ARP, ICMPv4 Router Discovery, and ICMPv4 Redirects over IPv6 (`Next Header 58`). FrameAssembly automatically sets `TTL 255` (Hop Limit `255`) on every `NDP` packet unless explicitly overridden, because RFC 4861 requires receivers to silently drop any NDP packet whose IPv6 Hop Limit is less than `255` (protecting against off-link spoofing).

| Modifier | Syntax | ICMPv6 Type | Default Destination IP & MAC | Wire Options & Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **Neighbor Solicit** | `NEIGHBOR_SOLICIT` | `Type 135` | Solicited-Node `ff02::1:ffxx:xxxx` (`33:33:ff:xx:xx:xx`) | Default `NDP` type; sets `TARGET` and appends Option `1` (`SLLA`) |
| **Neighbor Advert** | `NEIGHBOR_ADVERT` | `Type 136` | Unicast (host's IPv6 & MAC) | Sets Solicited + Override flags (`0x60`), `TARGET`, and Option `2` (`TLLA`) |
| **Router Solicit** | `ROUTER_SOLICIT` | `Type 133` | All-Routers `ff02::2` (`33:33:00:00:00:02`) | Sent by booting IPv6 hosts to request an immediate Router Advertisement; appends `SLLA` |
| **Router Advert** | `ROUTER_ADVERT` | `Type 134` | Host / `ff02::1` (`33:33:00:00:00:01`) | Advertises `Cur Hop Limit = 64` and `ROUTER_LIFETIME` (default `1800`s) |
| **Redirect** | `REDIRECT` | `Type 137` | Unicast | Informs IPv6 host of a better first-hop link-local router |
| **Target Address** | `TARGET <ipv6>` | — | — | 128-bit Target IPv6 address being queried (`NS`) or advertised (`NA`) |
| **Link-Layer Opts** | `SLLA <mac>`, `TLLA <mac>` | Option `1` / `2` | — | 8-byte Source (`SLLA`) or Target (`TLLA`) Link-Layer MAC option (defaults to sender's MAC) |
| **Router Lifetime** | `ROUTER_LIFETIME <seconds>`| — | — | Default router lifetime in seconds in `ROUTER_ADVERT` (`0` = router decommissioned) |

### Example: Dual-Stack `ICMP` Diagnostics & IPv6 `NDP` SLAAC Bootstrap

```frameassembly
host client_v4 { ip 192.168.10.50 mac 00:50:56:40:00:50 }
host router_v4 { ip 192.168.10.1  mac 00:50:56:40:00:01 }
host host_v6   { ip 2001:db8:100::50 mac 00:50:56:60:00:50 }
host router_v6 { ip 2001:db8:100::1  mac 00:50:56:60:00:01 }

flow icmp_and_ndp_diagnostics(c4, r4, h6, r6) {
    // 1. IPv4 Ping, Traceroute Hop Expiration (TTL=1 -> Time Exceeded), and Firewall Admin Prohibited (Code 13)
    c4 -> r4 icmp echo_request id 900 seq 1 payload "PING_IPV4" wait 1ms
    c4 <- r4 icmp echo_reply id 900 seq 1 payload "PING_IPV4" wait 1ms
    c4 <- r4 icmp time_exceeded code 0 payload "TRACEROUTE_HOP_1_EXPIRED" wait 1ms
    c4 <- r4 icmp dest_unreach code 13 payload "ACL_ADMIN_PROHIBITED" wait 1ms
    c4 <- r4 icmp redirect code 1 gateway 192.168.10.254 wait 2ms

    // 2. IPv6 ICMPv6 Echo Request/Reply and Packet Too Big (Type 2, Code 0)
    h6 -> r6 icmp echo_request id 906 seq 1 payload "PING_IPV6" wait 1ms
    h6 <- r6 icmp echo_reply id 906 seq 1 payload "PING_IPV6" wait 1ms
    h6 <- r6 icmp type 2 code 0 payload "IPV6_PACKET_TOO_BIG_MTU_1280" wait 2ms

    // 3. IPv6 NDP Router Discovery (RS -> ff02::2, RA <- router) and Neighbor Resolution (NS -> ff02::1:ff00:1, NA <- router)
    h6 -> r6 ndp router_solicit slla 00:50:56:60:00:50 wait 2ms
    h6 <- r6 ndp router_advert slla 00:50:56:60:00:01 router_lifetime 1800 wait 2ms
    h6 -> r6 ndp neighbor_solicit target 2001:db8:100::1 slla 00:50:56:60:00:50 wait 1ms
    h6 <- r6 ndp neighbor_advert target 2001:db8:100::1 tlla 00:50:56:60:00:01
}

compile {
    icmp_and_ndp_diagnostics(client_v4, router_v4, host_v6, router_v6)
}
```

---

## 3. Multicast Group Management (`IGMP` & `MLD`)

Access switches rely on **IGMP Snooping** (IPv4) and **MLD Snooping** (IPv6) to inspect host membership reports so high-bitrate multicast streams (IPTV, financial market feeds, VXLAN BUM replication) are forwarded only to ports with active receivers. FrameAssembly automatically derives the multicast destination IP and Ethernet MAC (`01:00:5e:xx:xx:xx` or `33:33:xx:xx:xx:xx`) from the group address.

### `IGMP` (IPv4 — IP Protocol `2`) & `MLD` (IPv6 — ICMPv6 Next Header `58`) Modifiers

| Protocol | Modifier | Syntax | Wire Behavior & Default |
| :--- | :--- | :--- | :--- |
| **`IGMP`** | **Message Type** | `QUERY`, `REPORT`, `LEAVE` | `QUERY` (`0x11`), `REPORT` (`0x12` v1 / `0x16` v2 / `0x22` v3, default), `LEAVE` (`0x17`) |
| **`IGMP`** | **Protocol Version**| `V1`, `V2`, `V3`, or `VERSION <1..3>` | Selects IGMPv1, IGMPv2 (default), or IGMPv3 Membership Report type byte |
| **`IGMP`** | **Multicast Group** | `GROUP <ipv4>` | 32-bit group IPv4 address (defaults: `224.0.0.1` on `QUERY`, `239.1.1.1` on `REPORT`, `224.0.0.2` on `LEAVE`) |
| **`IGMP`** | **Max Resp Time** | `MAX_RESP <0..255>` | Max response time in tenths of a second (`100` = 10.0s default on `QUERY`) |
| **`MLD`** | **Message Type** | `QUERY`, `REPORT`, `DONE` | ICMPv6 Type `130` (`QUERY`), Type `131` (`REPORT`, default), Type `132` (`DONE`) |
| **`MLD`** | **Multicast Group** | `MULTICAST_ADDR <ipv6>` | 128-bit IPv6 multicast group address (defaults: `ff02::1` on `QUERY`/`REPORT`, `ff02::2` on `DONE`) |
| **`MLD`** | **Max Resp Delay** | `MAX_RESP_DELAY <0..65535>` | Maximum response delay in milliseconds (`0` default; e.g. `1000` = 1s on `QUERY`) |

### Example: IPv4 `IGMP` & IPv6 `MLD` Snooping Lifecycle

```frameassembly
host querier_v4  { ip 10.40.1.1  mac 00:1c:73:40:00:01 }
host receiver_v4 { ip 10.40.1.50 mac 00:50:56:40:00:50 }
host querier_v6  { ip fe80::1    mac 00:1c:73:60:00:01 }
host receiver_v6 { ip fe80::50   mac 00:50:56:60:00:50 }

flow multicast_snooping_verification(q4, h4, q6, h6) {
    // IPv4 IGMPv2 General Query -> Membership Report -> Fast Leave (TTL 1 for link-local multicast)
    q4 -> h4 igmp v2 query group 224.0.0.1 max_resp 100 ttl 1 dscp 48 wait 2ms
    q4 <- h4 igmp v2 report group 239.255.10.1 ttl 1 wait 2ms
    q4 <- h4 igmp v3 report group 239.255.10.1 ttl 1 wait 5ms
    q4 <- h4 igmp v2 leave group 239.255.10.1 ttl 1 wait 5ms

    // IPv6 MLD Query -> Report -> Done
    q6 -> h6 mld query multicast_addr ff3e::100 max_resp_delay 1000 ttl 1 dscp 48 wait 2ms
    q6 <- h6 mld report multicast_addr ff3e::100 ttl 1 wait 5ms
    q6 <- h6 mld done multicast_addr ff3e::100 ttl 1
}

compile {
    multicast_snooping_verification(querier_v4, receiver_v4, querier_v6, receiver_v6)
}
```

---

## 4. Overlay & Data Center Tunneling (`GRE`, `VXLAN`, `GENEVE`)

Use `GRE`, `VXLAN`, and `GENEVE` to test WAN tunnel decapsulation, EVPN-VXLAN Leaf-Spine VTEPs, Kubernetes CNI overlays (Cilium / OVN-Kubernetes / Calico), and cloud inspection appliances (AWS Gateway Load Balancer `GENEVE` options).

| Protocol | Encapsulation | Modifier | Syntax & Aliases | Description & Default |
| :--- | :--- | :--- | :--- | :--- |
| **`GRE`** | IP Proto `47` | **Tunnel Key** | `GRE_KEY <number>` or `KEY <number>` | Sets `K` bit (`0x2000`) and inserts 32-bit RFC 2890 tunnel key |
| **`GRE`** | IP Proto `47` | **Sequence Num** | `GRE_SEQ <number>` | Sets `S` bit (`0x1000`) and inserts 32-bit sequence number |
| **`GRE`** | IP Proto `47` | **Inner EtherType**| `GRE_PROTO <0..65535>` | 16-bit protocol (`0x0800` IPv4 default, `0x86DD` IPv6, `0x6558` TEB/NVGRE) |
| **`GRE`** | IP Proto `47` | **Header Checksum**| `CHECKSUM` | Sets `C` bit (`0x8000`) and computes 16-bit RFC 2784 GRE checksum |
| **`VXLAN`** | UDP `4789` | **Virtual Net ID** | `VNI <0..16777215>` or `VNID <0..16777215>` | 24-bit VXLAN Network Identifier with `I` flag `0x08` (`4096` default) |
| **`VXLAN`** | UDP `4789` | **UDP Ports** | `SRCPORT <0..65535>`, `DSTPORT <0..65535>` | Outer UDP entropy source port and destination port (`4789` default, `8472` Linux legacy) |
| **`GENEVE`**| UDP `6081` | **Virtual Net ID** | `VNI <0..16777215>` or `VNID <0..16777215>` | 24-bit Virtual Network Identifier (`4096` default) |
| **`GENEVE`**| UDP `6081` | **Inner EtherType**| `PROTOCOL_TYPE <0..65535>` | Inner payload type (`0x6558` Transparent Ethernet Bridging default, `0x0800` IPv4) |
| **`GENEVE`**| UDP `6081` | **Option Class/Type**| `OPT_CLASS <0..65535>`, `OPT_TYPE <0..255>` | Appends 4-byte GENEVE TLV option (`0x0102` OVN/Cilium, `0x0108` AWS GWLB, `0x0104` VMware NSX) |

> **Automatic Inner Passenger Frame Synthesis:** When you emit a `VXLAN` or `GENEVE` packet without an explicit `PAYLOAD` or `HEXPAYLOAD`, FrameAssembly automatically generates a complete, checksum-valid 42-byte inner Ethernet II + IPv4 (`10.0.0.1 -> 10.0.0.2`) + UDP passenger frame so Wireshark and hardware NIC offloads dissect both the outer tunnel and inner tenant headers cleanly.

### Example: WAN `GRE`, EVPN-`VXLAN` & Cloud-Native `GENEVE` Overlays

```frameassembly
host vtep_leaf_1 { ip 10.200.0.11 mac 00:1c:73:dc:00:11 }
host vtep_leaf_2 { ip 10.200.0.12 mac 00:1c:73:dc:00:12 }

flow fabric_tunnel_encapsulations(vtep1, vtep2) {
    // 1. Point-to-point GRE tunnel with Key 50010, Sequence 1, and RFC 2784 Checksum enabled
    vtep1 -> vtep2 gre gre_key 50010 gre_seq 1 gre_proto 0x0800 checksum df ttl 64 wait 1ms

    // 2. EVPN-VXLAN Layer 2 Stretch (VNI 10500, ECMP hash srcport 55123, DF set, auto-synthesized inner frame)
    vtep1 -> vtep2 vxlan vni 10500 srcport 55123 dstport 4789 df dscp 18 wait 1ms

    // 3. Cilium / OVN GENEVE overlay (VNI 20800, Option Class 0x0102 OVN, Option Type 1)
    vtep1 -> vtep2 geneve vni 20800 opt_class 0x0102 opt_type 1 protocol_type 0x6558 srcport 59400 df
}

compile {
    fabric_tunnel_encapsulations(vtep_leaf_1, vtep_leaf_2)
}
```

**Inspect with `tshark`:**
```console
tshark -r output.pcap -Y "gre or vxlan or geneve" -V
```

---

## 5. IPsec & Modern Cryptographic VPNs (`IKEV2`, `IPSEC`, `ESP`, `AH`, `WIREGUARD`)

Verifying that a border firewall passes IPsec `ESP` (`IP Protocol 50`), `AH` (`IP Protocol 51`), `IKEv2` (`UDP 500/4500`), or WireGuard (`UDP 51820`) traffic normally requires standing up two VPN gateways and exchanging keys before a single tunnel packet crosses the wire. FrameAssembly lets you generate all five VPN and IPsec protocols directly—complete with custom SPIs, anti-replay sequence numbers, Initialization Vectors (`IV`), Integrity Check Values (`ICV`), and WireGuard `Noise_IKpsk2` handshake frames.

### 5.1 `IKEV2` (Internet Key Exchange v2 — RFC 7296, UDP `500` / `4500`)
Negotiates IPsec Security Associations (`SA`). By default, `IKEV2` uses UDP port `500`; add `dstport 4500 srcport 4500` to simulate NAT-Traversal (`NAT-T`) over UDP `4500`.

| Modifier | Syntax | Wire Field & Values | Default |
| :--- | :--- | :--- | :--- |
| **Exchange Mode** | `SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL` (or `EXCHANGE <mode>`) | Exchange Type byte: `34` (`SA_INIT`), `36` (`CREATE_CHILD_SA`), `37` (`INFORMATIONAL`) | `SA_INIT` (`34`) |
| **Initiator SPI** | `INITIATOR_SPI <hex_or_int>` | 64-bit big-endian Initiator Security Parameters Index | `0x0102030405060708` |
| **Responder SPI** | `RESPONDER_SPI <hex_or_int>` | 64-bit big-endian Responder SPI (`0` on initial `SA_INIT` request) | `0` |
| **Message ID** | `MSGID <number>` | 32-bit sequence counter (`0` for `SA_INIT`, `1+` for `CREATE_CHILD_SA`/`INFORMATIONAL`) | `0` |
| **IKE Flags** | `FLAGS <0..255>` | `0x08` = Initiator, `0x20` = Response, `0x28` = Initiator + Response | `0x08` (Initiator) |
| **Next Payload** | `NEXT_PAYLOAD <0..255>` | First chained IKE payload type (`33` = SA, `34` = KE, `46` = Encrypted SK, `0` = None) | `0` |

### 5.2 `IPSEC` / `ESP` (RFC 4303 — IP Proto `50`) & `AH` (RFC 4302 — IP Proto `51`)
Both `IPSEC` and `ESP` emit RFC 4303 Encapsulating Security Payload frames (`IP Protocol 50`), while `AH` emits RFC 4302 Authentication Header frames (`IP Protocol 51`).

| Modifier | Syntax | Applies To | Wire Field & Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| **Security Param Index**| `SPI <hex_or_int>` | `IPSEC`, `ESP`, `AH` | 32-bit Security Association identifier (`0x1000` on ESP, `0x2000` on AH) | `0x1000` / `0x2000` |
| **Anti-Replay Seq** | `SEQ <number>` | `IPSEC`, `ESP`, `AH` | 32-bit monotonically increasing sequence number | `1` |
| **Init Vector** | `IV "<hex>"` | `IPSEC`, `ESP` | Explicit cipher Initialization Vector (e.g. 8-byte AES-GCM / CBC IV) | 8 zero bytes |
| **Integrity Check** | `ICV "<hex>"` | `IPSEC`, `ESP`, `AH` | Trailing HMAC / AEAD authentication tag | 12 zero bytes |
| **Inner Protocol** | `NEXT_HEADER <0..255>`| `IPSEC`, `ESP`, `AH` | Protected inner protocol: `4` = IPv4-in-IPsec, `41` = IPv6-in-IPsec, `6` = TCP, `17` = UDP | `59` (No Next Hdr) |

### 5.3 `WIREGUARD` (Noise_IKpsk2 Secure Network Tunnel — UDP `51820`)
WireGuard encodes all integer fields (`SENDER`, `RECEIVER`, `COUNTER`) in **little-endian** byte order inside fixed-size handshake packets (`148` bytes for `INITIATION`, `92` bytes for `RESPONSE`, `64` bytes for `COOKIE`) to resist amplification and fingerprinting attacks.

| Modifier | Syntax | Wire Packet Type & Size | Description & Default |
| :--- | :--- | :--- | :--- |
| **Message Type** | `TYPE <INITIATION\|RESPONSE\|COOKIE\|DATA>` (or bare `INITIATION`, `COOKIE`, `DATA`) | `1` = Initiation (`148` B), `2` = Response (`92` B), `3` = Cookie (`64` B), `4` = Data (`>=32` B) | `INITIATION` (`1`) |
| **Sender Index** | `SENDER <hex_or_int>` | 32-bit little-endian local session index (`INITIATION` and `RESPONSE`) | `1` |
| **Receiver Index** | `RECEIVER <hex_or_int>` | 32-bit little-endian peer session index (`RESPONSE`, `COOKIE`, and `DATA`) | `2` (Resp) / `1` (Data) |
| **AEAD Nonce Counter**| `COUNTER <number>` | 64-bit little-endian ChaCha20-Poly1305 packet counter (`DATA` packets) | `0` |

### Example: Site-to-Site `IKEV2` + `ESP` + `AH` and `WIREGUARD` Tunnel Lifecycle

```frameassembly
host branch_gw { ip 198.51.100.10 }
host hq_gw     { ip 203.0.113.1 }

flow vpn_ipsec_and_wireguard(branch, hq) {
    // 1. IKEv2 SA_INIT exchange (UDP 500) followed by ESP (Proto 50) and AH (Proto 51)
    branch -> hq ikev2 sa_init initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0 msgid 0 flags 0x08 next_payload 33 wait 2ms
    branch <- hq ikev2 sa_init initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x9988776655440002 msgid 0 flags 0x20 next_payload 33 wait 2ms
    branch -> hq ikev2 create_child_sa initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x9988776655440002 msgid 1 flags 0x08 next_payload 46 wait 2ms
    branch -> hq esp spi 0x10002001 seq 1 iv "1122334455667788" icv "aabbccddeeff001122334455" next_header 4 payload "ESP_TUNNEL_CIPHERTEXT" wait 1ms
    branch <- hq ah spi 0x20003002 seq 1 icv "99887766554433221100ffeeddcc" next_header 4 payload "AH_AUTHENTICATED_PACKET" wait 5ms

    // 2. WireGuard 1-RTT Handshake (148B Initiation -> 92B Response) + Encrypted Data (UDP 51820)
    branch -> hq wireguard type initiation sender 0x10203040 wait 1ms
    branch <- hq wireguard type response sender 0x50607080 receiver 0x10203040 wait 1ms
    branch -> hq wireguard type data receiver 0x50607080 counter 0 payload "WG_ENCRYPTED_PAYLOAD_1" wait 1ms
    branch <- hq wireguard type data receiver 0x10203040 counter 0 payload "WG_ENCRYPTED_REPLY_1"
}

compile {
    vpn_ipsec_and_wireguard(branch_gw, hq_gw)
}
```

---

## 6. Dynamic Unicast & Multicast Routing (`OSPF`, `BGP`, `RIP`, `PIM`)

Spinning up FRRouting, BIRD, or virtual router VMs just to test how a monitoring tool, firewall ACL, or packet dissector handles an OSPF adjacency, an eBGP route update, a RIPv2 poison-reverse advertisement, or a PIM-SM multicast join is overkill when you only need the packets. FrameAssembly handles link-local multicast addressing (`224.0.0.5`/`ff02::5`, `224.0.0.9`/`ff02::9`, `224.0.0.13`/`ff02::d`), TCP port `179` sequence tracking for `BGP`, and routing header checksums automatically.

### 6.1 `OSPF` (Open Shortest Path First — RFC 2328 / RFC 5340, IP Protocol `89`)
FrameAssembly automatically addresses `OSPF` packets to the **AllSPFRouters** multicast group (`224.0.0.5` / MAC `01:00:5e:00:00:05` on IPv4, and `ff02::5` / MAC `33:33:00:00:00:05` on IPv6) and computes the 16-bit OSPF packet checksum.

| Modifier | Syntax | Wire Field & Description | Default |
| :--- | :--- | :--- | :--- |
| **Packet Type** | `HELLO`, `DBD`, `LSR`, `LSU`, `LSACK` | Type `1` (`HELLO`), `2` (Database Desc), `3` (LS Request), `4` (LS Update), `5` (LS Ack) | `HELLO` (`1`) |
| **Router ID** | `ROUTER_ID <ipv4>` | 32-bit OSPF Router ID in the 24-byte header | Sending host's IPv4 (or `10.0.0.1`) |
| **Area ID** | `AREA_ID <number \| ipv4>` | Accepts both integer (`area_id 0`) and dotted-quad (`area_id 0.0.0.0`) formats | `0` (`Area 0.0.0.0`) |
| **Hello / Dead** | `HELLO_INTERVAL <seconds>`, `DEAD_INTERVAL <seconds>` | Hello timer (default `10`s) and Router Dead Interval (default `40`s; or DD Seq in `DBD`) | `10`s / `40`s |
| **DR Priority** | `PRIORITY <0..255>` | 8-bit Designated Router election priority (`0` = ineligible to become DR/BDR) | `1` |

### 6.2 `BGP` (Border Gateway Protocol v4 — RFC 4271, TCP Port `179`)
`BGP` runs over **TCP port `179`** and shares FrameAssembly's automatic 4-tuple TCP sequence and acknowledgment state machine with raw `TCP` statements. Every BGP message starts with the 16-byte `0xff..0xff` marker followed by the 16-bit length and 8-bit message type.

| Modifier | Syntax | Wire Field & Description | Default |
| :--- | :--- | :--- | :--- |
| **Message Type** | `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE` | `1` = `OPEN` (29B), `2` = `UPDATE`, `3` = `NOTIFICATION` (Cease), `4` = `KEEPALIVE` (19B) | `UPDATE` (if prefix/nexthop set) else `KEEPALIVE` |
| **Autonomous Sys**| `ASN <number>` | Peer ASN in `OPEN` (`My Autonomous System`) and `UPDATE` (`AS_PATH` segment) | `65001` |
| **Hold Time** | `HOLDTIME <seconds>` | Hold time in seconds negotiated in `OPEN` | `180` seconds |
| **BGP Identifier**| `BGPID <ipv4>` | 32-bit BGP Router ID in `OPEN` | Sending host's IPv4 |
| **NLRI Prefix** | `PREFIX "<cidr>"` or `NLRI "<cidr>"` | **Quoted** CIDR string (e.g. `"172.16.0.0/12"`, `"2001:db8::/32"`) encoded as RFC 4271 NLRI | Omitted |
| **Next Hop** | `NEXTHOP <ip>` | Next-hop IP encoded in Path Attribute Code `3` (`NEXT_HOP`) | Sending host's IP |

### 6.3 `RIP` (Routing Information Protocol v2 / RIPng — RFC 2453 / RFC 2080, UDP `520` / `521`)
Automatically targets multicast `224.0.0.9` on UDP port `520` for IPv4, or `ff02::9` on UDP port `521` for IPv6.
* **Modifiers:** `REQUEST` (Command `1`), `RESPONSE` or `REPLY` (Command `2`, default), `PREFIX <ip>` (**unquoted** IP address, e.g. `prefix 192.168.50.0`, default `10.0.0.0`), `NEXTHOP <ip>` (default `0.0.0.0`), `METRIC <1..16>` (hop count, default `1`, `16` = unreachable route poison-reverse), `TAG <0..65535>` (external route tag, default `0`).

> **Syntax Tip (`BGP` vs. `RIP` Prefixes):** In `BGP`, `PREFIX` takes a **quoted CIDR string** with slash length (`bgp update prefix "10.20.0.0/16"`). In `RIP`, `PREFIX` takes an **unquoted IP address** (`rip response prefix 10.20.0.0 metric 2`).

### 6.4 `PIM` (Protocol Independent Multicast - Sparse Mode — RFC 7761, IP Protocol `103`)
Automatically targets **All-PIM-Routers** (`224.0.0.13` on IPv4, `ff02::d` on IPv6).
* **Modifiers:** `HELLO` (Type `0`, default), `JOIN_PRUNE` (Type `3`), `REGISTER` (Type `1` unicast source encapsulation), `GROUP <ip>` (multicast group, default `239.1.1.1`), `SOURCE <ip>` (multicast source), `RP <ip>` (Rendezvous Point address), `HOLDTIME <seconds>` (`105`s default on `HELLO`, `210`s on `JOIN_PRUNE`), `DR_PRIORITY <number>` (Designated Router priority, default `1`).

### Example: Full OSPF Adjacency, TCP+eBGP Route Exchange, RIPv2 & PIM-SM

```frameassembly
host core_rtr_1 { ip 10.0.0.1 mac 00:1c:73:00:00:01 }
host core_rtr_2 { ip 10.0.0.2 mac 00:1c:73:00:00:02 }

flow dynamic_routing_suite(r1, r2) {
    // 1. OSPF Area 0.0.0.0 Adjacency (Hello -> DBD -> LSR -> LSU -> LSAck) to 224.0.0.5
    r1 -> r2 dscp 48 ttl 1 ospf hello router_id 1.1.1.1 area_id 0.0.0.0 hello_interval 10 dead_interval 40 priority 100 wait 1ms
    r1 <- r2 dscp 48 ttl 1 ospf hello router_id 2.2.2.2 area_id 0.0.0.0 hello_interval 10 dead_interval 40 priority 50 wait 1ms
    r1 -> r2 dscp 48 ttl 1 ospf dbd router_id 1.1.1.1 area_id 0 dead_interval 1001 wait 1ms
    r1 <- r2 dscp 48 ttl 1 ospf lsr router_id 2.2.2.2 area_id 0 wait 1ms
    r1 -> r2 dscp 48 ttl 1 ospf lsu router_id 1.1.1.1 area_id 0 wait 1ms
    r1 <- r2 dscp 48 ttl 1 ospf lsack router_id 2.2.2.2 area_id 0 wait 2ms

    // 2. eBGP Session over TCP 179 (TCP 3-way handshake shares SEQ/ACK state with BGP messages!)
    r1 -> r2 dscp 48 ttl 255 tcp syn srcport 51000 dstport 179 wait 1ms
    r1 <- r2 dscp 48 ttl 255 tcp syn ack wait 1ms
    r1 -> r2 dscp 48 ttl 255 tcp ack wait 1ms
    r1 -> r2 dscp 48 ttl 255 bgp open asn 65001 holdtime 90 bgpid 1.1.1.1 wait 1ms
    r1 <- r2 dscp 48 ttl 255 bgp open asn 65002 holdtime 90 bgpid 2.2.2.2 wait 1ms
    r1 -> r2 dscp 48 ttl 255 bgp keepalive wait 1ms
    r1 <- r2 dscp 48 ttl 255 bgp update asn 65002 prefix "172.16.0.0/12" nexthop 10.0.0.2 wait 2ms

    // 3. RIPv2 Route Advertisement & PIM-SM Multicast Join/Prune
    r1 -> r2 dscp 48 ttl 2 rip response prefix 192.168.50.0 nexthop 10.0.0.1 metric 2 tag 100 wait 1ms
    r1 <- r2 dscp 48 ttl 1 pim join_prune group 239.10.10.1 source 10.1.1.10 rp 10.0.0.1 holdtime 210
}

compile {
    dynamic_routing_suite(core_rtr_1, core_rtr_2)
}
```

---

## 7. First-Hop Redundancy, Fast Liveness & SDN (`VRRP`, `HSRP`, `BFD`, `OPENFLOW`)

Testing first-hop gateway failovers (`VRRP` and Cisco `HSRP`), sub-second `BFD` link-down detection, or `OpenFlow` SDN controller messages in production is nerve-wracking because triggering a real failover disrupts live traffic. With FrameAssembly, you can synthesize priority-preemption elections, 3-way BFD state transitions (`Down -> Init -> Up`), and OpenFlow 1.0–1.5 `FLOW_MOD` messages offline with valid pseudo-header and control-plane checksums.

### 7.1 `VRRP` (Virtual Router Redundancy Protocol — RFC 3768 v2 / RFC 5798 v3, IP Proto `112`)
Automatically sets `TTL 255` and addresses packets to `224.0.0.18` (`01:00:5e:00:00:12`) on IPv4 or `ff02::12` (`33:33:00:00:00:12`) on IPv6.
* **Modifiers:**
  * `VERSION <2|3>`: Selects RFC 3768 VRRPv2 (`2`) or RFC 5798 VRRPv3 (`3`, default, with IPv4/IPv6 pseudo-header checksum).
  * `VRID <1..255>`: Virtual Router ID (default `1`).
  * `PRIORITY <0..255>`: Election priority (default `100`; `255` = VIP owner, `0` = Master releasing ownership).
  * `ADV_INT <0..65535>`: Advertisement interval (in seconds for v2, default `1`s; in centiseconds for v3, default `100` = 1.00s).
  * `VIP <ip>`: Virtual IPv4 or IPv6 gateway address.

### 7.2 `HSRP` (Cisco Hot Standby Router Protocol — RFC 2281, UDP `1985` / `2029`)
Automatically targets `224.0.0.2` on UDP port `1985` (IPv4) or `ff02::66` on UDP port `2029` (IPv6).
* **Modifiers:** `GROUP <0..255>` (default `1`), `PRIORITY <0..255>` (default `100`), `STATE <0..255>` (`0` = Initial, `1` = Learn, `2` = Listen, `4` = Speak, `8` = Standby, `16` = Active default), `HELLOTIME <seconds>` (default `3`s), `HOLDTIME <seconds>` (default `10`s), `AUTH "<text>"` (8-byte cleartext string, default `"cisco"`), `VIP <ip>`.

### 7.3 `BFD` (Bidirectional Forwarding Detection — RFC 5880 / RFC 5881, UDP `3784`)
Provides sub-second forwarding path failure detection (`UDP 3784` single-hop, or override with `dstport 4784` for RFC 5883 multihop).

| Modifier | Syntax | Values & Description | Default |
| :--- | :--- | :--- | :--- |
| **Session State** | `STATE <0..3>` | `0` = AdminDown, `1` = Down, `2` = Init, `3` = Up | `3` (`Up`) |
| **Diagnostic Code** | `DIAG <0..31>` | `0` = No Diag, `1` = Control Timer Expired, `3` = Neighbor Down, `7` = AdminDown | `0` |
| **Discriminators** | `MY_DISC <number>`, `YOUR_DISC <number>` | Local (`1` default) and remote (`0` on initial Down, peer's `MY_DISC` once learned) session IDs | `1` / `0` |
| **TX / RX Timers** | `MIN_TX <microseconds>`, `MIN_RX <microseconds>` | Desired Min TX and Required Min RX intervals in **microseconds** (`50000` = 50ms) | `1000000` (1s) |
| **Multiplier** | `MULT <1..255>` | Detection time multiplier (`3` x `50ms` = `150ms` failover detection) | `3` |

### 7.4 `OPENFLOW` (ONF OpenFlow Switch Protocol — TCP Port `6653`)
Simulates Software-Defined Networking (SDN) controller-to-switch communication over TCP port `6653`.
* **Message Types (bare or preceded by `TYPE`):** `HELLO` (`0`), `ECHO_REQ` / `ECHO_REQUEST` (`2`), `ECHO_REPLY` (`3`), `FEATURES_REQ` (`5`), `FEATURES_REPLY` (`6`, builds a complete 32-byte `ofp_switch_features` frame with `DPID` and `TABLE_ID`), `PACKET_IN` (`10`), `PACKET_OUT` (`13`), `FLOW_MOD` (`14`, builds a complete 56-byte `ofp_flow_mod` frame with `TABLE_ID` and `PRIORITY`).
* **Modifiers:** `VERSION <1..6>` (`1` = OF 1.0, `4` = OF 1.3 default, `5` = OF 1.4, `6` = OF 1.5), `XID <number>` (Transaction ID, default `1`), `DPID <hex_or_int>` (64-bit switch Datapath ID), `TABLE_ID <0..255>`, `PRIORITY <0..65535>`.

### Example: VRRP/HSRP Gateway Election, 3-Way BFD Handshake & OpenFlow 1.3 Programming

```frameassembly
host gw_primary   { ip 10.10.0.2 mac 00:00:5e:00:01:0a }
host gw_secondary { ip 10.10.0.3 mac 00:1c:73:10:00:03 }

flow fhrp_bfd_and_openflow(pri, sec) {
    // 1. VRRPv3 Advertisement (VRID 10, Priority 200 Master) and Cisco HSRP Active/Standby Hellos
    pri -> sec vrrp version 3 vrid 10 priority 200 adv_int 100 vip 10.10.0.1 ttl 255 dscp 48 wait 1ms
    pri -> sec hsrp group 10 priority 150 state 16 hellotime 3 holdtime 10 auth "corpkey1" vip 10.10.0.254 ttl 1 dscp 48 wait 1ms
    pri <- sec hsrp group 10 priority 100 state 8 hellotime 3 holdtime 10 auth "corpkey1" vip 10.10.0.254 ttl 1 dscp 48 wait 2ms

    // 2. BFD 3-Way Session Bring-Up (Down -> Init -> Up at 50ms intervals)
    pri -> sec bfd state 1 diag 0 my_disc 1001 your_disc 0 min_tx 50000 min_rx 50000 mult 3 ttl 255 dscp 48 wait 1ms
    pri <- sec bfd state 2 diag 0 my_disc 2002 your_disc 1001 min_tx 50000 min_rx 50000 mult 3 ttl 255 dscp 48 wait 1ms
    pri -> sec bfd state 3 diag 0 my_disc 1001 your_disc 2002 min_tx 50000 min_rx 50000 mult 3 ttl 255 dscp 48 wait 2ms

    // 3. OpenFlow 1.3 (Version 4) Hello, Features Handshake, and Flow Table Modification
    pri <- sec openflow version 4 hello xid 100 wait 1ms
    pri -> sec openflow version 4 hello xid 100 wait 1ms
    pri <- sec openflow version 4 features_req xid 101 wait 1ms
    pri -> sec openflow version 4 features_reply xid 101 dpid 0x0000001c73aabbcc table_id 64 wait 1ms
    pri <- sec openflow version 4 flow_mod xid 102 dpid 0x0000000000000001 table_id 0 priority 500
}

compile {
    fhrp_bfd_and_openflow(gw_primary, gw_secondary)
}
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — End-to-end recipes for firewall ACL testing, routing failover simulation, QoS verification, and IDS/IPS validation.
- [**Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)**](l2_protocols.md) — `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, and `MPLS`.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — `TCP`, `UDP`, and `SCTP` 4-tuple state tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling.
- [**Layer 7 Network Management (`l7_snmp.md`)**](l7_snmp.md) — `SNMP1`, `SNMP2`, and encrypted `SNMP3` USM traps and polls for routing/FHRP alerting.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Complete EVPN-VXLAN leaf-spine fabric and WAN BFD/OSPF/VRRP/IPsec/MPLS failover captures.
- [**`.fasm` File Format & Media Type Specification (`fasm-specification.md`)**](fasm-specification.md) — Normative `text/vnd.frameassembly` media type specification, lexical rules, and `.fasm` extension disambiguation.
