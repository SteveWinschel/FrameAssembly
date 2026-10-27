# Layer 3 Network, Routing, Tunneling, VPN & FHRP Protocols Reference

FrameAssembly provides native, zero-dependency packet crafting and wire encapsulation for all **20 Layer 3 (Network, Routing, Overlay Tunneling, IPsec/VPN, First-Hop Redundancy, and SDN Control)** protocols across both IPv4 (`0x0800`) and IPv6 (`0x86DD`).

This canonical reference covers:
- **IPv4 & IPv6 Base Headers, QoS & Fragmentation**: `TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `IPID`, `DF`, `MF`, `FRAGOFFSET`, `NEXT_HEADER`
- **Diagnostics & Neighbor Discovery**: `ICMP` (RFC 792 / RFC 4443 ICMPv6) and `NDP` (RFC 4861)
- **Multicast Group Management**: `IGMP` (RFC 3376) and `MLD` (RFC 3810)
- **Overlay & Underlay Tunneling**: `GRE` (RFC 2784 / 2890), `VXLAN` (RFC 7348), and `GENEVE` (RFC 8926)
- **Cryptographic VPNs & Key Exchange**: `IPSEC` (RFC 4301), `ESP` (RFC 4303), `AH` (RFC 4302), `IKEV2` (RFC 7296), and `WIREGUARD` (Noise_IKpsk2)
- **Dynamic Interior & Exterior Routing**: `OSPF` (RFC 2328 / 5340), `BGP` (RFC 4271), `RIP` (RFC 2453), and `PIM` (RFC 7761)
- **First-Hop Redundancy, Fast Failover & SDN**: `VRRP` (RFC 5798), `HSRP` (RFC 2281), `BFD` (RFC 5880), and `OPENFLOW` (ONF v1.3)

---

## 1. Layer 3 Protocol Architecture & RFC Matrix

| Protocol | Keyword | Standard RFC | Transport / IP Proto | Corpus Directory | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ICMP / ICMPv6** | `ICMP` | RFC 792 / RFC 4443 | IP Proto `1` / `58` | [`examples/l3/icmp/`](../examples/l3/icmp) | Echo ping, Destination Unreachable, Time Exceeded, Redirect |
| **NDP** | `NDP` | RFC 4861 | ICMPv6 (`133..136`) | [`examples/l3/ndp/`](../examples/l3/ndp) | IPv6 Router/Neighbor Solicitation & Advertisement, SLAAC |
| **IGMP** | `IGMP` | RFC 1112 / 2236 / 3376 | IP Proto `2` (`224.0.0.1/22`) | [`examples/l3/igmp/`](../examples/l3/igmp) | IPv4 multicast group `QUERY`, `REPORT`, `LEAVE` (`V1`–`V3`) |
| **MLD** | `MLD` | RFC 2710 / RFC 3810 | ICMPv6 (`130..132`) | [`examples/l3/mld/`](../examples/l3/mld) | IPv6 Multicast Listener Discovery `QUERY`, `REPORT`, `DONE` |
| **GRE** | `GRE` | RFC 2784 / RFC 2890 | IP Proto `47` | [`examples/l3/gre/`](../examples/l3/gre) | Generic Routing Encapsulation (`GRE_KEY`, `GRE_SEQ`, `GRE_PROTO`) |
| **VXLAN** | `VXLAN` | RFC 7348 | UDP Port `4789` | [`examples/l3/vxlan/`](../examples/l3/vxlan) | 24-bit `VNI` Layer 2 over Layer 3 data center fabric overlay |
| **GENEVE** | `GENEVE` | RFC 8926 | UDP Port `6081` | [`examples/l3/geneve/`](../examples/l3/geneve) | Extensible TLV overlay (`VNI`, `OPT_CLASS`, `OPT_TYPE`) |
| **IPsec** | `IPSEC` | RFC 4301 | IP Proto `50` | [`examples/l3/ipsec/`](../examples/l3/ipsec) | Security Association `SPI`, `SEQ`, `IV`, `ICV`, `NEXT_HEADER` |
| **ESP** | `ESP` | RFC 4303 | IP Proto `50` | [`examples/l3/esp/`](../examples/l3/esp) | Encapsulating Security Payload confidentiality & AEAD integrity |
| **AH** | `AH` | RFC 4302 | IP Proto `51` | [`examples/l3/ah/`](../examples/l3/ah) | Authentication Header connectionless IP integrity (`SPI`, `ICV`) |
| **IKEv2** | `IKEV2` | RFC 7296 | UDP Port `500` / `4500` | [`examples/l3/ikev2/`](../examples/l3/ikev2) | `SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL` SPI negotiation |
| **WireGuard** | `WIREGUARD` | Noise_IKpsk2 | UDP Port `51820` | [`examples/l3/wireguard/`](../examples/l3/wireguard) | Modern VPN (`INITIATION`, `RESPONSE`, `COOKIE`, `DATA`) |
| **OSPF** | `OSPF` | RFC 2328 / RFC 5340 | IP Proto `89` (`224.0.0.5/6`) | [`examples/l3/ospf/`](../examples/l3/ospf) | Link-state IGP (`HELLO`, `DBD`, `LSR`, `LSU`, `LSACK`) |
| **BGP-4** | `BGP` | RFC 4271 | TCP Port `179` | [`examples/l3/bgp/`](../examples/l3/bgp) | Inter-domain routing (`OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`) |
| **RIPv2** | `RIP` | RFC 2453 | UDP Port `520` (`224.0.0.9`) | [`examples/l3/rip/`](../examples/l3/rip) | Distance-vector routing (`PREFIX`, `NEXTHOP`, `METRIC`, `TAG`) |
| **VRRP** | `VRRP` | RFC 5798 | IP Proto `112` (`224.0.0.18`) | [`examples/l3/vrrp/`](../examples/l3/vrrp) | First-Hop Redundancy (`VRID`, `PRIORITY`, `ADV_INT`, `VIP`) |
| **HSRP** | `HSRP` | RFC 2281 | UDP Port `1985` (`224.0.0.2`) | [`examples/l3/hsrp/`](../examples/l3/hsrp) | Hot Standby Router Protocol (`GROUP`, `PRIORITY`, `STATE`, `VIP`) |
| **PIM-SM** | `PIM` | RFC 7761 | IP Proto `103` (`224.0.0.13`) | [`examples/l3/pim/`](../examples/l3/pim) | Multicast routing (`HELLO`, `JOIN_PRUNE`, `REGISTER`, `RP`) |
| **BFD** | `BFD` | RFC 5880 | UDP Port `3784` / `4784` | [`examples/l3/bfd/`](../examples/l3/bfd) | Sub-second forwarding plane liveness (`MY_DISC`, `MIN_TX`, `MULT`) |
| **OpenFlow** | `OPENFLOW` | ONF v1.3 / v1.5 | TCP Port `6653` | [`examples/l3/openflow/`](../examples/l3/openflow) | SDN flow table control (`FEATURES_REQ`, `PACKET_IN`, `FLOW_MOD`) |

---

## 2. Universal IPv4 & IPv6 Layer 3 Modifiers

Any frame statement in FrameAssembly can include Layer 3 IPv4 (RFC 791) and IPv6 (RFC 8200) header modifiers:

| Modifier | Syntax | Range | Description & Standard |
| :--- | :--- | :--- | :--- |
| **Time to Live / Hop Limit** | `TTL <u8>` | `0..255` | Sets IPv4 TTL or IPv6 Hop Limit (`64` default, `255` for GTSM BGP/NDP, `1` for link-local multicast) |
| **DiffServ Code Point** | `DSCP <u8>` | `0..63` | 6-bit QoS class (`46` = EF Voice, `34` = AF41 Video, `48` = CS6 Routing Control, `8` = CS1 Scavenger) |
| **Congestion Notification** | `ECN <u8>` | `0..3` | 2-bit Explicit Congestion Notification (`0` = Non-ECT, `1` = ECT(1), `2` = ECT(0), `3` = CE) |
| **IPv6 Flow Label** | `FLOWLABEL <u20>`| `0..1048575` | 20-bit IPv6 Flow Label for stateless ECMP spine hashing (silently ignored on IPv4 statements) |
| **IPv4 Identification** | `IPID <u16>` | `0..65535` | 16-bit IPv4 Identification field for fragment reassembly |
| **Don't Fragment Flag** | `DF` | Flag (0-arg) | Sets IPv4 Don't Fragment bit (`0x4000`) for Path MTU Discovery |
| **More Fragments Flag** | `MF` | Flag (0-arg) | Sets IPv4 More Fragments bit (`0x2000`) on non-terminal fragments |
| **Fragment Offset** | `FRAGOFFSET <u16>`| `0..8191` | 13-bit IPv4 fragment offset in 8-octet units |
| **Next Header / Protocol** | `NEXT_HEADER <u8>`| `0..255` | Overrides inner protocol number on IPsec/ESP/AH/IPv6 headers |

---

## 3. Diagnostics & Neighbor Discovery (`ICMP` & `NDP`)

### 3.1 `ICMP` Modifiers (IPv4 RFC 792 & IPv6 RFC 4443)
When `ICMP` is used between IPv4 hosts, the compiler emits ICMPv4 (IP Protocol `1`). When `ICMP` is used between IPv6 hosts, the compiler automatically emits ICMPv6 (Next Header `58`) and computes the mandatory RFC 4443 IPv6 pseudo-header checksum.

| Modifier | Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **Message Type** | `ECHO_REQUEST` / `ECHO_REPLY` / `DEST_UNREACH` / `TIME_EXCEEDED` / `REDIRECT` | Flag (0-arg) | Selects standard ICMPv4 or ICMPv6 message type |
| **ICMP Code** | `CODE <u8>` | `u8` (`0..255`) | Subtype code (e.g. `4` = Fragmentation Needed / Packet Too Big) |
| **Identifier** | `ID <u16>` | `u16` | Echo Request/Reply session identifier |
| **Sequence Number**| `SEQ <u32>` | `u32` | Echo Request/Reply sequence number |
| **Redirect Gateway**| `GATEWAY <ip>` | IPv4 / IPv6 | Next-hop gateway address in ICMP `REDIRECT` messages |

### 3.2 `NDP` Modifiers (IPv6 Neighbor Discovery Protocol — RFC 4861)

| Modifier | Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **Message Type** | `ROUTER_SOLICIT` / `ROUTER_ADVERT` / `NEIGHBOR_SOLICIT` / `NEIGHBOR_ADVERT` | Flag (0-arg) | ICMPv6 types `133`, `134`, `135`, `136` (default Hop Limit `255`) |
| **Target IPv6** | `TARGET <ipv6>` | IPv6 literal | Target IPv6 address in Neighbor Solicitation / Advertisement |
| **Source Link-Layer**| `SLLA <mac>` | 48-bit MAC | ICMPv6 Option Type `1` (Source Link-Layer Address) |
| **Target Link-Layer**| `TLLA <mac>` | 48-bit MAC | ICMPv6 Option Type `2` (Target Link-Layer Address) |
| **Router Lifetime** | `ROUTER_LIFETIME <u16>` | `u16` | Default router lifetime in seconds inside `ROUTER_ADVERT` |

### 3.3 Verified `ICMP` (Dual-Stack) and `NDP` Example

```frameassembly
// PROMPT: Dual-stack ICMPv4 Path MTU Discovery, ICMPv6 echo probing, and RFC 4861 NDP SLAAC + Neighbor Resolution.
// TOKENS: HOST, IP, MAC, FLOW, ICMP, ECHO_REQUEST, ECHO_REPLY, DEST_UNREACH, TIME_EXCEEDED, REDIRECT, CODE, ID, SEQ, GATEWAY, NDP, ROUTER_SOLICIT, ROUTER_ADVERT, NEIGHBOR_SOLICIT, NEIGHBOR_ADVERT, TARGET, SLLA, TLLA, ROUTER_LIFETIME, TTL, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv4 client and router endpoints.
host client_v4 {
    ip 192.168.10.50
    mac 00:50:56:10:00:50
}

// INSTRUCTION: Declare the IPv4 core router.
host router_v4 {
    ip 192.168.10.1
    mac 00:50:56:10:00:01
}

// INSTRUCTION: Declare IPv6 host and router endpoints for ICMPv6 and NDP.
host host_v6 {
    ip 2001:db8:100::50
    mac 00:50:56:60:00:50
}

// INSTRUCTION: Declare the IPv6 first-hop router.
host router_v6 {
    ip 2001:db8:100::1
    mac 00:50:56:60:00:01
}

// INSTRUCTION: Define IPv4 ICMP Echo, Destination Unreachable (Frag Needed Code 4), Time Exceeded, and Redirect.
flow icmpv4_diagnostics(c, r) {
    c -> r icmp echo_request id 1001 seq 1 payload "IPV4_ECHO_PROBE" wait 1ms
    c <- r icmp echo_reply id 1001 seq 1 payload "IPV4_ECHO_PROBE" wait 1ms
    c <- r icmp dest_unreach code 4 payload "PMTUD_NEXT_HOP_MTU_1400" wait 1ms
    c <- r icmp time_exceeded code 0 payload "TRACEROUTE_HOP_EXPIRED" wait 1ms
    c <- r icmp redirect code 1 gateway 192.168.10.254 payload "REDIRECT_TO_OPTIMAL_RTR" wait 1ms
}

// INSTRUCTION: Define IPv6 NDP Router Solicitation/Advertisement, Neighbor Solicitation/Advertisement, and ICMPv6 Ping.
flow ipv6_ndp_and_icmp6(h, r) {
    h -> r ndp router_solicit slla 00:50:56:60:00:50 ttl 255 wait 2ms
    h <- r ndp router_advert slla 00:50:56:60:00:01 router_lifetime 1800 ttl 255 wait 2ms
    h -> r ndp neighbor_solicit target 2001:db8:100::1 slla 00:50:56:60:00:50 ttl 255 wait 2ms
    h <- r ndp neighbor_advert target 2001:db8:100::1 tlla 00:50:56:60:00:01 ttl 255 wait 2ms
    h -> r icmp echo_request id 6001 seq 1 payload "IPV6_ECHO_PROBE" wait 1ms
    h <- r icmp echo_reply id 6001 seq 1 payload "IPV6_ECHO_PROBE" wait 1ms
}

// INSTRUCTION: Compile both IPv4 ICMP diagnostics and IPv6 NDP/ICMPv6 flows.
compile {
    icmpv4_diagnostics(client_v4, router_v4)
    ipv6_ndp_and_icmp6(host_v6, router_v6)
}
```

---

## 4. Multicast Group Management (`IGMP` & `MLD`)

### 4.1 Canonical `IGMP` and `MLD` Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`IGMP`** | `QUERY` / `REPORT` / `LEAVE` | Flag (0-arg) | IGMP Membership Query (`0x11`), Report (`0x12`/`0x16`/`0x22`), or Leave (`0x17`) |
| **`IGMP`** | `V1` / `V2` / `V3` or `VERSION <1..3>` | Flag or `u8` | Selects IGMPv1 (`0x12`, RFC 1112), IGMPv2 (`0x16`, RFC 2236), or IGMPv3 (`0x22`, RFC 3376) |
| **`IGMP`** | `GROUP <ipv4>` | IPv4 multicast | Multicast group address (e.g. `239.1.1.100`) |
| **`IGMP`** | `MAX_RESP <u8>` | `u8` | Maximum Response Time in $1/10$ths of a second (default `100` = 10s) |
| **`MLD`** | `QUERY` / `REPORT` / `DONE` | Flag (0-arg) | ICMPv6 MLD Query (`130`), Report (`131`/`143`), or Done (`132`) |
| **`MLD`** | `MULTICAST_ADDR <ipv6>` | IPv6 multicast | Target IPv6 multicast group address (e.g. `ff3e::8000:1`) |
| **`MLD`** | `MAX_RESP_DELAY <u16>` | `u16` | Maximum response delay in milliseconds |

### 4.2 Verified `IGMP` and `MLD` Example

```frameassembly
// PROMPT: IPv4 IGMPv2/v3 and IPv6 MLD multicast group query, join report, and leave lifecycle.
// TOKENS: HOST, IP, MAC, FLOW, IGMP, QUERY, REPORT, LEAVE, VERSION, GROUP, MAX_RESP, MLD, DONE, MULTICAST_ADDR, MAX_RESP_DELAY, TTL, WAIT, COMPILE

// INSTRUCTION: Declare IPv4 multicast querier router and IPTV receiver.
host mcast_router_v4 {
    ip 10.40.1.1
    mac 00:1c:73:40:01:01
}

// INSTRUCTION: Declare IPv4 IPTV receiver host.
host iptv_stb_v4 {
    ip 10.40.1.50
    mac 00:1c:73:40:01:50
}

// INSTRUCTION: Declare IPv6 MLD querier router and subscriber host.
host mld_router_v6 {
    ip fe80::1
    mac 00:1c:73:60:01:01
}

// INSTRUCTION: Declare IPv6 multicast listener host.
host mld_listener_v6 {
    ip fe80::50
    mac 00:1c:73:60:01:50
}

// INSTRUCTION: Define IPv4 IGMPv3 query, IGMPv2 report, and leave sequence with TTL 1.
flow igmp_group_lifecycle(rtr, stb) {
    rtr -> stb igmp version 3 query group 239.255.1.1 max_resp 100 ttl 1 wait 2ms
    rtr <- stb igmp version 2 report group 239.255.1.1 ttl 1 wait 2ms
    rtr <- stb igmp version 2 leave group 239.255.1.1 ttl 1 wait 2ms
}

// INSTRUCTION: Define IPv6 MLD query, report, and done teardown with Hop Limit 1.
flow mld_group_lifecycle(rtr6, host6) {
    rtr6 -> host6 mld query multicast_addr ff3e::100 max_resp_delay 1000 ttl 1 wait 2ms
    rtr6 <- host6 mld report multicast_addr ff3e::100 ttl 1 wait 2ms
    rtr6 <- host6 mld done multicast_addr ff3e::100 ttl 1 wait 2ms
}

// INSTRUCTION: Compile both IPv4 IGMP and IPv6 MLD flows.
compile {
    igmp_group_lifecycle(mcast_router_v4, iptv_stb_v4)
    mld_group_lifecycle(mld_router_v6, mld_listener_v6)
}
```

---

## 5. Overlay & Underlay Tunneling (`GRE`, `VXLAN`, `GENEVE`)

### 5.1 Canonical Tunneling Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`GRE`** | `GRE_KEY <u32>` | `u32` | Sets RFC 2890 Key Present bit (`0x2000`) and 32-bit Tunnel Key |
| **`GRE`** | `GRE_SEQ <u32>` or `SEQ <u32>` | `u32` | Sets RFC 2890 Sequence Number Present bit (`0x1000`) and 32-bit sequence |
| **`GRE`** | `GRE_PROTO <u16>` | `u16` | Inner encapsulated EtherType (`0x0800` IPv4, `0x86DD` IPv6, `0x6558` TEB) |
| **`GRE`** | `CHECKSUM` | Flag (0-arg) | Sets RFC 2784 Checksum Present bit (`0x8000`) and computes 16-bit one's-complement GRE checksum |
| **`VXLAN`** | `VNI <u24>` or `VNID <u24>` | `u32` (`0..16777215`) | 24-bit VNI on UDP port `4789` (synthesizes a 42-byte inner Ethernet + IPv4 + UDP frame when payload is empty) |
| **`GENEVE`**| `VNI <u24>` or `VNID <u24>` | `u32` (`0..16777215`) | 24-bit VNI on UDP port `6081` (synthesizes a 42-byte inner Ethernet + IPv4 + UDP frame when payload is empty) |
| **`GENEVE`**| `OPT_CLASS <u16>` / `OPT_TYPE <u8>` | `u16`, `u8` | Extensible Geneve TLV Option Class (e.g. `0x0102` OVN/Cilium) and Type |
| **`GENEVE`**| `PROTOCOL_TYPE <u16>` | `u16` | Inner EtherType (`0x6558` Transparent Ethernet Bridging, `0x0800` IPv4) |

### 5.2 Verified `GRE`, `VXLAN`, and `GENEVE` Example

```frameassembly
// PROMPT: Data center and WAN overlay encapsulation across GRE (RFC 2890), VXLAN (RFC 7348), and Geneve (RFC 8926).
// TOKENS: HOST, IP, MAC, FLOW, GRE, GRE_KEY, GRE_SEQ, GRE_PROTO, CHECKSUM, VXLAN, VNI, GENEVE, OPT_CLASS, OPT_TYPE, PROTOCOL_TYPE, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare VTEP / Tunnel Endpoint Alpha.
host vtep_alpha {
    ip 10.200.0.1
    mac 00:1c:73:c0:00:01
}

// INSTRUCTION: Declare VTEP / Tunnel Endpoint Beta.
host vtep_beta {
    ip 10.200.0.2
    mac 00:1c:73:c0:00:02
}

// INSTRUCTION: Define GRE key/sequence/checksum tunneling, VXLAN VNI 10500, and Geneve TLV metadata overlay.
flow overlay_tunnels_showcase(vtep_a, vtep_b) {
    vtep_a -> vtep_b gre gre_key 50010 gre_seq 1 gre_proto 0x0800 checksum payload "INNER_GRE_ROUTED_PACKET" wait 1ms
    vtep_a <- vtep_b gre gre_key 50010 gre_seq 2 gre_proto 0x0800 checksum payload "INNER_GRE_RETURN_PACKET" wait 1ms
    vtep_a -> vtep_b vxlan vni 10500 payload "EVPN_VXLAN_L2_TENANT_FRAME" wait 1ms
    vtep_a <- vtep_b vxlan vni 10500 payload "EVPN_VXLAN_L2_RETURN_FRAME" wait 1ms
    vtep_a -> vtep_b geneve vni 20800 opt_class 0x0102 opt_type 1 protocol_type 0x6558 payload "CILIUM_EBPF_SECURITY_IDENTITY_FRAME" wait 1ms
}

// INSTRUCTION: Compile the overlay tunnel encapsulation capture.
compile {
    overlay_tunnels_showcase(vtep_alpha, vtep_beta)
}
```

---

## 6. Cryptographic VPNs & Key Exchange (`IKEV2`, `IPSEC`, `ESP`, `AH`, `WIREGUARD`)

### 6.1 Canonical VPN & Security Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`IKEV2`** | `SA_INIT` / `CREATE_CHILD_SA` / `INFORMATIONAL` | Flag (0-arg) | RFC 7296 Exchange Type (`34` = IKE_SA_INIT, `36` = CREATE_CHILD_SA, `37` = INFO) |
| **`IKEV2`** | `INITIATOR_SPI <u64>` / `RESPONDER_SPI <u64>` | `u64` | 64-bit IKEv2 Security Parameter Indexes |
| **`IKEV2`** | `MSGID <u32>` / `NEXT_PAYLOAD <u8>` | `u32`, `u8` | IKEv2 Message ID and first payload type (`33` = SA, `46` = SK) |
| **`IPSEC` / `ESP` / `AH`** | `SPI <u32>` / `SEQ <u32>` | `u32`, `u32` | 32-bit Security Parameter Index and anti-replay sequence number |
| **`IPSEC` / `ESP`** | `IV "<hex>"` / `ICV "<hex>"` | Quoted hex string | Initialization Vector and Integrity Check Value hex bytes |
| **`ESP` / `AH`** | `NEXT_HEADER <u8>` | `u8` | Protected inner IP protocol (`4` = IPv4-in-IPsec, `6` = TCP, `41` = IPv6) |
| **`WIREGUARD`** | `TYPE <INITIATION\|RESPONSE\|COOKIE\|DATA>` | Keyword | Noise_IKpsk2 message type (`1` = Init, `2` = Resp, `3` = Cookie, `4` = Data with 16-byte Poly1305 AEAD tag, `>= 32` bytes total) |
| **`WIREGUARD`** | `SENDER <u32>` / `RECEIVER <u32>` / `COUNTER <u64>`| `u32`, `u32`, `u64` | WireGuard peer index numbers and ChaCha20-Poly1305 nonce counter |

### 6.2 Verified `IKEV2`, `ESP`, `AH`, and `WIREGUARD` Example

```frameassembly
// PROMPT: Site-to-site IPsec VPN (IKEv2 SA_INIT, ESP, AH) alongside a WireGuard Noise_IKpsk2 tunnel session.
// TOKENS: HOST, IP, MAC, FLOW, IKEV2, SA_INIT, CREATE_CHILD_SA, INFORMATIONAL, INITIATOR_SPI, RESPONDER_SPI, MSGID, NEXT_PAYLOAD, ESP, AH, IPSEC, SPI, SEQ, IV, ICV, NEXT_HEADER, WIREGUARD, TYPE, INITIATION, RESPONSE, COOKIE, DATA, SENDER, RECEIVER, COUNTER, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Branch VPN Gateway.
host vpn_branch {
    ip 198.51.100.10
    mac 00:50:56:a0:00:10
}

// INSTRUCTION: Declare Headquarters VPN Concentrator.
host vpn_hq {
    ip 203.0.113.1
    mac 00:50:56:a0:00:01
}

// INSTRUCTION: Define IKEv2 negotiation followed by IPsec ESP, IPsec AH, and generic IPSEC frames.
flow ipsec_ikev2_suite(branch, hq) {
    branch -> hq ikev2 sa_init initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x0000000000000000 msgid 0 next_payload 33 wait 2ms
    branch <- hq ikev2 sa_init initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x9988776655440002 msgid 0 next_payload 33 wait 2ms
    branch -> hq ikev2 create_child_sa initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x9988776655440002 msgid 1 next_payload 46 wait 2ms
    branch -> hq esp spi 0x10002001 seq 1 iv "1122334455667788" icv "aabbccddeeff001122334455" next_header 4 payload "AES_GCM_CIPHERTEXT" wait 1ms
    branch <- hq ah spi 0x20003002 seq 1 icv "99887766554433221100ffeeddcc" next_header 4 payload "AUTHENTICATED_IP_PACKET" wait 1ms
    branch -> hq ipsec spi 0x10002001 seq 2 iv "8877665544332211" icv "00112233445566778899aabb" wait 1ms
    branch <- hq ikev2 informational initiator_spi 0xa1b2c3d4e5f60001 responder_spi 0x9988776655440002 msgid 2 next_payload 46 wait 1ms
}

// INSTRUCTION: Define a complete WireGuard handshake initiation, response, cookie reply, and encrypted data transport.
flow wireguard_tunnel_lifecycle(branch, hq) {
    branch -> hq wireguard type initiation sender 0x10203040 payload "WG_NOISE_EPHEMERAL_STATIC_TIMESTAMP" wait 1ms
    branch <- hq wireguard type cookie receiver 0x10203040 payload "WG_DOS_MITIGATION_MAC2_COOKIE" wait 1ms
    branch <- hq wireguard type response sender 0x50607080 receiver 0x10203040 payload "WG_EPHEMERAL_EMPTY_TAG" wait 1ms
    branch -> hq wireguard type data receiver 0x50607080 counter 1 payload "CHACHA20_POLY1305_TRANSPORT_DATA" wait 1ms
}

// INSTRUCTION: Compile both the IPsec/IKEv2 suite and WireGuard tunnel lifecycle.
compile {
    ipsec_ikev2_suite(vpn_branch, vpn_hq)
    wireguard_tunnel_lifecycle(vpn_branch, vpn_hq)
}
```

---

## 7. Dynamic Routing Protocols (`OSPF`, `BGP`, `RIP`, `PIM`)

### 7.1 Canonical Routing Protocol Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`OSPF`** | `HELLO` / `DBD` / `LSR` / `LSU` / `LSACK` | Flag (0-arg) | OSPF Packet Types `1`..`5` (IP Protocol `89`) |
| **`OSPF`** | `ROUTER_ID <ipv4>` / `AREA_ID <u32>` | IPv4, `u32` | 32-bit OSPF Router ID and integer Area ID (e.g. `AREA_ID 0` for Backbone) |
| **`OSPF`** | `HELLO_INTERVAL <u16>` / `DEAD_INTERVAL <u32>` | `u16`, `u32` | Hello timer (default `10`s) and Dead timer (default `40`s) |
| **`BGP`** | `OPEN` / `UPDATE` / `NOTIFICATION` / `KEEPALIVE`| Flag (0-arg) | BGP-4 Message Types `1`..`4` over TCP port `179` |
| **`BGP`** | `ASN <u32>` / `HOLDTIME <u16>` / `BGPID <ipv4>` | `u32`, `u16`, IPv4| Autonomous System Number, Hold Time, and 32-bit BGP Identifier |
| **`BGP`** | `PREFIX "<cidr>"` / `NEXTHOP <ip>` | String, IP | Encodes NLRI prefix (`PREFIX`) and Path Attribute Type 3 (`NEXT_HOP`) in `UPDATE` messages |
| **`RIP`** | `PREFIX <ipv4>` / `NEXTHOP <ipv4>` | IPv4, IPv4 | RIPv2 Route Entry destination IPv4 address and Next Hop |
| **`RIP`** | `METRIC <u32>` / `TAG <u16>` | `u32`, `u16` | Hop count metric (`1..16`, `16` = infinity) and external route tag |
| **`PIM`** | `HELLO` / `JOIN_PRUNE` / `REGISTER` | Flag (0-arg) | PIM-SM control message types (IP Protocol `103`) |
| **`PIM`** | `GROUP <ip>` / `SOURCE <ip>` / `RP <ip>` | IP literal | Multicast Group `(S,G)`, Source address, and Rendezvous Point |
| **`PIM`** | `HOLDTIME <u16>` / `DR_PRIORITY <u32>` | `u16`, `u32` | PIM Neighbor Holdtime and Designated Router election priority |

> **Important Syntax Rule**: In `OSPF`, `AREA_ID` takes an integer `<u32>` (such as `AREA_ID 0` for Area `0.0.0.0`, or `AREA_ID 10`), never an IPv4 dotted quad. In `RIP`, `PREFIX` takes an IPv4 address literal (e.g. `PREFIX 10.20.0.0`), while in `BGP`, `PREFIX` takes a quoted CIDR string (e.g. `PREFIX "10.20.0.0/16"`).

### 7.2 Verified `OSPF`, `BGP`, `RIP`, and `PIM` Example

```frameassembly
// PROMPT: Core routing convergence combining OSPFv2 adjacency formation, eBGP prefix exchange, RIPv2 updates, and PIM-SM multicast trees.
// TOKENS: HOST, IP, MAC, FLOW, OSPF, HELLO, DBD, LSR, LSU, LSACK, ROUTER_ID, AREA_ID, HELLO_INTERVAL, DEAD_INTERVAL, BGP, OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ASN, HOLDTIME, BGPID, PREFIX, NEXTHOP, RIP, METRIC, TAG, PIM, JOIN_PRUNE, REGISTER, GROUP, SOURCE, RP, DR_PRIORITY, TTL, WAIT, COMPILE

// INSTRUCTION: Declare Core Router 1.
host core_rtr1 {
    ip 10.0.0.1
    mac 00:1c:73:00:00:01
}

// INSTRUCTION: Declare Core Router 2.
host core_rtr2 {
    ip 10.0.0.2
    mac 00:1c:73:00:00:02
}

// INSTRUCTION: Define full OSPF 5-packet adjacency synchronization and PIM-SM multicast tree join.
flow igp_ospf_and_pim(r1, r2) {
    r1 -> r2 ospf hello router_id 1.1.1.1 area_id 0 hello_interval 10 dead_interval 40 ttl 1 wait 1ms
    r1 <- r2 ospf hello router_id 2.2.2.2 area_id 0 hello_interval 10 dead_interval 40 ttl 1 wait 1ms
    r1 -> r2 ospf dbd router_id 1.1.1.1 area_id 0 ttl 1 wait 1ms
    r1 <- r2 ospf lsr router_id 2.2.2.2 area_id 0 ttl 1 wait 1ms
    r1 -> r2 ospf lsu router_id 1.1.1.1 area_id 0 ttl 1 wait 1ms
    r1 <- r2 ospf lsack router_id 2.2.2.2 area_id 0 ttl 1 wait 1ms
    r1 -> r2 pim hello holdtime 105 dr_priority 100 ttl 1 wait 1ms
    r1 <- r2 pim join_prune group 239.10.10.1 source 10.1.1.10 rp 10.0.0.1 ttl 1 wait 1ms
    r1 -> r2 pim register group 239.10.10.1 source 10.1.1.10 rp 10.0.0.1 ttl 64 wait 1ms
}

// INSTRUCTION: Define eBGP session establishment, NLRI update, keepalive, and RIPv2 route advertisement.
flow bgp_and_rip_exchange(r1, r2) {
    r1 -> r2 bgp open asn 65001 holdtime 90 bgpid 1.1.1.1 ttl 255 wait 1ms
    r1 <- r2 bgp open asn 65002 holdtime 90 bgpid 2.2.2.2 ttl 255 wait 1ms
    r1 -> r2 bgp keepalive ttl 255 wait 1ms
    r1 <- r2 bgp update prefix "172.16.0.0/12" nexthop 10.0.0.2 ttl 255 wait 1ms
    r1 -> r2 bgp notification ttl 255 wait 1ms
    r1 -> r2 rip prefix 192.168.50.0 nexthop 10.0.0.1 metric 2 tag 100 ttl 2 wait 1ms
}

// INSTRUCTION: Compile the dynamic routing protocols convergence capture.
compile {
    igp_ospf_and_pim(core_rtr1, core_rtr2)
    bgp_and_rip_exchange(core_rtr1, core_rtr2)
}
```

---

## 8. First-Hop Redundancy, Fast Failover & SDN (`VRRP`, `HSRP`, `BFD`, `OPENFLOW`)

### 8.1 Canonical FHRP, BFD, and OpenFlow Modifiers

| Protocol | Modifier Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **`VRRP`** | `VERSION <2\|3>` / `VRID <u8>` | `u8`, `u8` | VRRP version (default `3` with RFC 5798 pseudo-header checksum and default TTL/Hop Limit `255`; `2` uses RFC 3768 message checksum) and Virtual Router ID (`1..255`) |
| **`VRRP`** | `PRIORITY <u16>` / `ADV_INT <u16>` / `VIP <ip>` | `u16`, `u16`, IP | Election priority (`255` = owner, `100` = default), advertisement interval, virtual IP |
| **`HSRP`** | `GROUP <u8>` / `PRIORITY <u16>` / `STATE <u8>` | `u8`, `u16`, `u8` | HSRP group ID, priority, and state (`16` = Active, `8` = Standby) |
| **`HSRP`** | `HELLOTIME <u8>` / `HOLDTIME <u16>` / `VIP <ip>`| `u8`, `u16`, IP | Hello interval (`3`s), Hold time (`10`s), and Virtual IP |
| **`BFD`** | `STATE <u8>` / `DIAG <u8>` / `MULT <u8>` | `u8` | BFD state (`3` = Up, `2` = Init, `1` = Down) and detection multiplier |
| **`BFD`** | `MY_DISC <u32>` / `YOUR_DISC <u32>` | `u32`, `u32` | Local and remote 32-bit BFD session discriminators |
| **`BFD`** | `MIN_TX <u32>` / `MIN_RX <u32>` | `u32`, `u32` | Desired Minimum TX and Required Minimum RX intervals in microseconds |
| **`OPENFLOW`**| `FEATURES_REQ` / `FEATURES_REPLY` / `PACKET_IN` / `PACKET_OUT` / `FLOW_MOD` / `ECHO_REQ` / `ECHO_REPLY` | Flag (0-arg) | OpenFlow 1.3 control channel message types on TCP port `6653` |
| **`OPENFLOW`**| `VERSION <u8>` / `XID <u32>` / `DPID <u64>` / `TABLE <u8>` or `TABLE_ID <u8>` / `PRIORITY <u16>` | Integer | OpenFlow protocol version (`4` = v1.3), transaction ID, Datapath ID, table ID, priority |

### 8.2 Verified `VRRP`, `HSRP`, `BFD`, and `OPENFLOW` Example

```frameassembly
// PROMPT: Gateway high availability (VRRP, HSRP), sub-second BFD failure detection, and SDN OpenFlow 1.3 flow installation.
// TOKENS: HOST, IP, MAC, FLOW, VRRP, VERSION, VRID, PRIORITY, ADV_INT, VIP, HSRP, GROUP, STATE, HELLOTIME, HOLDTIME, BFD, DIAG, MY_DISC, YOUR_DISC, MIN_TX, MIN_RX, MULT, OPENFLOW, FEATURES_REQ, FEATURES_REPLY, PACKET_IN, FLOW_MOD, PACKET_OUT, ECHO_REQ, ECHO_REPLY, XID, DPID, TABLE_ID, TTL, WAIT, COMPILE

// INSTRUCTION: Declare Primary Gateway / SDN Switch.
host gw_primary {
    ip 10.10.0.2
    mac 00:00:5e:00:01:0a
}

// INSTRUCTION: Declare Secondary Gateway / SDN Controller.
host gw_secondary {
    ip 10.10.0.3
    mac 00:00:0c:07:ac:0a
}

// INSTRUCTION: Define VRRPv3 active advertisement, HSRPv1 active/standby election, and 50ms BFD echo liveness.
flow fhrp_and_bfd_ha(pri, sec) {
    pri -> sec vrrp version 3 vrid 10 priority 200 adv_int 1 vip 10.10.0.1 ttl 255 wait 1ms
    pri -> sec hsrp group 10 priority 150 state 16 hellotime 3 holdtime 10 vip 10.10.0.254 ttl 1 wait 1ms
    pri <- sec hsrp group 10 priority 100 state 8 hellotime 3 holdtime 10 vip 10.10.0.254 ttl 1 wait 1ms
    pri -> sec bfd state 3 diag 0 my_disc 1001 your_disc 2002 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 1ms
    pri <- sec bfd state 3 diag 0 my_disc 2002 your_disc 1001 min_tx 50000 min_rx 50000 mult 3 ttl 255 wait 1ms
}

// INSTRUCTION: Define SDN OpenFlow 1.3 handshake, Packet-In punt, Flow-Mod rule push, and Echo heartbeat.
flow sdn_openflow_control(sw, ctrl) {
    sw <- ctrl openflow version 4 features_req xid 101 wait 1ms
    sw -> ctrl openflow version 4 features_reply xid 101 dpid 0x0000001c73aabbcc wait 1ms
    sw -> ctrl openflow version 4 packet_in xid 102 table_id 0 wait 1ms
    sw <- ctrl openflow version 4 flow_mod xid 103 table_id 0 priority 1000 wait 1ms
    sw <- ctrl openflow version 4 packet_out xid 104 wait 1ms
    sw -> ctrl openflow version 4 echo_req xid 105 wait 1ms
    sw <- ctrl openflow version 4 echo_reply xid 105 wait 1ms
}

// INSTRUCTION: Compile the FHRP/BFD high-availability and OpenFlow SDN control plane capture.
compile {
    fhrp_and_bfd_ha(gw_primary, gw_secondary)
    sdn_openflow_control(gw_primary, gw_secondary)
}
```
