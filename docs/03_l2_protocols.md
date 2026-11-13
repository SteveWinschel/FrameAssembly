# Layer 2: VLANs, STP, LACP, 802.1X & Label Stacks

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

Layer 2 problems have a talent for happening on the one switch nobody labeled. A forgotten desk switch with a default priority and a lower MAC address wins the Root Bridge election, and the whole floor discovers the 1990s. A laptop NIC quietly strips the 802.1Q tag before `tcpdump` ever sees it, so the capture says the trunk is fine while the trunk is, in fact, not fine. A port-channel sits in `Suspended` and the only clue is an 8-bit state byte.

You can reproduce all of this on your desk. Write the frame as `.frasm` code, compile it with `frameassembly l2_test.frasm`, and replay `l2_test.pcap` onto a trunk with `tcpreplay`. Or go the other way: `frameassembly reverse trace.pcap` turns a capture from a misbehaving switch into `.frasm` code you can edit and replay. Leave out the optional fields and FrameAssembly fills in the Ethernet II or 802.3 LLC header, the right multicast MAC, and every mandatory TLV.

| Protocol | Keyword | Standard | Framing / EtherType | Default Destination MAC |
| :--- | :--- | :--- | :--- | :--- |
| **ARP** | `arp` | RFC 826 / RFC 5227 | Ethernet II (`0x0806`) | `ff:ff:ff:ff:ff:ff` (request), unicast (reply) |
| **VLAN** | `vlan` | IEEE 802.1Q / 802.1p | 802.1Q tag (`0x8100`) | Host or protocol MAC |
| **QinQ** | `qinq` | IEEE 802.1ad | S-Tag (`0x88A8`) + C-Tag (`0x8100`) | Host or protocol MAC |
| **LLDP** | `lldp` | IEEE 802.1AB | Ethernet II (`0x88CC`) | `01:80:c2:00:00:0e` |
| **STP / RSTP** | `stp` | IEEE 802.1D / 802.1w | 802.3 length + 802.2 LLC (`0x424203`) | `01:80:c2:00:00:00` |
| **LACP** | `lacp` | IEEE 802.3ad / 802.1AX | Slow Protocols (`0x8809`) | `01:80:c2:00:00:02` |
| **EAPOL** | `eapol` | IEEE 802.1X / RFC 3748 | Ethernet II (`0x888E`) | `01:80:c2:00:00:03` |
| **MPLS** | `mpls` | RFC 3031 / RFC 3032 | Ethernet II (`0x8847`) | Host or next-hop MAC |

---

## 1. Ethernet MAC Overrides Without Making Your Switch Panic

Every statement in FrameAssembly, whether it is an `arp` request or a `modbus` write, rides inside an Ethernet frame. Three modifiers work on any statement and let you rewrite that outer header: spoof a source MAC, force a broadcast destination, or pick an EtherType the IEEE never imagined.

When you leave them out, FrameAssembly picks the wire MAC for you in this order:

| Priority | Condition | Source MAC | Destination MAC |
| :--- | :--- | :--- | :--- |
| **1. Statement override** | `srcmac` or `dstmac` on the statement | The statement's `srcmac` | The statement's `dstmac` |
| **2. Protocol control group** | `lldp`, `stp`, `lacp`, `eapol`, `arp request` | Host `mac` (or default unicast) | IEEE 802.1D multicast (`01:80:c2:00:00:xx`) or broadcast |
| **3. Multicast target IP** | Destination is IPv4 `224.0.0.0/4` or IPv6 `ff00::/8` | Host `mac` (or default unicast) | RFC 1112 `01:00:5e:xx:xx:xx` (IPv4) or RFC 2464 `33:33:xx:xx:xx:xx` (IPv6) |
| **4. Host declaration** | `host <id> { ip <ip> mac <mac> }` | Sending host's `mac` | Receiving host's `mac` |
| **5. Unicast fallback** | Host `mac` omitted on a unicast IP | `00:00:00:00:00:01` forward, `00:00:00:00:00:02` reverse | `00:00:00:00:00:02` forward, `00:00:00:00:00:01` reverse |

The fallback in row 5 is direction-aware on purpose. Forward and reverse statements swap the two default MACs, so a capture replayed through a real switch looks like two stations talking instead of one MAC-address shape-shifter. Your CAM table stays quiet and nobody opens a MAC-flap ticket about your lab.

```frameassembly
host sensor_a { ip 10.10.1.10 mac 00:1b:21:aa:bb:01 }
host sensor_b { ip 10.10.1.20 mac 00:1b:21:aa:bb:02 }

flow custom_ethernet_framing(a, b) {
    // Normal unicast UDP frame using the MACs from the host blocks
    a -> b udp srcport 40000 dstport 40000 payload "NORMAL_UNICAST" wait 1ms

    // Spoofed source MAC, broadcast destination, EtherType 0x88b5 (IEEE local experimental)
    a -> b udp srcport 40000 dstport 40000 srcmac de:ad:be:ef:00:01 dstmac ff:ff:ff:ff:ff:ff ethertype 0x88b5 payload "CUSTOM_L2_ETHERTYPE"
}

compile {
    custom_ethernet_framing(sensor_a, sensor_b)
}
```

All 8 Layer 2 protocols also accept **MAC-only hosts**. No `ip` needed, and you can write statements straight into `compile { ... }` when a reusable `flow` would be overkill:

```frameassembly
host sw1 { mac 00:1c:73:00:00:01 }
host sw2 { mac 00:1c:73:00:00:02 }

compile {
    sw1 -> sw2 lldp chassisid "00:1c:73:00:00:01" portid "Ethernet1/1" ttl 120 sysname "spine-01" wait 2ms
    sw1 <- sw2 stp rstp rootid "4096/00:1c:73:00:00:02" bridgeid "4096/00:1c:73:00:00:02" portid 0x8001 cost 0 flags 0x3c wait 2ms
    sw1 -> sw2 lacp actorsys 00:1c:73:00:00:01 actorkey 10 actorport 1 actorstate 0x3f partnersys 00:1c:73:00:00:02 partnerkey 10 partnerport 1 partnerstate 0x3f
}
```

### Modifier & Wire Cheat-Sheet: Ethernet Header

| Modifier | Syntax | Value Format | Effect |
| :--- | :--- | :--- | :--- |
| **Source MAC** | `srcmac <mac>` | `aa:bb:cc:dd:ee:ff` | Overrides the Ethernet source MAC for this one frame |
| **Destination MAC** | `dstmac <mac>` | `aa:bb:cc:dd:ee:ff` | Overrides the Ethernet destination MAC for this one frame |
| **EtherType** | `ethertype <0..65535>` | Hex (`0x88cc`) or decimal | Overrides the 16-bit EtherType in front of the inner payload |
| **Host MAC** | `host <id> { mac <mac> }` | `00:1a:2b:3c:4d:5e`, `00-1A-2B-3C-4D-5E`, or `001a.2b3c.4d5e` | Sets the default wire MAC for every statement from that host |

---

## 2. Gratuitous `arp` Failover & Dynamic ARP Inspection Probes

A firewall pair fails over, the standby grabs the gateway VIP, and half the subnet keeps sending traffic to the dead unit's MAC for the next four minutes. The cause is almost always a Gratuitous ARP that was lost, rate-limited, or filtered by Dynamic ARP Inspection (`DAI`). With `arp` you can send the exact announcement, watch whether DAI drops it, and do it without pulling a cable out of a production firewall.

**Wire behavior over IPv4 (`0x0806`):** a 28-byte ARP header (`HTYPE 1`, `PTYPE 0x0800`, `HLEN 6`, `PLEN 4`).

* `arp request` (default): Opcode `1`, broadcast destination, `tha` zeroed.
* `arp reply`: Opcode `2`, destination is the target host's unicast MAC, `tha` is the target's MAC.
* `gratuitous` (or `garp`): `tpa` equals `spa`, `tha` zeroed.

**Wire behavior over IPv6 (`0x86DD`):** run the same `arp` flow with IPv6 hosts and FrameAssembly emits RFC 4861 ICMPv6 Neighbor Discovery with Hop Limit `255`. A request becomes a Neighbor Solicitation (Type `135`, Source Link-Layer Address option) sent to the solicited-node multicast address and MAC `33:33:ff:xx:xx:xx`. A reply becomes a Neighbor Advertisement (Type `136`, Solicited + Override `0x60`, Target Link-Layer Address option).

Gateway resolution plus an RFC 5227 duplicate address probe (sender IP `0.0.0.0`):

```frameassembly
host workstation { ip 192.168.10.55  mac 00:50:56:a1:10:55 }
host fw_active   { ip 192.168.10.1   mac 00:50:56:fe:00:01 }
host lan_bcast   { ip 192.168.10.255 mac ff:ff:ff:ff:ff:ff }

flow gateway_lookup_and_probe(client, gw, bcast) {
    // "Who has 192.168.10.1?" broadcast, then the unicast answer
    client -> gw arp request dstmac ff:ff:ff:ff:ff:ff tha 00:00:00:00:00:00 wait 1ms
    client <- gw arp reply wait 5ms

    // RFC 5227 probe: sender IP 0.0.0.0, asking whether 192.168.10.55 is already taken
    client -> bcast arp request sendermac 00:50:56:a1:10:55 senderip 0.0.0.0 targetmac 00:00:00:00:00:00 targetip 192.168.10.55
}

compile { gateway_lookup_and_probe(workstation, fw_active, lan_bcast) }
```

The standby takes over the VIP and announces it:

```frameassembly
host fw_standby { ip 192.168.10.2   mac 00:50:56:fe:00:02 }
host lan_bcast  { ip 192.168.10.255 mac ff:ff:ff:ff:ff:ff }

flow vip_takeover(sec, bcast) {
    // Standby claims 192.168.10.1 with its own MAC. DAI should have an opinion about this.
    sec -> bcast arp reply gratuitous sendermac 00:50:56:fe:00:02 senderip 192.168.10.1 targetmac ff:ff:ff:ff:ff:ff targetip 192.168.10.1
}

compile { vip_takeover(fw_standby, lan_bcast) }
```

One `flow`, both address families. The IPv4 pair produces ARP, the IPv6 pair produces Neighbor Discovery:

```frameassembly
host app_v4 { ip 10.20.0.10      mac 00:16:3e:10:00:10 }
host gw_v4  { ip 10.20.0.1       mac 00:16:3e:10:00:01 }
host app_v6 { ip 2001:db8:20::10 mac 00:16:3e:60:00:10 }
host gw_v6  { ip 2001:db8:20::1  mac 00:16:3e:60:00:01 }

flow neighbor_lookup(host_ep, router_ep) {
    host_ep -> router_ep arp request wait 1ms
    host_ep <- router_ep arp reply
}

compile {
    neighbor_lookup(app_v4, gw_v4)
    neighbor_lookup(app_v6, gw_v6)
}
```

```console
$ frameassembly arp_test.frasm
$ tshark -r arp_test.pcap -Y "arp or icmpv6" -T fields -e frame.number -e eth.src -e eth.dst -e arp.opcode -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4
```

### Modifier & Wire Cheat-Sheet: `arp`

| Modifier | Syntax & Aliases | Wire Field | Default When Omitted |
| :--- | :--- | :--- | :--- |
| **Request opcode** | `request` | `OPER = 1` | `request` |
| **Reply opcode** | `reply` | `OPER = 2` | `request` |
| **Gratuitous flag** | `gratuitous` or `garp` | `tpa = spa`, `tha = 00:00:00:00:00:00` | Disabled |
| **Sender MAC** | `sha <mac>` or `sendermac <mac>` | Sender Hardware Address in the ARP payload | Sending host's MAC |
| **Sender IP** | `spa <ipv4>` or `senderip <ipv4>` | Sender Protocol Address (`0.0.0.0` for RFC 5227 probes) | Sending host's IPv4 |
| **Target MAC** | `tha <mac>` or `targetmac <mac>` | Target Hardware Address in the ARP payload | `00:00:00:00:00:00` (request), destination MAC (reply) |
| **Target IP** | `tpa <ipv4>` or `targetip <ipv4>` | Target Protocol Address (the IP being queried or claimed) | Receiving host's IPv4 |

---

## 3. Trunking: `vlan`, `qinq` & `mpls` Label Stacks

The trunk looks healthy until the carrier's S-tag meets your customer's C-tag and the MTU math goes sideways. Or the voice VLAN arrives with `pcp 0` because one policy map forgot a class. Or a provider-edge router needs MPLS labels, and you would rather not build a BGP label-distribution lab just to see four bytes of shim header.

`vlan`, `qinq`, and `mpls` each work two ways:

1. **As a modifier on any statement.** Put `vlan <vid>`, `qinq <svid> innervlan <cvid>`, or `mpls <label>` in front of `arp`, `stp`, `ospf`, `bgp`, `tcp`, `udp`, `http`, `sip`, `modbus`, or anything else, and the tags are inserted ahead of the inner packet. They stack: `vlan` or `qinq` outside, `mpls` inside.
2. **As a standalone statement.** A statement that is only `vlan 100`, `qinq 2000 innervlan 100`, or `mpls 16001`, with no upper-layer keyword, emits a tagged frame carrying a default IP + UDP packet, or raw bytes if you add `payload` or `hexpayload`.

Two rules the validator enforces: VLAN IDs run `1..4094` (`0` is priority-tagged and `4095` is reserved, so `vlan 0` and `vlan 4095` are rejected), and a statement takes either `qinq` or `vlan`, never both.

An 802.1Q trunk carrying three traffic classes (voice, lossless storage, scavenger backup):

```frameassembly
host tor_sw_a { ip 172.16.10.1 mac 00:1c:73:10:00:01 }
host tor_sw_b { ip 172.16.10.2 mac 00:1c:73:10:00:02 }

flow trunk_cos_mix(a, b) {
    // VLAN 10: voice, PCP 5, DSCP 46 (EF)
    a -> b vlan 10 pcp 5 dei 0 dscp 46 rtp seq 101 timestamp 16000 ssrc 0x11223344 payload "G711_PCMU_FRAME" wait 1ms

    // VLAN 20: RoCEv2 lossless queue, PCP 3, DSCP 26 (AF31)
    a -> b vlan 20 pcp 3 dei 0 dscp 26 udp srcport 51000 dstport 4791 payload "RDMA_WRITE_ONLY" wait 1ms

    // VLAN 99: backup traffic marked drop-eligible, PCP 1, DEI 1, DSCP 8 (CS1)
    a -> b vlan 99 pcp 1 dei 1 dscp 8 tcp psh ack srcport 49152 dstport 873 payload "RSYNC_SNAPSHOT_CHUNK"
}

compile { trunk_cos_mix(tor_sw_a, tor_sw_b) }
```

A carrier 802.1ad handoff: S-VLAN 2500 outside, the customer's C-VLAN 40 inside, an eBGP session riding in it:

```frameassembly
host cpe_site_a { ip 10.100.40.1 mac 00:50:56:ce:40:01 }
host cpe_site_b { ip 10.100.40.2 mac 00:50:56:ce:40:02 }

flow metro_qinq_handoff(a, b) {
    a -> b qinq 2500 innervlan 40 pcp 6 dscp 48 tcp syn srcport 53000 dstport 179 wait 1ms
    a <- b qinq 2500 innervlan 40 pcp 6 dscp 48 tcp syn ack wait 1ms
    a -> b qinq 2500 innervlan 40 pcp 6 dscp 48 tcp ack wait 1ms
    a -> b qinq 2500 innervlan 40 pcp 6 dscp 48 bgp open asn 65100 holdtime 90 bgpid 10.100.40.1 wait 2ms
    a <- b qinq 2500 innervlan 40 pcp 6 dscp 48 bgp open asn 65200 holdtime 90 bgpid 10.100.40.2
}

compile { metro_qinq_handoff(cpe_site_a, cpe_site_b) }
```

An MPLS label is one 32-bit shim entry:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Label                  | EXP |S|       TTL     |
|               (20 bits)               |(3b) |1|    (8 bits)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

L3VPN-style labeled ping, then an SR-MPLS HTTPS flow on a VLAN subinterface:

```frameassembly
host pe_west { ip 10.100.1.1 mac 00:1c:73:ce:00:01 }
host pe_east { ip 10.100.1.2 mac 00:1c:73:ce:00:02 }

flow mpls_l3vpn_and_sr(west, east) {
    // Label 24010, EXP 5 (voice), MPLS TTL 64, inner IP TTL 63
    west -> east mpls 24010 exp 5 bos 1 mplsttl 64 ttl 63 dscp 46 icmp echorequest id 501 seq 1 payload "L3VPN_PING" wait 1ms
    west <- east mpls 24020 tc 5 bos 1 mplsttl 63 ttl 62 dscp 46 icmp echoreply id 501 seq 1 payload "L3VPN_PONG" wait 2ms

    // 802.1Q VLAN 400 subinterface carrying an SR-MPLS labeled TCP handshake
    west -> east vlan 400 pcp 5 mpls 16005 exp 5 bos 1 mplsttl 255 tcp syn srcport 51200 dstport 443 wait 1ms
    west <- east vlan 400 pcp 5 mpls 16001 exp 5 bos 1 mplsttl 254 tcp syn ack
}

compile { mpls_l3vpn_and_sr(pe_west, pe_east) }
```

```console
$ frameassembly trunk_test.frasm
$ tshark -r trunk_test.pcap -T fields -e frame.number -e eth.type -e vlan.id -e vlan.prio -e vlan.dei -e mpls.label -e mpls.exp -e mpls.bottom -e mpls.ttl -e ip.src -e ip.dst
```

### Modifier & Wire Cheat-Sheet: `vlan`, `qinq`, `mpls`

| Protocol | Modifier | Syntax & Aliases | Range | Wire Field | Default |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `vlan` | **VLAN ID** | `vlan <1..4094>` | `1..4094` | 802.1Q tag, `TPID 0x8100`, 12-bit VID | `1` (bare `vlan`) |
| `vlan` / `qinq` | **Priority (CoS)** | `pcp <0..7>` | `0..7` | 3-bit 802.1p Priority Code Point in the TCI | `0` |
| `vlan` / `qinq` | **Drop Eligible** | `dei <0..1>` | `0..1` | 1-bit DEI (`1` = drop first under congestion) | `0` |
| `qinq` | **Outer service VLAN** | `qinq <1..4094>` | `1..4094` | 802.1ad S-Tag, `TPID 0x88A8` | `1` (bare `qinq`) |
| `qinq` | **Inner customer VLAN** | `innervlan <1..4094>` | `1..4094` | 802.1Q C-Tag, `TPID 0x8100`, inside `qinq` | `2` (standalone) |
| `mpls` | **Label** | `mpls <0..1048575>` or `label <0..1048575>` | `0..1048575` | 20-bit label (`0` IPv4 Explicit Null, `2` IPv6 Explicit Null, `3` Implicit Null, `16+` L3VPN / SR-MPLS) | `0` |
| `mpls` | **Traffic Class** | `exp <0..7>` or `tc <0..7>` | `0..7` | 3-bit RFC 5462 Traffic Class | `0` |
| `mpls` | **Bottom of Stack** | `bos <0\|1>` | `0..1` | `1` = last label before the IP header | `1` |
| `mpls` | **Shim TTL** | `mplsttl <0..255>` | `0..255` | 8-bit MPLS TTL, independent of the inner IP `ttl` | `64` |

| `pcp` | 802.1p Class | Typical DSCP | Typical Use |
| :--- | :--- | :--- | :--- |
| `0` | Best Effort | `dscp 0` (BE) | Default user traffic, web browsing |
| `1` | Background | `dscp 8` (CS1) | Backups, NAS replication, scavenger (often with `dei 1`) |
| `2` | Excellent Effort | `dscp 18` (AF21) | Transactional database and ERP traffic |
| `3` | Critical Applications | `dscp 26` (AF31) | Mission-critical messaging, RoCEv2 lossless queues (PFC priority 3) |
| `4` | Video | `dscp 34` (AF41) | Conferencing, RTSP streams, IPTV |
| `5` | Voice | `dscp 46` (EF) | VoIP RTP (`sip` / `rtp`), strict-priority queues |
| `6` | Internetwork Control | `dscp 48` (CS6) | Routing protocols (`ospf`, `bgp`, `pim`, `bfd`) and keepalives |
| `7` | Network Control | `dscp 56` (CS7) | Layer 2 control and fabric management |

---

## 4. `stp` BPDU Guard, `lldp` Neighbors & `lacp` Port-Channels

Three protocols that all run silently until the day they do not.

### Rogue switches vs. `stp`

`stp` emits classic 802.1D Configuration BPDUs or 802.1w Rapid Spanning Tree (`rstp`) BPDUs. Use it to check that access ports with **BPDU Guard** or **Root Guard** err-disable the moment a rogue switch injects a superior BPDU, instead of learning that the hard way when somebody plugs in a "temporary" switch under a desk.

* **Framing:** 802.3 length frame to the Bridge Group MAC `01:80:c2:00:00:00` with a 3-byte 802.2 LLC header (`DSAP 0x42`, `SSAP 0x42`, `Control 0x03`).
* **Classic BPDU:** 35 bytes (`Version 0`, `Type 0x00`). **RSTP BPDU:** 36 bytes (`Version 2`, `Type 0x02`, trailing `Version 1 Length 0x00`).
* **Timers:** `maxage`, `hellotime`, and `forwarddelay` are given in seconds and scaled to 1/256-second wire units automatically.

```frameassembly
host core_root { ip 10.0.1.1  mac 00:1c:73:00:00:01 }
host dist_sw   { ip 10.0.1.2  mac 00:1c:73:00:00:02 }
host rogue_sw  { ip 10.0.1.99 mac 00:e0:4c:99:99:99 }

flow bpduguard_test(root, dist, rogue) {
    // Legitimate root (priority 4096) sends a steady-state designated BPDU
    root -> dist stp rstp rootid "4096/00:1c:73:00:00:01" bridgeid "4096/00:1c:73:00:00:01" portid 0x8001 cost 0 maxage 20 hellotime 2 forwarddelay 15 flags 0x3c wait 5ms

    // Rogue switch injects a priority 0 superior BPDU. BPDU Guard should err-disable the port.
    rogue -> dist stp rstp rootid "0/00:e0:4c:99:99:99" bridgeid "0/00:e0:4c:99:99:99" portid 0x8001 cost 0 flags 0x3c
}

compile { bpduguard_test(core_root, dist_sw, rogue_sw) }
```

RSTP Proposal and Agreement, to time rapid convergence:

```frameassembly
host core_root { ip 10.0.1.1 mac 00:1c:73:00:00:01 }
host dist_sw   { ip 10.0.1.2 mac 00:1c:73:00:00:02 }

flow rstp_handshake(root, dist) {
    // Proposal (0x0e = Proposal + Designated role)
    root -> dist stp rstp rootid "4096/00:1c:73:00:00:01" bridgeid "4096/00:1c:73:00:00:01" portid 0x8001 cost 0 flags 0x0e wait 2ms

    // Agreement (0x7c = Agreement + Forwarding + Learning + Root role)
    root <- dist stp rstp rootid "4096/00:1c:73:00:00:01" bridgeid "32768/00:1c:73:00:00:02" portid 0x8001 cost 2000 flags 0x7c
}

compile { rstp_handshake(core_root, dist_sw) }
```

`rootid` and `bridgeid` accept `"<priority>/<mac>"` (decimal `"4096/..."` or hex `"0x1000/..."`), a bare MAC string (priority defaults to `32768`), or a 16-character hex string. As with every FrameAssembly keyword, write them in lowercase with no underscores.

| Bit(s) | Mask | Flag / Role | Common Composite `flags` |
| :--- | :--- | :--- | :--- |
| **0** | `0x01` | Topology Change (TC): tells switches to flush MAC tables faster | `0x01` classic TC |
| **1** | `0x02` | Proposal (RSTP) | `0x0e` = Proposal + Designated role |
| **3..2** | `0x04` / `0x08` / `0x0c` | Port role (RSTP): Alternate/Backup, Root, Designated | `0x3c` = Designated + Learning + Forwarding |
| **4** | `0x10` | Learning (RSTP) | `0x7c` = Root + Learning + Forwarding + Agreement |
| **5** | `0x20` | Forwarding (RSTP) | `0x3d` = `0x3c` + Topology Change |
| **6** | `0x40` | Agreement (RSTP) | `0x81` = classic TC + TCA |
| **7** | `0x80` | Topology Change Acknowledgment (TCA) | n/a |

### Mis-cabled neighbors vs. `lldp`

Chasing a mis-patched leaf-spine port, or checking how NetBox, `lldpd`, or a phone provisioning script parses a neighbor advertisement, usually needs a live switch at the other end of the cable. `lldp` produces the advertisement directly.

* **Framing:** Ethernet II (`0x88CC`) to the Nearest Bridge multicast `01:80:c2:00:00:0e`.
* **Always emitted:** Chassis ID (TLV 1, subtype `4` MAC, defaults to the host MAC), Port ID (TLV 2, subtype `5` interface name, defaults to `"eth0"`), TTL (TLV 3, defaults to `120`).
* **Optional:** System Name (TLV 5) with `sysname`, System Description (TLV 6) with `sysdesc`, raw TLVs from `hexpayload` (such as Org-Specific Type `127`), then the mandatory End of LLDPDU marker.

```frameassembly
host spine_01 { ip 10.255.0.1  mac 00:1c:73:a0:01:01 }
host leaf_01  { ip 10.255.0.11 mac 00:1c:73:b0:11:49 }

flow dc_lldp_discovery(spine, leaf) {
    spine -> leaf lldp chassisid "00:1c:73:a0:01:01" portid "Ethernet1/1" ttl 120 sysname "spine-01.dc1.example.net" sysdesc "Arista EOS 4.32.1F 7060X5" wait 5ms

    // Leaf answers with an Org-Specific Port VLAN TLV (Type 127, OUI 00-80-C2, subtype 1, VLAN 100)
    spine <- leaf lldp chassisid "00:1c:73:b0:11:49" portid "Ethernet49/1" ttl 120 sysname "leaf-01.dc1.example.net" hexpayload "fe060080c2010064" wait 5ms

    // ttl 0 withdraws the neighbor: the port is "shutting down"
    spine <- leaf lldp chassisid "00:1c:73:b0:11:49" portid "Ethernet49/1" ttl 0
}

compile { dc_lldp_discovery(spine_01, leaf_01) }
```

```console
$ frameassembly lldp_test.frasm
$ tshark -r lldp_test.pcap -Y "lldp" -V
```

### Port-channels stuck in `Suspended` vs. `lacp`

Anyone who has stared at a member port stuck in `Individual` or `Suspended` knows it comes down to the 8-bit Actor and Partner state bytes. `lacp` builds the full 110-byte LACPDU over Slow Protocols (`0x8809`, destination `01:80:c2:00:00:02`): Actor TLV (Type 1, Length 20), Partner TLV (Type 2, Length 20), Collector (Type 3, Length 16), Terminator (Type 0), plus the 50-byte zero pad. You replay a bundle bring-up without a second switch.

```frameassembly
host tor_sw   { ip 10.0.2.1 mac 00:1c:73:11:22:33 }
host linux_hv { ip 10.0.2.2 mac 00:50:56:88:99:aa }

flow lacp_bond_bringup(sw, hv) {
    // Unbundled and defaulted (0x47), partner unknown
    sw -> hv lacp actorsys 00:1c:73:11:22:33 actorkey 10 actorport 1 actorstate 0x47 partnersys 00:00:00:00:00:00 partnerkey 0 partnerport 0 partnerstate 0x00 wait 2ms

    // Linux bond0 answers, in sync (0x0f)
    sw <- hv lacp actorsys 00:50:56:88:99:aa actorkey 10 actorport 1 actorstate 0x0f partnersys 00:1c:73:11:22:33 partnerkey 10 partnerport 1 partnerstate 0x07 wait 2ms

    // Both sides reach Collecting + Distributing (0x3f)
    sw -> hv lacp actorsys 00:1c:73:11:22:33 actorkey 10 actorport 1 actorstate 0x3f partnersys 00:50:56:88:99:aa partnerkey 10 partnerport 1 partnerstate 0x3f
}

compile { lacp_bond_bringup(tor_sw, linux_hv) }
```

| Bit | Mask | Flag | Set (`1`) | Cleared (`0`) |
| :--- | :--- | :--- | :--- | :--- |
| **0** | `0x01` | Activity | Active (sends LACPDUs) | Passive |
| **1** | `0x02` | Timeout | Short (1s periodic, 3s timeout) | Long (30s periodic, 90s timeout) |
| **2** | `0x04` | Aggregation | Aggregatable | Individual link |
| **3** | `0x08` | Synchronization | In sync | Out of sync |
| **4** | `0x10` | Collecting | Receiving on this member | Not collecting |
| **5** | `0x20` | Distributing | Transmitting on this member | Not distributing |
| **6** | `0x40` | Defaulted | No partner LACPDU received yet | Using real partner info |
| **7** | `0x80` | Expired | Receive state machine timed out | Normal |

Common values: `0x47` unbundled and defaulted, `0x3d` healthy slow-timer bundle (the default), `0x3f` healthy fast-timer bundle.

### Modifier & Wire Cheat-Sheet: `stp`, `lldp`, `lacp`

| Protocol | Modifier | Syntax | Wire Field | Default When Omitted |
| :--- | :--- | :--- | :--- | :--- |
| `stp` | **Rapid mode** | `rstp` | BPDU Version `2`, Type `0x02`, trailing Version 1 Length | Classic STP (`Version 0`) |
| `stp` | **Flags** | `flags <0..255>` | 8-bit flags byte (hex accepted) | `0x00` |
| `stp` | **Root bridge ID** | `rootid "<prio>/<mac>"` | 8-byte Root ID (2B priority + 6B MAC) | `32768` + source MAC |
| `stp` | **Sender bridge ID** | `bridgeid "<prio>/<mac>"` | 8-byte Bridge ID | `32768` + source MAC |
| `stp` | **Root path cost** | `cost <number>` | 32-bit cost (`2000` for 10GbE, `200` for 100GbE) | `0` |
| `stp` | **Port identifier** | `portid <0..65535>` | Port priority + number (`0x8001` = priority 128, port 1) | `0x8001` |
| `stp` | **Max age** | `maxage <seconds>` | BPDU age limit | `20` |
| `stp` | **Hello time** | `hellotime <seconds>` | Interval between BPDUs | `2` |
| `stp` | **Forward delay** | `forwarddelay <seconds>` | Listening/Learning delay | `15` |
| `lldp` | **Chassis ID** | `chassisid "<text>"` | TLV 1 (subtype `4`) | Host's 6-byte MAC |
| `lldp` | **Port ID** | `portid "<name>"` or `<0..65535>` | TLV 2 (subtype `5`) | `"eth0"` |
| `lldp` | **Hold time** | `ttl <0..255>` | TLV 3 in seconds (`0` withdraws the neighbor) | `120` |
| `lldp` | **System name** | `sysname "<text>"` | TLV 5 | Omitted |
| `lldp` | **System description** | `sysdesc "<text>"` | TLV 6 | Omitted |
| `lldp` | **Custom TLVs** | `hexpayload "<hex>"` | Raw bytes before End of LLDPDU | Empty |
| `lacp` | **Actor system** | `actorsys <mac>` | Local System ID (priority fixed `0x8000`) | Host MAC |
| `lacp` | **Actor key** | `actorkey <0..65535>` | Bundle key (`100` for `Po100`) | `1` |
| `lacp` | **Actor port** | `actorport <0..65535>` | Local member port (priority fixed `0x8000`) | `1` |
| `lacp` | **Actor state** | `actorstate <0..255>` | Local state bitmask | `0x3d` |
| `lacp` | **Partner system** | `partnersys <mac>` | Remote System ID | Receiving host's MAC |
| `lacp` | **Partner key** | `partnerkey <0..65535>` | Remote key | `1` |
| `lacp` | **Partner port** | `partnerport <0..65535>` | Remote member port | `1` |
| `lacp` | **Partner state** | `partnerstate <0..255>` | Remote state bitmask | `0x3d` |

---

## 5. `eapol` 802.1X Tests Without Locking Yourself Out

Debugging why an IoT supplicant failed EAP-TLS usually means wrestling `wpa_supplicant` certificates against a live RADIUS or ISE lab, and the one test port you own is the one that just blocked you. `eapol` (`0x888E`, destination `01:80:c2:00:00:03`) lets you script the whole conversation between a **Supplicant** and an **Authenticator**: `EAPOL-Start`, Identity, EAP-TLS challenge, `EAP-Success`, `EAPOL-Logoff`. Send it as a capture, replay it at the NAC, and read the verdict in the switch logs.

* **4-byte EAPOL header:** `Protocol Version` (default `1`), `Packet Type` (`0` eappacket, `1` start, `2` logoff, `3` key), 16-bit `Body Length`.
* **EAP Request / Response (`eapcode 1` / `2`):** `Code | Identifier | Length | Type`, then the `identity` string and any `payload` / `hexpayload`.
* **EAP Success / Failure (`eapcode 3` / `4`) with no payload:** a strict 4-byte RFC 3748 packet with no Type field.

Start and Identity exchange:

```frameassembly
host workstation { ip 10.50.10.25 mac 00:24:d7:11:22:33 }
host campus_sw   { ip 10.50.10.1  mac 00:1c:73:80:21:10 }

flow dot1x_identity(supp, auth_sw) {
    supp -> auth_sw eapol version 2 type start wait 2ms
    supp <- auth_sw eapol version 2 type eappacket eapcode 1 eapid 1 eapmethod 1 wait 2ms
    supp -> auth_sw eapol version 2 type eappacket eapcode 2 eapid 1 eapmethod 1 identity "host/wkstn-25.corp.internal" wait 5ms
}

compile { dot1x_identity(workstation, campus_sw) }
```

EAP-TLS challenge, success, key descriptor, and a polite logoff:

```frameassembly
host workstation { ip 10.50.10.25 mac 00:24:d7:11:22:33 }
host campus_sw   { ip 10.50.10.1  mac 00:1c:73:80:21:10 }

flow dot1x_eaptls_and_logoff(supp, auth_sw) {
    // EAP-TLS (method 13) request, then the supplicant's response
    supp <- auth_sw eapol version 2 type eappacket eapcode 1 eapid 2 eapmethod 13 hexpayload "20" wait 2ms
    supp -> auth_sw eapol version 2 type eappacket eapcode 2 eapid 2 eapmethod 13 payload "EAP_TLS_CLIENT_CERT_VERIFY" wait 5ms

    // 4-byte EAP-Success, then an EAPOL-Key descriptor
    supp <- auth_sw eapol version 2 type eappacket eapcode 3 eapid 2 wait 2ms
    supp <- auth_sw eapol version 2 type key hexpayload "02008a00100000000000000001" wait 10ms

    supp -> auth_sw eapol version 2 type logoff
}

compile { dot1x_eaptls_and_logoff(workstation, campus_sw) }
```

Pair this with `radius` (see [Layer 7 infrastructure](07_l7_infra_and_telemetry.md)) to cover the authenticator-to-server leg too.

### Modifier & Wire Cheat-Sheet: `eapol`

| Modifier | Syntax | Values | Default |
| :--- | :--- | :--- | :--- |
| **802.1X version** | `version <1..3>` | `1` 802.1X-2001, `2` 802.1X-2004, `3` 802.1X-2010/2020 (MACsec) | `1` |
| **Packet type** | `type <start\|logoff\|key\|eappacket>` | Or the bare words `start`, `logoff`, `key`, `eappacket` | `eappacket` (`0`) |
| **EAP code** | `eapcode <1..4>` | `1` Request, `2` Response, `3` Success, `4` Failure | `1` |
| **EAP identifier** | `eapid <0..255>` | Matches a Request to its Response | `1` |
| **EAP method** | `eapmethod <0..255>` | `1` Identity, `4` MD5-Challenge, `13` EAP-TLS, `21` TTLS, `25` PEAP | `1` |
| **Identity** | `identity "<text>"` | Username or machine principal, such as `"host/wkstn01.corp.example.com"` | Empty |
