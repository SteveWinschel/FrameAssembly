# Layer 2 Switching, VLAN Trunking & Data-Link Protocols Reference (`ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`)

Testing Layer 2 edge cases—double-tagged 802.1ad QinQ trunks, Gratuitous ARP (`GARP`) VIP failovers, STP BPDU Guard triggers, LACP port-channel negotiations, 802.1X EAPOL NAC onboarding, or MPLS label stacks—is normally a headache because OS network stacks strip VLAN tags and physical lab switches take time to cable and configure.

With FrameAssembly, you write the exact Layer 2 or Layer 2.5 frame in a few lines of `.fasm` code, compile it to `.pcap`, and replay it straight onto a trunk port with `tcpreplay` (or inspect it in Wireshark). When optional fields are omitted, FrameAssembly automatically builds standards-compliant Ethernet II or IEEE 802.3 LLC headers, derives unicast, broadcast, and multicast MAC addresses, and populates mandatory protocol TLVs.

| Protocol | Keyword | Standard | Framing / EtherType | Default Destination MAC | Primary Operational Use Cases |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ARP** | `ARP` | RFC 826 / RFC 5227 | Ethernet II (`0x0806`) | `ff:ff:ff:ff:ff:ff` (Request) / Unicast (Reply) | Next-hop MAC resolution, Gratuitous ARP (`GARP`) VIP failover, RFC 5227 duplicate IP probes |
| **VLAN** | `VLAN` | IEEE 802.1Q / 802.1p | 802.1Q Tag (`0x8100`) | Host / Protocol MAC | 12-bit VLAN IDs (`1..4094`), 3-bit CoS priority (`PCP 0..7`), 1-bit drop eligibility (`DEI 0..1`) |
| **QinQ** | `QINQ` | IEEE 802.1ad | S-Tag (`0x88A8`) + C-Tag (`0x8100`) | Host / Protocol MAC | Carrier Metro Ethernet double-tagging (`qinq <s_vid> inner_vlan <c_vid>`) and L2VPN handoffs |
| **LLDP** | `LLDP` | IEEE 802.1AB | Ethernet II (`0x88CC`) | `01:80:c2:00:00:0e` | Switch/server topology discovery (`CHASSIS_ID`, `PORT_ID`, `TTL`, `SYSNAME`, `SYSDESC`) |
| **STP / RSTP** | `STP` | IEEE 802.1D / 802.1w | 802.3 Length + 802.2 LLC (`0x424203`) | `01:80:c2:00:00:00` | Root Bridge elections, RSTP Proposal/Agreement handshakes, BPDU Guard and Root Guard testing |
| **LACP** | `LACP` | IEEE 802.3ad / 802.1AX | Slow Protocols (`0x8809`) | `01:80:c2:00:00:02` | Dynamic LAG / Port-Channel Actor and Partner state synchronization |
| **EAPOL** | `EAPOL` | IEEE 802.1X / RFC 3748 | Ethernet II (`0x888E`) | `01:80:c2:00:00:03` | Port-based NAC (`START`, `EAP_PACKET` Identity/MD5/TLS/PEAP, WPA `KEY`, `LOGOFF`) |
| **MPLS** | `MPLS` | RFC 3031 / RFC 3032 | Ethernet II (`0x8847`) | Host / Next-Hop MAC | 20-bit label switching (`MPLS` / `LABEL`), Traffic Class (`EXP` / `TC`), `BOS`, and `MPLS_TTL` |

---

## Universal Ethernet II Header Overrides & Automatic MAC Derivation

Every statement in FrameAssembly—whether it is a raw Layer 2 frame (`ARP`, `LLDP`, `STP`) or a Layer 7 application packet (`HTTP`, `DNS`, `SNMP3`, `MODBUS`)—is wrapped in an outer Ethernet frame. You can override the outer Ethernet header on any statement using three universal modifiers:

| Modifier | Syntax | Value Format | Description |
| :--- | :--- | :--- | :--- |
| **Source MAC** | `SRCMAC <mac>` | `aa:bb:cc:dd:ee:ff` | Overrides the 48-bit Ethernet source MAC address for this single frame |
| **Destination MAC** | `DSTMAC <mac>` | `aa:bb:cc:dd:ee:ff` | Overrides the 48-bit Ethernet destination MAC address for this single frame |
| **EtherType** | `ETHERTYPE <0..65535>` | Hex (`0x88cc`) or `0..65535` | Overrides the 16-bit Ethernet II EtherType preceding the inner payload |

### How FrameAssembly Automatically Derives MAC Addresses
When you omit `SRCMAC`, `DSTMAC`, or the optional `MAC` field in a `HOST` declaration, FrameAssembly selects the wire MAC address using the following priority order:

| Priority | Condition | Source MAC Selected | Destination MAC Selected |
| :--- | :--- | :--- | :--- |
| **1. Statement Override** | `srcmac <mac>` or `dstmac <mac>` on statement | The statement's `srcmac` | The statement's `dstmac` |
| **2. Protocol Control Group** | `LLDP`, `STP`, `LACP`, `EAPOL`, `ARP REQUEST` | Host `mac` (or default unicast) | IEEE 802.1D multicast (`01:80:c2:00:00:xx`) or broadcast (`ff:ff:ff:ff:ff:ff`) |
| **3. Multicast Target IP** | Destination IP is IPv4 `224.0.0.0/4` or IPv6 `ff00::/8` | Host `mac` (or default unicast) | **RFC 1112** `01:00:5e:xx:xx:xx` (IPv4) or **RFC 2464** `33:33:xx:xx:xx:xx` (IPv6) |
| **4. Host Declaration** | `host <id> { ip <ip> mac <mac> }` | Sending host's `mac` | Receiving host's `mac` |
| **5. Unicast Fallback** | Host `mac` omitted on unicast IP | `00:00:00:00:00:01` (`->`) / `00:00:00:00:00:02` (`<-`) | `00:00:00:00:00:02` (`->`) / `00:00:00:00:00:01` (`<-`) |

> **Why Direction-Aware Unicast Fallback Matters:** When replaying a `.pcap` through a physical or virtual switch with `tcpreplay`, forward (`->`) and reverse (`<-`) packets automatically swap `00:00:00:00:00:01` and `00:00:00:00:00:02` even if you never typed a `mac` address in your `host` blocks. This prevents switch MAC-table flapping alerts.

```frameassembly
host sensor_a { ip 10.10.1.10 mac 00:1b:21:aa:bb:01 }
host sensor_b { ip 10.10.1.20 mac 00:1b:21:aa:bb:02 }

flow custom_ethernet_framing(a, b) {
    // Standard unicast UDP frame using the MACs declared in the host blocks
    a -> b udp srcport 40000 dstport 40000 payload "NORMAL_UNICAST" wait 1ms

    // Spoofed source MAC, broadcast destination MAC, and custom EtherType (0x88B5 IEEE Local Experimental)
    a -> b udp srcport 40000 dstport 40000 srcmac de:ad:be:ef:00:01 dstmac ff:ff:ff:ff:ff:ff ethertype 0x88b5 payload "CUSTOM_L2_ETHERTYPE"
}

compile {
    custom_ethernet_framing(sensor_a, sensor_b)
}
```

---

## 1. Address Resolution Protocol (`ARP` — RFC 826 / RFC 5227)

`ARP` resolves IPv4 addresses (`0x0800`) to 48-bit Ethernet hardware addresses (`EtherType 0x0806`). Network administrators use `ARP` captures to validate default gateway resolution, test Dynamic ARP Inspection (`DAI`) on access switches, simulate **Gratuitous ARP (`GARP`)** VIP failovers for HA firewalls/load balancers, and test **RFC 5227 Duplicate Address Detection (DAD)** probes.

### Default Wire Behavior & Dual-Stack IPv6 Adaptation
* **IPv4 Hosts (`EtherType 0x0806`):** Builds a 28-byte ARP header (`HTYPE = 1` Ethernet, `PTYPE = 0x0800` IPv4, `HLEN = 6`, `PLEN = 4`).
  * `ARP REQUEST` (default): Sets Opcode `1`, outer Ethernet Destination MAC to broadcast (`ff:ff:ff:ff:ff:ff`), and Target Hardware Address (`THA`) to `00:00:00:00:00:00`.
  * `ARP REPLY`: Sets Opcode `2`, outer Ethernet Destination MAC to the target host's unicast MAC, and `THA` to the target host's MAC.
  * `GRATUITOUS` (or `GARP`): Sets Target Protocol Address (`TPA`) equal to Sender Protocol Address (`SPA`) and zeroes `THA` (`00:00:00:00:00:00`).
* **IPv6 Hosts (`EtherType 0x86DD`, RFC 4861 Automatic Dual-Stack IPv6 Adaptation):** If you run an `ARP` flow with IPv6 hosts inside `compile { ... }`, FrameAssembly automatically translates the statements into RFC 4861 ICMPv6 Neighbor Discovery packets with `Hop Limit 255`:
  * `ARP REQUEST` becomes an **ICMPv6 Neighbor Solicitation** (Type `135`, Option 1 Source Link-Layer Address) sent to the target's Solicited-Node multicast address (`ff02::1:ffxx:xxxx`) and Ethernet MAC (`33:33:ff:xx:xx:xx`).
  * `ARP REPLY` becomes an **ICMPv6 Neighbor Advertisement** (Type `136`, Solicited + Override flags `0x60`, Option 2 Target Link-Layer Address).

### `ARP` Modifiers

| Modifier | Syntax & Aliases | Wire Field & Description | Default When Omitted |
| :--- | :--- | :--- | :--- |
| **Request Opcode** | `REQUEST` | Sets 16-bit `OPER = 1` (ARP Request) | `REQUEST` (`1`) |
| **Reply Opcode** | `REPLY` | Sets 16-bit `OPER = 2` (ARP Reply) | `REQUEST` (`1`) |
| **Gratuitous Flag** | `GRATUITOUS` or `GARP` | Sets `TPA = SPA` and `THA = 00:00:00:00:00:00` for VIP announcements | Disabled |
| **Sender MAC** | `SHA <mac>` or `SENDERMAC <mac>` | 48-bit Sender Hardware Address (`SHA`) in the ARP payload | Sending host's MAC |
| **Sender IP** | `SPA <ipv4>` or `SENDERIP <ipv4>` | 32-bit Sender Protocol Address (`SPA`, e.g. `0.0.0.0` for RFC 5227 probes) | Sending host's IPv4 |
| **Target MAC** | `THA <mac>` or `TARGETMAC <mac>` | 48-bit Target Hardware Address (`THA`) in the ARP payload | `00:00:00:00:00:00` (Req) / Dst MAC (Reply) |
| **Target IP** | `TPA <ipv4>` or `TARGETIP <ipv4>` | 32-bit Target Protocol Address (`TPA`, the IP being queried or claimed) | Receiving host's IPv4 |

### Example 1A: Gateway ARP Resolution, RFC 5227 Probe & HA VIP Failover (`GARP`)

```frameassembly
host workstation { ip 192.168.10.55  mac 00:50:56:a1:10:55 }
host fw_active   { ip 192.168.10.1   mac 00:50:56:fe:00:01 }
host fw_standby  { ip 192.168.10.2   mac 00:50:56:fe:00:02 }
host lan_bcast   { ip 192.168.10.255 mac ff:ff:ff:ff:ff:ff }

flow arp_resolution_and_vip_failover(client, pri, sec, bcast) {
    // 1. Standard broadcast ARP Request from workstation asking "Who has 192.168.10.1?"
    client -> pri arp request dstmac ff:ff:ff:ff:ff:ff tha 00:00:00:00:00:00 wait 1ms

    // 2. Unicast ARP Reply from the active firewall
    client <- pri arp reply wait 5ms

    // 3. RFC 5227 Duplicate Address Detection (ARP Probe with Sender IP 0.0.0.0)
    client -> bcast arp request sendermac 00:50:56:a1:10:55 senderip 0.0.0.0 targetmac 00:00:00:00:00:00 targetip 192.168.10.55 wait 2ms

    // 4. Standby firewall takes over the 192.168.10.1 VIP and broadcasts a Gratuitous ARP
    sec -> bcast arp reply gratuitous sendermac 00:50:56:fe:00:02 senderip 192.168.10.1 targetmac ff:ff:ff:ff:ff:ff targetip 192.168.10.1
}

compile {
    arp_resolution_and_vip_failover(workstation, fw_active, fw_standby, lan_bcast)
}
```

### Example 1B: Dual-Stack `ARP` Flow Over Both IPv4 and IPv6

```frameassembly
host app_v4 { ip 10.20.0.10       mac 00:16:3e:10:00:10 }
host gw_v4  { ip 10.20.0.1        mac 00:16:3e:10:00:01 }
host app_v6 { ip 2001:db8:20::10  mac 00:16:3e:60:00:10 }
host gw_v6  { ip 2001:db8:20::1   mac 00:16:3e:60:00:01 }

flow neighbor_lookup(host_ep, router_ep) {
    host_ep -> router_ep arp request wait 1ms
    host_ep <- router_ep arp reply
}

compile {
    // Emits RFC 826 ARP Request + Reply (EtherType 0x0806)
    neighbor_lookup(app_v4, gw_v4)
    // Automatically emits RFC 4861 ICMPv6 Neighbor Solicitation + Advertisement (Hop Limit 255)
    neighbor_lookup(app_v6, gw_v6)
}
```

**Inspect with `tshark`:**
```console
tshark -r output.pcap -Y "arp or icmpv6" -T fields -e frame.number -e eth.src -e eth.dst -e arp.opcode -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4
```

---

## 2. Virtual LAN (`VLAN` — IEEE 802.1Q) & Provider Bridging (`QINQ` — IEEE 802.1ad)

Both `VLAN` and `QINQ` work in two ways:
1. **Cross-Layer Encapsulation Modifiers:** Add `vlan <vid> [pcp <0..7>] [dei <0..1>]` or `qinq <outer_svid> inner_vlan <inner_cvid> [pcp <0..7>] [dei <0..1>]` to **any** statement (`ARP`, `STP`, `OSPF`, `BGP`, `TCP`, `UDP`, `HTTP`, `SIP`, `MODBUS`, etc.) to insert 802.1Q or 802.1ad tags ahead of the inner packet.
2. **Standalone Layer 2 Statements:** Write `a -> b vlan 100` or `a -> b qinq 2000 inner_vlan 100` with no upper-layer protocol keyword to emit a tagged Ethernet frame (wrapping a valid inner IP+UDP packet by default, or raw bytes if `payload` / `hexpayload` is provided).

### `VLAN` & `QINQ` Modifiers

| Modifier | Syntax | Valid Range | Wire Field & Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| **802.1Q VLAN ID** | `VLAN <1..4094>` | `1..4094` | Inserts an IEEE 802.1Q tag (`TPID = 0x8100`) with 12-bit VLAN ID | `1` (if bare `vlan`) |
| **Priority (CoS)** | `PCP <0..7>` | `0..7` | 3-bit IEEE 802.1p Priority Code Point in the 802.1Q / 802.1ad TCI | `0` (Best Effort) |
| **Drop Eligible** | `DEI <0..1>` | `0..1` | 1-bit Drop Eligible Indicator (`1` = drop first during queue congestion) | `0` |
| **Outer Service VLAN** | `QINQ <1..4094>` | `1..4094` | Inserts an outer IEEE 802.1ad Service VLAN tag (`TPID = 0x88A8`) | `1` (if bare `qinq`) |
| **Inner Customer VLAN**| `INNER_VLAN <1..4094>` | `1..4094` | Inserts an inner IEEE 802.1Q Customer VLAN tag (`TPID = 0x8100`) inside `QINQ` | `2` (standalone) |

> **Important Syntax Rules:**
> * **Valid VLAN Range (`1..4094`):** IEEE 802.1Q reserves VLAN `0` (priority-tagged frame) and `4095` (`0xFFF` implementation reserved). FrameAssembly rejects `vlan 0` or `vlan 4095` with a clear validation error pointing to the invalid VLAN ID.
> * **Double-Tagging Rule:** For IEEE 802.1ad double-tagged frames, always write `qinq <outer_svid> inner_vlan <inner_cvid>`. Do not combine `qinq` and `vlan` on the same statement.

### IEEE 802.1p Class of Service (`PCP`) Reference Table

| `PCP` Value | IEEE 802.1p Traffic Class | Typical DSCP Pairing | Common Enterprise & Carrier Use Case |
| :--- | :--- | :--- | :--- |
| `0` | Best Effort (`BE`) | `DSCP 0` (`BE`) | Default untagged/tagged LAN user traffic and HTTP browsing |
| `1` | Background (`BK`) | `DSCP 8` (`CS1`) | Bulk backups (`rsync`, NAS replication), scavenger traffic (often paired with `DEI 1`) |
| `2` | Excellent Effort (`EE`) | `DSCP 18` (`AF21`) | Transactional database and ERP traffic |
| `3` | Critical Applications (`CA`) | `DSCP 26` (`AF31`) | Mission-critical enterprise messaging, RoCEv2 RDMA lossless queues (`PFC` priority 3) |
| `4` | Video (`VI`) | `DSCP 34` (`AF41`) | Conferencing, RTSP streaming, and broadcast IPTV |
| `5` | Voice (`VO`) | `DSCP 46` (`EF`) | VoIP RTP audio (`SIP`/`RTP`) and low-latency strict-priority queues |
| `6` | Internetwork Control (`IC`) | `DSCP 48` (`CS6`) | Routing protocols (`OSPF`, `BGP`, `PIM`, `BFD`) and keepalives |
| `7` | Network Control (`NC`) | `DSCP 56` (`CS7`) | Layer 2 control protocols and high-priority fabric management |

### Example 2A: Enterprise 802.1Q Trunk with Multi-CoS Traffic (`PCP` & `DEI`)

```frameassembly
host tor_sw_a { ip 172.16.10.1 mac 00:1c:73:10:00:01 }
host tor_sw_b { ip 172.16.10.2 mac 00:1c:73:10:00:02 }

flow enterprise_8021q_trunk(a, b) {
    // VLAN 10: High-priority VoIP RTP audio (PCP 5 = Voice, DSCP 46 = EF)
    a -> b vlan 10 pcp 5 dei 0 dscp 46 rtp seq 101 timestamp 16000 ssrc 0x11223344 payload "G711_PCMU_FRAME" wait 1ms

    // VLAN 20: RoCEv2 lossless storage queue (PCP 3, DSCP 26 = AF31)
    a -> b vlan 20 pcp 3 dei 0 dscp 26 udp srcport 51000 dstport 4791 payload "RDMA_WRITE_ONLY" wait 1ms

    // VLAN 99: Scavenger backup traffic marked Drop-Eligible (PCP 1, DEI 1, DSCP 8 = CS1)
    a -> b vlan 99 pcp 1 dei 1 dscp 8 tcp psh ack srcport 49152 dstport 873 payload "RSYNC_SNAPSHOT_CHUNK"
}

compile {
    enterprise_8021q_trunk(tor_sw_a, tor_sw_b)
}
```

### Example 2B: Carrier IEEE 802.1ad `QINQ` Metro Ethernet Handoff

```frameassembly
host cpe_site_a { ip 10.100.40.1 mac 00:50:56:ce:40:01 }
host cpe_site_b { ip 10.100.40.2 mac 00:50:56:ce:40:02 }

flow metro_qinq_handoff(a, b) {
    // Carrier S-VLAN 2500 (0x88A8) + Customer C-VLAN 40 (0x8100) carrying eBGP control plane (PCP 6)
    a -> b qinq 2500 inner_vlan 40 pcp 6 dscp 48 tcp syn srcport 53000 dstport 179 wait 1ms
    a <- b qinq 2500 inner_vlan 40 pcp 6 dscp 48 tcp syn ack wait 1ms
    a -> b qinq 2500 inner_vlan 40 pcp 6 dscp 48 tcp ack wait 1ms
    a -> b qinq 2500 inner_vlan 40 pcp 6 dscp 48 bgp open asn 65100 holdtime 90 bgpid 10.100.40.1 wait 2ms
    a <- b qinq 2500 inner_vlan 40 pcp 6 dscp 48 bgp open asn 65200 holdtime 90 bgpid 10.100.40.2
}

compile {
    metro_qinq_handoff(cpe_site_a, cpe_site_b)
}
```

**Inspect with `tshark`:**
```console
tshark -r output.pcap -T fields -e frame.number -e eth.type -e vlan.id -e vlan.prio -e vlan.dei -e ip.src -e ip.dst
```

---

## 3. Link Layer Discovery Protocol (`LLDP` — IEEE 802.1AB)

Tracking down miscabled leaf-spine ports or testing how an inventory daemon (`lldpd`, NetBox, or a VoIP phone provisioning script) parses neighbor discovery frames normally requires live switches on the other end of the patch cord. With `LLDP`, you can script switch, router, and hypervisor advertisements—including chassis identity, port names, hold times, system hostnames, software banners, and `TTL 0` port-shutdown withdrawals—directly in `.fasm` code.

### Default Wire Behavior
* **Framing:** Ethernet II (`EtherType = 0x88CC`) addressed to the IEEE 802.1D Nearest Bridge non-TPMR multicast MAC `01:80:c2:00:00:0e`.
* **Mandatory TLVs (Always Emitted):**
  1. **Chassis ID (`TLV Type 1`):** Subtype `4` (MAC address). Defaults to the sending host's 6-byte MAC address if `CHASSIS_ID` is omitted, or encodes your custom string if specified.
  2. **Port ID (`TLV Type 2`):** Subtype `5` (Interface Name). Defaults to `"eth0"` if `PORT_ID` is omitted.
  3. **Time To Live (`TLV Type 3`):** 16-bit hold time in seconds. Defaults to `120` seconds if `TTL` is omitted.
* **Optional TLVs & End Marker:** Emits **System Name (`TLV Type 5`)** when `SYSNAME` is specified, **System Description (`TLV Type 6`)** when `SYSDESC` is specified, appends any custom `PAYLOAD` / `HEXPAYLOAD` bytes (such as IEEE 802.1 / 802.3 Organizationally Specific TLVs of Type `127`), and terminates with the mandatory **End Of LLDPDU (`TLV Type 0, Length 0`)** marker.

### `LLDP` Modifiers

| Modifier | Syntax | Wire TLV & Description | Default When Omitted |
| :--- | :--- | :--- | :--- |
| **Chassis ID** | `CHASSIS_ID "<text>"` | TLV Type `1` (Subtype `4`): Switch/server chassis MAC or identifier string | Sending host's 6-byte MAC |
| **Port ID** | `PORT_ID "<name>"` or `<0..65535>` | TLV Type `2` (Subtype `5`): Interface name (e.g. `"Ethernet1/1"`, `"ens3f0"`) | `"eth0"` |
| **Hold Time (TTL)** | `TTL <0..255>` | TLV Type `3`: Neighbor hold time in seconds (`0` signals LLDP shutdown/withdraw) | `120` seconds |
| **System Name** | `SYSNAME "<text>"` | TLV Type `5`: Device FQDN or hostname | Omitted |
| **System Description**| `SYSDESC "<text>"` | TLV Type `6`: NOS version, kernel release, and hardware platform string | Omitted |
| **Custom TLVs** | `HEXPAYLOAD "<hex>"` | Appends raw TLV bytes (e.g. Type `127` Org-Specific TLVs) before End-of-LLDPDU | Empty |

### Example: Leaf-Spine Data Center & Hypervisor LLDP Exchange

```frameassembly
host spine_01 { ip 10.255.0.1  mac 00:1c:73:a0:01:01 }
host leaf_01  { ip 10.255.0.11 mac 00:1c:73:b0:11:49 }

flow dc_lldp_discovery(spine, leaf) {
    // Spine switch advertising 400G uplink port
    spine -> leaf lldp chassis_id "00:1c:73:a0:01:01" port_id "Ethernet1/1" ttl 120 sysname "spine-01.dc1.example.net" sysdesc "Arista EOS 4.32.1F 7060X5" wait 5ms

    // Leaf switch replying with Management/PVID Org-Specific TLV (Type 127, Len 6, OUI 00-80-C2, Subtype 1, VLAN 100)
    spine <- leaf lldp chassis_id "00:1c:73:b0:11:49" port_id "Ethernet49/1" ttl 120 sysname "leaf-01.dc1.example.net" sysdesc "SONiC OS 202511 ToR" hexpayload "fe060080c2010064" wait 5ms

    // Port administrative shutdown: TTL 0 instructs neighbor to age out entry immediately
    spine <- leaf lldp chassis_id "00:1c:73:b0:11:49" port_id "Ethernet49/1" ttl 0
}

compile {
    dc_lldp_discovery(spine_01, leaf_01)
}
```

**Inspect with `tshark`:**
```console
tshark -r output.pcap -Y "lldp" -V
```

---

## 4. Spanning Tree Protocol (`STP` / `RSTP` — IEEE 802.1D / 802.1w)

`STP` emits classic IEEE 802.1D Configuration BPDUs or IEEE 802.1w Rapid Spanning Tree (`RSTP`) BPDUs. Use `STP` to validate Root Bridge elections, test RSTP Proposal/Agreement rapid convergence, or verify that access ports configured with **BPDU Guard** (`spanning-tree bpduguard enable`) or **Root Guard** immediately err-disable when a rogue switch injects a superior BPDU.

### Default Wire Behavior
* **Framing:** IEEE 802.3 length-framed Ethernet addressed to the Bridge Group multicast MAC `01:80:c2:00:00:00`, carrying a 3-byte IEEE 802.2 LLC header (`DSAP = 0x42`, `SSAP = 0x42`, `Control = 0x03`).
* **BPDU Packet Format:**
  * Without `RSTP`: 35-byte IEEE 802.1D Configuration BPDU (`Protocol ID = 0x0000`, `Version = 0`, `BPDU Type = 0x00`).
  * With `RSTP`: 36-byte IEEE 802.1w Rapid Spanning Tree BPDU (`Protocol ID = 0x0000`, `Version = 2`, `BPDU Type = 0x02`, plus trailing `Version 1 Length = 0x00`).
  * Timers (`MAX_AGE`, `HELLO_TIME`, `FORWARD_DELAY`) are automatically scaled into IEEE 802.1D 1/256-second wire units (`seconds << 8`).

### `STP` Modifiers

| Modifier | Syntax | Wire Field & Format | Default When Omitted |
| :--- | :--- | :--- | :--- |
| **Rapid STP Mode** | `RSTP` | Sets BPDU Version `2`, Type `0x02`, and appends 1-byte Version 1 Length (`0x00`) | Classic STP (`Version 0`) |
| **BPDU Flags** | `FLAGS <0..255>` | 8-bit STP/RSTP flags byte (accepts hex like `0x0e` or `0x7c`) | `0x00` |
| **Root Bridge ID** | `ROOT_ID "<prio>/<mac>"` | 8-byte Root Identifier (`2B Priority + 6B MAC`, e.g. `"4096/00:05:73:a0:00:01"`) | `32768` + Source MAC |
| **Sender Bridge ID** | `BRIDGE_ID "<prio>/<mac>"` | 8-byte Transmitting Bridge Identifier (`2B Priority + 6B MAC`) | `32768` + Source MAC |
| **Root Path Cost** | `COST <number>` | 32-bit Root Path Cost (`0` on Root Bridge, `2000` for 10GbE, `200` for 100GbE) | `0` |
| **Port Identifier** | `PORT_ID <0..65535>` | 16-bit Port Priority + Port Number (e.g. `0x8001` = priority `128`, port `1`) | `0x8001` |
| **Max Age Timer** | `MAX_AGE <seconds>` | Maximum BPDU age in seconds before topology reconvergence | `20` seconds |
| **Hello Time** | `HELLO_TIME <seconds>` | Interval in seconds between Configuration BPDUs | `2` seconds |
| **Forward Delay** | `FORWARD_DELAY <seconds>` | Listening/Learning state delay in seconds | `15` seconds |

> **Syntax Note:** Always include the underscore in `ROOT_ID` and `BRIDGE_ID`. Both fields accept `"<priority>/<mac>"` (such as `"4096/00:1c:73:00:00:01"` or `"0x1000/00:1c:73:00:00:01"`), a bare MAC address string (`"00:1c:73:00:00:01"` with default priority `32768`), or a 16-character hex string.

### STP / RSTP `FLAGS` Bitmask Reference

| Bit(s) | Hex Mask | Flag / Role Meaning | Common Composite `FLAGS` Values |
| :--- | :--- | :--- | :--- |
| **Bit 0** | `0x01` | **Topology Change (`TC`)** — instructs switches to flush MAC tables faster | `0x01` (Classic STP Topology Change) |
| **Bit 1** | `0x02` | **Proposal** (RSTP) — Designated port proposing rapid transition | `0x0e` (`0x02` Proposal + `0x0c` Designated Role) |
| **Bits 3..2**| `0x04` / `0x08` / `0x0c` | **Port Role** (RSTP): `0x04` Alternate/Backup, `0x08` Root, `0x0c` Designated | `0x3c` (`0x0c` Designated + `0x10` Learning + `0x20` Forwarding) |
| **Bit 4** | `0x10` | **Learning** (RSTP) — port is learning MAC addresses | `0x7c` (`0x08` Root + `0x10` Learn + `0x20` Fwd + `0x40` Agreement) |
| **Bit 5** | `0x20` | **Forwarding** (RSTP) — port is forwarding user frames | `0x3d` (Designated + Learn + Fwd + Topology Change `0x01`) |
| **Bit 6** | `0x40` | **Agreement** (RSTP) — Root port acknowledging a Proposal | `0x81` (Classic STP TC + TCA) |
| **Bit 7** | `0x80` | **Topology Change Acknowledgment (`TCA`)** | — |

### Example: RSTP Proposal/Agreement & Rogue Superior BPDU Test

```frameassembly
host core_root  { ip 10.0.1.1  mac 00:1c:73:00:00:01 }
host dist_sw    { ip 10.0.1.2  mac 00:1c:73:00:00:02 }
host rogue_sw   { ip 10.0.1.99 mac 00:e0:4c:99:99:99 }

flow rstp_convergence_and_bpduguard(root, dist, rogue) {
    // 1. Root bridge (Priority 4096) sends RSTP Proposal (0x0e = Proposal + Designated Role)
    root -> dist stp rstp root_id "4096/00:1c:73:00:00:01" bridge_id "4096/00:1c:73:00:00:01" port_id 0x8001 cost 0 max_age 20 hello_time 2 forward_delay 15 flags 0x0e wait 2ms

    // 2. Distribution switch (Priority 32768) replies with RSTP Agreement (0x7c = Agreement + Fwd + Learn + Root Role)
    root <- dist stp rstp root_id "4096/00:1c:73:00:00:01" bridge_id "32768/00:1c:73:00:00:02" port_id 0x8001 cost 2000 max_age 20 hello_time 2 forward_delay 15 flags 0x7c wait 5ms

    // 3. Steady-state Designated Forwarding BPDU (0x3c)
    root -> dist stp rstp root_id "4096/00:1c:73:00:00:01" bridge_id "4096/00:1c:73:00:00:01" port_id 0x8001 cost 0 max_age 20 hello_time 2 forward_delay 15 flags 0x3c wait 5ms

    // 4. Rogue switch on an access port injects a Priority 0 Superior BPDU (triggers Root Guard / BPDU Guard)
    rogue -> dist stp rstp root_id "0/00:e0:4c:99:99:99" bridge_id "0/00:e0:4c:99:99:99" port_id 0x8001 cost 0 flags 0x3c
}

compile {
    rstp_convergence_and_bpduguard(core_root, dist_sw, rogue_sw)
}
```

---

## 5. Link Aggregation Control Protocol (`LACP` — IEEE 802.3ad / 802.1AX)

Anyone who has stared at a switch port stuck in `Individual` or `Suspended` state knows that debugging IEEE 802.3ad Link Aggregation (`LAG` / Cisco & Arista `Port-Channel` / Linux `bond0` mode 4) comes down to the 8-bit Actor and Partner state flags. FrameAssembly builds complete 110-byte LACPDUs over Ethernet Slow Protocols (`EtherType = 0x8809`, destination MAC `01:80:c2:00:00:02`)—including Actor (`Type 1, Length 20`), Partner (`Type 2, Length 20`), Collector (`Type 3, Length 16`), and Terminator (`Type 0, Length 0`) TLVs plus the mandatory 50-byte IEEE 802.3ad zero pad—so you can replay exact bundle bring-up and timeout sequences without a second switch.

### `LACP` Modifiers

| Modifier | Syntax | Wire Field & Description | Default When Omitted |
| :--- | :--- | :--- | :--- |
| **Actor System MAC** | `ACTOR_SYS <mac>` | 48-bit local switch/server LACP System ID (Priority fixed at `0x8000`) | Sending host's MAC |
| **Actor Key** | `ACTOR_KEY <0..65535>` | 16-bit local administrative/operational bundle key (e.g. `100` for `Po100`) | `1` |
| **Actor Port** | `ACTOR_PORT <0..65535>` | 16-bit local member port number (`1`, `2`, etc.; Priority fixed at `0x8000`) | `1` |
| **Actor State** | `ACTOR_STATE <0..255>` | 8-bit local LACP state bitmask (see table below) | `0x3d` |
| **Partner System MAC** | `PARTNER_SYS <mac>` | 48-bit remote peer's LACP System ID as seen by the Actor | Receiving host's MAC |
| **Partner Key** | `PARTNER_KEY <0..65535>` | 16-bit remote peer's operational key | `1` |
| **Partner Port** | `PARTNER_PORT <0..65535>` | 16-bit remote peer's port number | `1` |
| **Partner State** | `PARTNER_STATE <0..255>` | 8-bit remote peer's state bitmask | `0x3d` |

### LACP State Byte (`ACTOR_STATE` / `PARTNER_STATE`) Bitmask Breakdown

| Bit | Hex Value | Flag Name | `1` (Set) | `0` (Cleared) |
| :--- | :--- | :--- | :--- | :--- |
| **Bit 0** | `0x01` | `LACP_Activity` | **Active** (transmits LACPDUs actively) | **Passive** (waits for peer LACPDU) |
| **Bit 1** | `0x02` | `LACP_Timeout` | **Short Timeout** (`1`s fast periodic, `3`s timeout) | **Long Timeout** (`30`s slow periodic, `90`s timeout) |
| **Bit 2** | `0x04` | `Aggregation` | **Aggregatable** (can join a multi-link LAG) | **Individual** (standalone link only) |
| **Bit 3** | `0x08` | `Synchronization` | **In Sync** (allocated to the correct LAG group) | **Out of Sync** (still negotiating) |
| **Bit 4** | `0x10` | `Collecting` | **Collecting** (receiving frames on this member link) | Not collecting |
| **Bit 5** | `0x20` | `Distributing` | **Distributing** (transmitting frames on this member) | Not distributing |
| **Bit 6** | `0x40` | `Defaulted` | **Defaulted** (no LACPDU received from partner yet) | Using real Partner LACPDU info |
| **Bit 7** | `0x80` | `Expired` | **Expired** (receive state machine timed out) | Normal operation |

**Common Operational Hex Combinations:**
* `0x47` (`0x01 + 0x02 + 0x04 + 0x40`): **Initial Unbundled Port** — Active, Short Timeout, Aggregatable, Defaulted (partner unknown).
* `0x3d` (`0x01 + 0x04 + 0x08 + 0x10 + 0x20`): **Healthy Slow-Timer Bundle (Default)** — Active, Long Timeout (`30`s), Aggregatable, In Sync, Collecting, Distributing.
* `0x3f` (`0x01 + 0x02 + 0x04 + 0x08 + 0x10 + 0x20`): **Healthy Fast-Timer Bundle** — Active, Short Timeout (`1`s), Aggregatable, In Sync, Collecting, Distributing.

### Example: LACP Port-Channel Bring-Up (`Defaulted` to `In-Sync Collecting/Distributing`)

```frameassembly
host tor_sw   { ip 10.0.2.1 mac 00:1c:73:11:22:33 }
host linux_hv { ip 10.0.2.2 mac 00:50:56:88:99:aa }

flow lacp_bond_negotiation(sw, hv) {
    // 1. Switch port comes up unbundled (0x47 = Active/Short/Agg/Defaulted) with zeroed Partner info
    sw -> hv lacp actor_sys 00:1c:73:11:22:33 actor_key 10 actor_port 1 actor_state 0x47 partner_sys 00:00:00:00:00:00 partner_key 0 partner_port 0 partner_state 0x00 wait 2ms

    // 2. Linux bond0 replies acknowledging the switch's System MAC/Key/Port and advertising In-Sync (0x0f)
    sw <- hv lacp actor_sys 00:50:56:88:99:aa actor_key 10 actor_port 1 actor_state 0x0f partner_sys 00:1c:73:11:22:33 partner_key 10 partner_port 1 partner_state 0x07 wait 2ms

    // 3. Both sides transition to full Collecting + Distributing (0x3f = Active/Short/Agg/Sync/Col/Dist)
    sw -> hv lacp actor_sys 00:1c:73:11:22:33 actor_key 10 actor_port 1 actor_state 0x3f partner_sys 00:50:56:88:99:aa partner_key 10 partner_port 1 partner_state 0x3f wait 2ms
    sw <- hv lacp actor_sys 00:50:56:88:99:aa actor_key 10 actor_port 1 actor_state 0x3f partner_sys 00:1c:73:11:22:33 partner_key 10 partner_port 1 partner_state 0x3f
}

compile {
    lacp_bond_negotiation(tor_sw, linux_hv)
}
```

---

## 6. IEEE 802.1X Port-Based Network Access Control (`EAPOL` — IEEE 802.1X / RFC 3748)

Testing campus 802.1X Network Access Control (`NAC`) policies or debugging why an IoT supplicant failed EAP-TLS onboarding usually means wrestling with `wpa_supplicant` certificates and a live RADIUS/ISE lab. FrameAssembly lets you script the entire `EAPOL` conversation (`EtherType = 0x888E`, destination MAC `01:80:c2:00:00:03`) between the **Supplicant** (client workstation or IoT endpoint) and the **Authenticator** (campus switch port or wireless AP)—from `EAPOL-Start` and Identity requests through EAP-TLS challenges, `EAP-Success`, and `EAPOL-Logoff`.

### Default Wire Behavior
* **4-Byte EAPOL Header:** `Protocol Version` (default `1`), `Packet Type` (`0` = `EAP_PACKET`, `1` = `START`, `2` = `LOGOFF`, `3` = `KEY`), and 16-bit `Body Length`.
* **Nested RFC 3748 EAP Frame (when `EAP_PACKET` is selected):**
  * For `EAP_CODE 1` (Request) and `EAP_CODE 2` (Response): Emits `Code (1B) | Identifier (1B) | Length (2B) | Method/Type (1B)` followed by `IDENTITY` string bytes and any `PAYLOAD` / `HEXPAYLOAD`.
  * For `EAP_CODE 3` (Success) and `EAP_CODE 4` (Failure) with no payload: Emits a strict 4-byte RFC 3748 §4.2 packet (`Code | Identifier | Length = 0x0004`) with no Method field.

### `EAPOL` Modifiers

| Modifier | Syntax | Values & Description | Default |
| :--- | :--- | :--- | :--- |
| **802.1X Version** | `VERSION <1..3>` | `1` (802.1X-2001), `2` (802.1X-2004), `3` (802.1X-2010/2020 MACsec) | `1` |
| **Packet Type** | `TYPE <START\|LOGOFF\|KEY\|EAP_PACKET>` | Or bare `START`, `LOGOFF`, `KEY`, `EAP_PACKET` | `EAP_PACKET` (`0`) |
| **EAP Code** | `EAP_CODE <1..4>` | `1` = Request, `2` = Response, `3` = Success, `4` = Failure | `1` (Request) |
| **EAP Identifier** | `EAP_ID <0..255>` | 8-bit correlation ID matching a Request to its Response | `1` |
| **EAP Method** | `EAP_METHOD <0..255>` | `1` = Identity, `4` = MD5-Challenge, `13` = EAP-TLS, `21` = TTLS, `25` = PEAP | `1` (Identity) |
| **User Identity** | `IDENTITY "<text>"` | Username or machine principal (e.g. `"host/wkstn01.corp.example.com"`) | Empty |

### Example: Complete 802.1X Supplicant Onboarding, EAP-TLS & Logoff

```frameassembly
host workstation { ip 10.50.10.25 mac 00:24:d7:11:22:33 }
host campus_sw   { ip 10.50.10.1  mac 00:1c:73:80:21:10 }

flow dot1x_port_authentication(supp, auth_sw) {
    // 1. Supplicant sends EAPOL-Start to 01:80:c2:00:00:03
    supp -> auth_sw eapol version 2 type start wait 2ms

    // 2. Switch requests EAP Identity (Code 1 = Request, Method 1 = Identity)
    supp <- auth_sw eapol version 2 type eap_packet eap_code 1 eap_id 1 eap_method 1 wait 2ms

    // 3. Supplicant responds with machine certificate identity (Code 2 = Response, Method 1 = Identity)
    supp -> auth_sw eapol version 2 type eap_packet eap_code 2 eap_id 1 eap_method 1 identity "host/wkstn-25.corp.internal" wait 5ms

    // 4. Switch initiates EAP-TLS (Method 13) challenge and Supplicant replies with TLS ClientHello fragment
    supp <- auth_sw eapol version 2 type eap_packet eap_code 1 eap_id 2 eap_method 13 hexpayload "20" wait 2ms
    supp -> auth_sw eapol version 2 type eap_packet eap_code 2 eap_id 2 eap_method 13 payload "EAP_TLS_CLIENT_CERT_VERIFY" wait 5ms

    // 5. Switch sends 4-byte EAP-Success (Code 3) and EAPOL-Key descriptor
    supp <- auth_sw eapol version 2 type eap_packet eap_code 3 eap_id 2 wait 2ms
    supp <- auth_sw eapol version 2 type key hexpayload "02008a00100000000000000001" wait 10ms

    // 6. Supplicant disconnects cleanly with EAPOL-Logoff
    supp -> auth_sw eapol version 2 type logoff
}

compile {
    dot1x_port_authentication(workstation, campus_sw)
}
```

---

## 7. Multiprotocol Label Switching (`MPLS` — RFC 3032 / RFC 5462)

Capturing real MPLS L3VPN or Segment Routing (`SR-MPLS`) packets normally requires a provider-edge (`PE`) router lab running LDP, RSVP-TE, or IS-IS segment routing just to put a 4-byte shim header on the wire. In FrameAssembly, adding an `MPLS` label (`EtherType = 0x8847`)—complete with 20-bit Label ID, 3-bit QoS Traffic Class (`EXP`/`TC`), Bottom-of-Stack (`BOS`) bit, and independent `MPLS_TTL`—takes a single modifier on any packet statement:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Label                  | EXP |S|       TTL     |
|               (20 bits)               |(3b) |1|    (8 bits)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Like `VLAN`, `MPLS` can be used both as a **standalone statement** (`a -> b mpls 16001`) and as a **cross-layer modifier** wrapping any L3/L4/L7 protocol (`ICMP`, `OSPF`, `BGP`, `TCP`, `UDP`, `HTTP`, `SNMP3`, etc.), optionally combined with outer `VLAN` or `QINQ` tags.

### `MPLS` Modifiers & Reserved Labels

| Modifier | Syntax & Aliases | Range | Wire Field & Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| **MPLS Label** | `MPLS <0..1048575>` or `LABEL <0..1048575>` | `0..1048575` | 20-bit MPLS Label (`0` = IPv4 Explicit Null, `2` = IPv6 Explicit Null, `3` = Implicit Null, `16+` = L3VPN / SR-MPLS) | `0` |
| **Traffic Class** | `EXP <0..7>` or `TC <0..7>` | `0..7` | 3-bit RFC 5462 Traffic Class (formerly Experimental) QoS bits | `0` |
| **Bottom of Stack**| `BOS <0\|1>` | `0..1` | 1-bit Bottom-of-Stack indicator (`1` = last label before IP header) | `1` |
| **MPLS Shim TTL** | `MPLS_TTL <0..255>` | `0..255` | 8-bit MPLS Time-To-Live (independent of inner IP `TTL`) | `64` |

### Example: Service Provider MPLS L3VPN & VLAN-Subinterface Forwarding

```frameassembly
host pe_west { ip 10.100.1.1 mac 00:1c:73:ce:00:01 }
host pe_east { ip 10.100.1.2 mac 00:1c:73:ce:00:02 }

flow mpls_l3vpn_and_sr_forwarding(west, east) {
    // 1. MPLS-labeled ICMPv4 echo across an L3VPN (Label 24010, EXP/TC 5 for Voice/EF, MPLS TTL 64, Inner IP TTL 63)
    west -> east mpls 24010 exp 5 bos 1 mpls_ttl 64 ttl 63 dscp 46 icmp echo_request id 501 seq 1 payload "L3VPN_PING" wait 1ms
    west <- east mpls 24020 tc 5 bos 1 mpls_ttl 63 ttl 62 dscp 46 icmp echo_reply id 501 seq 1 payload "L3VPN_PONG" wait 2ms

    // 2. 802.1Q VLAN 400 subinterface carrying an SR-MPLS labeled HTTPS flow
    west -> east vlan 400 pcp 5 mpls 16005 exp 5 bos 1 mpls_ttl 255 tcp syn srcport 51200 dstport 443 wait 1ms
    west <- east vlan 400 pcp 5 mpls 16001 exp 5 bos 1 mpls_ttl 254 tcp syn ack
}

compile {
    mpls_l3vpn_and_sr_forwarding(pe_west, pe_east)
}
```

**Inspect with `tshark`:**
```console
tshark -r output.pcap -Y "mpls" -T fields -e frame.number -e vlan.id -e mpls.label -e mpls.exp -e mpls.bottom -e mpls.ttl -e ip.ttl
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — End-to-end recipes for VLAN/QinQ/MPLS/QoS verification, firewall ACL testing, and network troubleshooting.
- [**Layer 3 Control, Tunneling, VPN & Routing Protocols (`l3_protocols.md`)**](l3_protocols.md) — Universal IPv4/IPv6 headers (`TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `DF`, `MF`), `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IKEV2`, `IPSEC`/`ESP`/`AH`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `PIM`, `VRRP`, `HSRP`, `BFD`, and `OPENFLOW`.
- [**Layer 4 Transport Protocols (`l4_transports.md`)**](l4_transports.md) — `TCP`, `UDP`, and `SCTP` 4-tuple state tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling.
- [**Layer 7 Infrastructure, Time, AAA & Flow Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — Pair `802.1X EAPOL` with `RADIUS`, `DHCP`, `DNS`, `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW`.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Complete EVPN-VXLAN leaf-spine fabric, Campus 802.1X NAC, and WAN QinQ/MPLS failover topologies.
- [**`.fasm` File Format & Media Type Specification (`fasm-specification.md`)**](fasm-specification.md) — Normative `text/vnd.frameassembly` media type specification, lexical rules, and `.fasm` extension disambiguation.
