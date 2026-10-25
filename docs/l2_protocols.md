# Layer 2 Data Link Protocols & Encapsulation Reference

FrameAssembly provides native, zero-dependency packet crafting and wire encapsulation for all eight IEEE and IETF Layer 2 (Data Link) and Layer 2.5 protocols: **ARP (RFC 826)**, **VLAN (IEEE 802.1Q)**, **QINQ (IEEE 802.1ad)**, **LLDP (IEEE 802.1AB)**, **STP / RSTP (IEEE 802.1D / 802.1w)**, **LACP (IEEE 802.3ad / 802.1AX)**, **EAPOL (IEEE 802.1X)**, and **MPLS (RFC 3031 / RFC 3032)**.

Every Layer 2 protocol compiles with RFC-compliant default fields when optional modifiers are omitted and supports granular field overrides for switch fabric simulation, carrier Ethernet testing, Network Access Control (NAC) verification, and security dataset generation.

---

## 1. Layer 2 Protocol Architecture & RFC Summary

| Protocol | Keyword | Standard RFC / IEEE | EtherType / Multicast MAC | Corpus Directory | Key Capabilities |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ARP** | `ARP` | RFC 826 / RFC 5227 | `0x0806` / `ff:ff:ff:ff:ff:ff` | [`examples/l2/arp/`](../examples/l2/arp) | Address resolution, gratuitous ARP (`GARP`), proxy ARP, DAD |
| **VLAN** | `VLAN` | IEEE 802.1Q / 802.1p | `0x8100` | [`examples/l2/vlan/`](../examples/l2/vlan) | 12-bit VID (`0..4095`), 3-bit `PCP` CoS (`0..7`), 1-bit `DEI` |
| **QINQ** | `QINQ` | IEEE 802.1ad | `0x88A8` (S-Tag) + `0x8100` (C-Tag) | [`examples/l2/qinq/`](../examples/l2/qinq) | Provider bridging double-tagging (`QINQ <s_vid> INNER_VLAN <c_vid>`) |
| **LLDP** | `LLDP` | IEEE 802.1AB | `0x88CC` / `01:80:c2:00:00:0e` | [`examples/l2/lldp/`](../examples/l2/lldp) | Chassis ID, Port ID, TTL, System Name, System Description TLVs |
| **STP** | `STP` | IEEE 802.1D / 802.1w | `0x0026` (802.3 LLC) / `01:80:c2:00:00:00` | [`examples/l2/stp/`](../examples/l2/stp) | Classic STP and `RSTP` BPDUs, root elections, path cost, timers |
| **LACP** | `LACP` | IEEE 802.3ad / 802.1AX | `0x8809` / `01:80:c2:00:00:02` | [`examples/l2/lacp/`](../examples/l2/lacp) | Link aggregation Actor/Partner system MAC, key, port, state machine |
| **EAPOL** | `EAPOL` | IEEE 802.1X-2020 | `0x888E` / `01:80:c2:00:00:03` | [`examples/l2/eapol/`](../examples/l2/eapol) | `START`, `LOGOFF`, `KEY`, and `EAP_PACKET` (Identity, MD5, TLS) |
| **MPLS** | `MPLS` | RFC 3031 / RFC 3032 | `0x8847` (unicast) | [`examples/l2/mpls/`](../examples/l2/mpls) | 20-bit label switching (`LABEL`), 3-bit `EXP`, `BOS`, `MPLS_TTL` |

### Universal Ethernet II Header Overrides
In addition to protocol-specific modifiers, any frame statement in FrameAssembly accepts Ethernet II header overrides:
- `SRCMAC <mac>` (or `SRC_MAC <mac>`): Overrides the 48-bit source MAC address in the outer Ethernet II frame header.
- `DSTMAC <mac>` (or `DST_MAC <mac>`): Overrides the 48-bit destination MAC address in the outer Ethernet II frame header.
- `ETHERTYPE <u16>` (or `ETHER_TYPE <u16>`): Overrides the 16-bit EtherType field in the outer Ethernet II frame header.

---

## 2. Address Resolution Protocol (`ARP` — RFC 826)

The Address Resolution Protocol maps IPv4 network addresses (`0x0800`) to 48-bit IEEE 802 Ethernet hardware addresses (`0x0001`). When `ARP` is used between IPv6 endpoints in a polymorphic dual-stack flow, the compiler automatically synthesizes an RFC 4861 ICMPv6 Neighbor Solicitation / Advertisement frame with default IPv6 Hop Limit `255`.

### 2.1 Wire Format & Header Layout (28 Bytes)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Hardware Type (1)       |     Protocol Type (0x0800)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  HW Size (6)  | Proto Size(4) |          Opcode (1/2)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender Hardware Address (Bytes 0-3)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sender HW Addr (Bytes 4-5)   |   Sender Protocol IP (0-1)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Sender Protocol IP (2-3)    |   Target HW Addr (Bytes 0-1)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Hardware Address (Bytes 2-5)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Protocol IP Address (Bytes 0-3)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Canonical `ARP` Modifiers

| Modifier | Syntax | Description | Wire Default |
| :--- | :--- | :--- | :--- |
| **Operation** | `REQUEST` / `REPLY` | Sets ARP Opcode (`1` = Request, `2` = Reply) | `1` (Request) |
| **Gratuitous Mode** | `GRATUITOUS` or `GARP` | Sets Sender IP equal to Target IP for failover / DAD announcements | Disabled |
| **Sender MAC** | `SHA <mac>` or `SENDERMAC <mac>` | Overrides 48-bit Sender Hardware Address | Source Host MAC |
| **Sender IP** | `SPA <ipv4>` or `SENDERIP <ipv4>` | Overrides 32-bit Sender Protocol Address | Source Host IP |
| **Target MAC** | `THA <mac>` or `TARGETMAC <mac>` | Overrides 48-bit Target Hardware Address (`00:00:00:00:00:00` on Request) | Destination Host MAC |
| **Target IP** | `TPA <ipv4>` or `TARGETIP <ipv4>` | Overrides 32-bit Target Protocol Address | Destination Host IP |

### 2.3 Verified `ARP` Examples

```frameassembly
// PROMPT: Standard ARP request and unicast reply cycle resolving the default gateway hardware address.
// TOKENS: HOST, IP, MAC, FLOW, ARP, REQUEST, REPLY, SHA, SPA, THA, TPA, WAIT, COMPILE

// INSTRUCTION: Declare the enterprise workstation host.
HOST workstation {
    IP 192.168.1.105
    MAC 00:50:56:a1:00:20
}

// INSTRUCTION: Declare the local subnet default gateway router.
HOST default_gateway {
    IP 192.168.1.1
    MAC 00:50:56:fe:00:01
}

// INSTRUCTION: Define standard ARP resolution using explicit SHA, SPA, THA, and TPA fields.
FLOW arp_gateway_resolution(client, gw) {
    client -> gw ARP REQUEST SHA 00:50:56:a1:00:20 SPA 192.168.1.105 THA 00:00:00:00:00:00 TPA 192.168.1.1 WAIT 1ms
    client <- gw ARP REPLY SHA 00:50:56:fe:00:01 SPA 192.168.1.1 THA 00:50:56:a1:00:20 TPA 192.168.1.105 WAIT 1ms
}

// INSTRUCTION: Compile the ARP resolution exchange.
COMPILE {
    arp_gateway_resolution(workstation, default_gateway)
}
```

```frameassembly
// PROMPT: Gratuitous ARP (GARP) failover announcement and RFC 5227 Address Conflict Detection probe.
// TOKENS: HOST, IP, MAC, FLOW, ARP, REQUEST, REPLY, GRATUITOUS, GARP, SENDERMAC, SENDERIP, TARGETMAC, TARGETIP, WAIT, COMPILE

// INSTRUCTION: Declare the active high-availability load balancer node claiming a virtual IP.
HOST ha_node_primary {
    IP 10.0.0.10
    MAC 00:0c:29:88:99:aa
}

// INSTRUCTION: Declare the Layer 2 broadcast target for the subnet.
HOST subnet_broadcast {
    IP 10.0.0.255
    MAC ff:ff:ff:ff:ff:ff
}

// INSTRUCTION: Define an RFC 5227 ARP Probe (SENDERIP 0.0.0.0) followed by Gratuitous ARP announcements.
FLOW garp_failover_sequence(node, bcast) {
    node -> bcast ARP REQUEST SENDERMAC 00:0c:29:88:99:aa SENDERIP 0.0.0.0 TARGETMAC 00:00:00:00:00:00 TARGETIP 10.0.0.10 WAIT 5ms
    node -> bcast ARP REQUEST GRATUITOUS SENDERMAC 00:0c:29:88:99:aa SENDERIP 10.0.0.10 TARGETMAC ff:ff:ff:ff:ff:ff TARGETIP 10.0.0.10 WAIT 5ms
    node -> bcast ARP REPLY GARP SENDERMAC 00:0c:29:88:99:aa SENDERIP 10.0.0.10 TARGETMAC ff:ff:ff:ff:ff:ff TARGETIP 10.0.0.10 WAIT 5ms
}

// INSTRUCTION: Compile the ACD probe and Gratuitous ARP announcement frames.
COMPILE {
    garp_failover_sequence(ha_node_primary, subnet_broadcast)
}
```

---

## 3. Virtual LAN (`VLAN` — IEEE 802.1Q) & Provider Bridging (`QINQ` — IEEE 802.1ad)

FrameAssembly supports both standalone Layer 2 `VLAN` / `QINQ` frames and universal `VLAN` / `QINQ` modifiers attached to any upper-layer protocol (such as `TCP`, `UDP`, `HTTP`, `OSPF`, or `SIP`).

### 3.1 IEEE 802.1Q / 802.1ad Tag Control Information (TCI)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       TPID (0x8100 / 0x88A8)  | PCP |D|      VID (12 bits)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Canonical `VLAN` and `QINQ` Modifiers

| Modifier | Syntax | Range | Description |
| :--- | :--- | :--- | :--- |
| **802.1Q VLAN ID** | `VLAN <u16>` | `0..4095` | Inserts an 802.1Q tag (`0x8100`) with the specified 12-bit VLAN Identifier |
| **Priority Code Point** | `PCP <u8>` | `0..7` | Sets the 3-bit IEEE 802.1p Class of Service priority (`5` = Voice, `6` = Control, `7` = Network) |
| **Drop Eligible** | `DEI <u8>` | `0..1` | Sets the 1-bit Drop Eligible Indicator for congestion policing |
| **802.1ad Outer S-Tag** | `QINQ <u16>` | `0..4095` | Inserts an outer IEEE 802.1ad Service VLAN tag (`0x88A8`) |
| **802.1ad Inner C-Tag** | `INNER_VLAN <u16>` | `0..4095` | Sets the inner Customer VLAN ID (`0x8100`) paired with `QINQ <s_vid>` |

> **Important Syntax Rule**: When specifying double-tagged 802.1ad frames, always write `QINQ <outer_svid> INNER_VLAN <inner_cvid> [PCP <pcp>] [DEI <dei>]`. Do not combine `QINQ` and `VLAN` on the same statement; use `INNER_VLAN` for the customer tag inside `QINQ`.

### 3.3 Verified `VLAN` and `QINQ` Examples

```frameassembly
// PROMPT: Enterprise campus trunk carrying multi-CoS 802.1Q VLAN tagged voice, video, and scavenger traffic.
// TOKENS: HOST, IP, MAC, FLOW, VLAN, PCP, DEI, UDP, DSTPORT, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare access switch trunk interface.
HOST access_switch {
    IP 10.100.1.10
    MAC 00:1c:73:aa:00:10
}

// INSTRUCTION: Declare distribution switch trunk interface.
HOST dist_switch {
    IP 10.100.1.1
    MAC 00:1c:73:aa:00:01
}

// INSTRUCTION: Define multi-VLAN trunk traffic spanning Voice (VLAN 100, PCP 5), Video (VLAN 200, PCP 4), and Bulk (VLAN 300, PCP 1, DEI 1).
FLOW campus_trunk_cos(acc, dist) {
    acc -> dist VLAN 100 PCP 5 DEI 0 UDP SRCPORT 16384 DSTPORT 16384 PAYLOAD "VOICE_G711_RTP_FRAME" WAIT 1ms
    acc -> dist VLAN 200 PCP 4 DEI 0 UDP SRCPORT 5004 DSTPORT 5004 PAYLOAD "VIDEO_H264_KEYFRAME" WAIT 1ms
    acc -> dist VLAN 300 PCP 1 DEI 1 UDP SRCPORT 49200 DSTPORT 873 PAYLOAD "BACKUP_RSYNC_BULK_CHUNK" WAIT 1ms
}

// INSTRUCTION: Compile the 802.1Q CoS trunk capture.
COMPILE {
    campus_trunk_cos(access_switch, dist_switch)
}
```

```frameassembly
// PROMPT: Carrier Metro Ethernet IEEE 802.1ad QinQ tunnel encapsulating customer C-VLANs inside provider S-VLANs.
// TOKENS: HOST, IP, MAC, FLOW, QINQ, INNER_VLAN, PCP, DEI, TCP, SYN, ACK, PSH, SRCPORT, DSTPORT, SEQ, ACKNUM, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Customer Edge router at Site A.
HOST ce_site_a {
    IP 172.20.10.1
    MAC 00:50:56:ce:0a:01
}

// INSTRUCTION: Declare Customer Edge router at Site B.
HOST ce_site_b {
    IP 172.20.10.2
    MAC 00:50:56:ce:0b:02
}

// INSTRUCTION: Define a double-tagged 802.1ad QinQ flow using outer S-VLAN 2500 and inner C-VLAN 40.
FLOW carrier_qinq_l2vpn(site_a, site_b) {
    site_a -> site_b QINQ 2500 INNER_VLAN 40 PCP 6 DEI 0 TCP SYN SRCPORT 52000 DSTPORT 179 SEQ 1000 WAIT 1ms
    site_a <- site_b QINQ 2500 INNER_VLAN 40 PCP 6 DEI 0 TCP SYN ACK SRCPORT 179 DSTPORT 52000 SEQ 2000 ACKNUM 1001 WAIT 1ms
    site_a -> site_b QINQ 2500 INNER_VLAN 40 PCP 6 DEI 0 TCP PSH ACK SRCPORT 52000 DSTPORT 179 SEQ 1001 ACKNUM 2001 PAYLOAD "BGP_OVER_QINQ_KEEPALIVE" WAIT 1ms
}

// INSTRUCTION: Compile the IEEE 802.1ad QinQ L2VPN exchange.
COMPILE {
    carrier_qinq_l2vpn(ce_site_a, ce_site_b)
}
```

---

## 4. Link Layer Discovery Protocol (`LLDP` — IEEE 802.1AB)

LLDP enables network interfaces to advertise their identity, system name, software description, and port capabilities to directly attached neighbors via Ethernet multicast address `01:80:c2:00:00:0e` and EtherType `0x88CC`.

### 4.1 Canonical `LLDP` Modifiers

| Modifier | Syntax | Argument Type | TLV Type & Description |
| :--- | :--- | :--- | :--- |
| **Chassis ID** | `CHASSIS_ID "<str>"` | Quoted string | TLV Type `1` (Mandatory): Chassis identifier string or MAC |
| **Port ID** | `PORT_ID "<str>"` or `PORT_ID <u16>` | String or `u16` | TLV Type `2` (Mandatory): Interface name (e.g. `"Ethernet1/1"`) or port index |
| **Time to Live** | `TTL <u8>` | `u8` (`0..255`) | TLV Type `3` (Mandatory): Neighbor hold time in seconds (default `120`) |
| **System Name** | `SYSNAME "<str>"` | Quoted string | TLV Type `5` (Optional): Fully qualified hostname of the switch/router |
| **System Description**| `SYSDESC "<str>"` | Quoted string | TLV Type `6` (Optional): NOS version, platform model, and build metadata |

### 4.2 Verified `LLDP` Example

```frameassembly
// PROMPT: Bidirectional LLDP topology discovery between a leaf switch and a spine switch in a Clos fabric.
// TOKENS: HOST, IP, MAC, FLOW, LLDP, CHASSIS_ID, PORT_ID, TTL, SYSNAME, SYSDESC, WAIT, COMPILE

// INSTRUCTION: Declare Spine Switch 01 interface Ethernet1/1.
HOST spine_node {
    IP 10.255.0.1
    MAC 00:1c:73:a0:01:01
}

// INSTRUCTION: Declare Leaf Switch 01 uplink interface Ethernet49/1.
HOST leaf_node {
    IP 10.255.0.11
    MAC 00:1c:73:b0:11:49
}

// INSTRUCTION: Exchange complete LLDP neighbor discovery frames with mandatory and optional TLVs.
FLOW clos_lldp_discovery(spine, leaf) {
    spine -> leaf LLDP CHASSIS_ID "00:1c:73:a0:01:01" PORT_ID "Ethernet1/1" TTL 120 SYSNAME "spine-01.dc1.example.com" SYSDESC "SONiC OS 202511 Switch-ASIC-25.6T" WAIT 5ms
    spine <- leaf LLDP CHASSIS_ID "00:1c:73:b0:11:49" PORT_ID "Ethernet49/1" TTL 120 SYSNAME "leaf-01.dc1.example.com" SYSDESC "SONiC OS 202511 ToR-400G" WAIT 5ms
}

// INSTRUCTION: Compile the bidirectional LLDP exchange.
COMPILE {
    clos_lldp_discovery(spine_node, leaf_node)
}
```

---

## 5. Spanning Tree Protocol (`STP` / `RSTP` — IEEE 802.1D / 802.1w)

STP and Rapid Spanning Tree Protocol (`RSTP`) prevent Layer 2 bridging loops by electing a Root Bridge and calculating loop-free active topologies via Bridge Protocol Data Units (BPDUs) sent to `01:80:c2:00:00:00`.

### 5.1 Canonical `STP` Modifiers

| Modifier | Syntax | Argument Type | Description & Wire Default |
| :--- | :--- | :--- | :--- |
| **Rapid STP Mode** | `RSTP` | Flag (0-arg) | Emits 36-byte IEEE 802.1w Rapid Spanning Tree BPDU (Version `2`, Type `0x02`, trailing `Version 1 Length = 0x00`) |
| **BPDU Flags** | `FLAGS <u8>` | `u8` (`0x00..0xFF`) | Sets Topology Change (`0x01`), Proposal (`0x02`), Role, Learning/Forwarding, TCA (`0x80`) |
| **Root Bridge ID** | `ROOTID "<str>"` or `ROOT_ID "<str>"` | Quoted string | Root Bridge priority/MAC string (e.g. `"4096/00:1c:73:00:00:01"`) encoded as 8-byte Bridge ID |
| **Transmitting Bridge**| `BRIDGEID "<str>"` or `BRIDGE_ID "<str>"` | Quoted string | Sender Bridge priority/MAC string (e.g. `"32768/00:1c:73:00:02:01"`) encoded as 8-byte Bridge ID |
| **Root Path Cost** | `COST <u32>` | `u32` | Cumulative path cost to Root Bridge (`0` for root bridge, `2000` for 10GbE) |
| **Port Identifier** | `PORT_ID <u16>` | `u16` | 16-bit STP Port Priority and Port Number (`0x8001` default) |
| **Max Age Timer** | `MAX_AGE <u16>` | `u16` | Maximum BPDU age before topology reconvergence (default `20` seconds) |
| **Hello Time** | `HELLO_TIME <u16>` | `u16` | Interval between Root Bridge configuration BPDUs (default `2` seconds) |
| **Forward Delay** | `FORWARD_DELAY <u16>`| `u16` | Listening/Learning state transition delay (default `15` seconds) |

### 5.2 Verified `STP` and `RSTP` Example

```frameassembly
// PROMPT: Root bridge election and Rapid Spanning Tree (RSTP) proposal-agreement synchronization.
// TOKENS: HOST, IP, MAC, FLOW, STP, RSTP, FLAGS, ROOT_ID, BRIDGE_ID, COST, MAX_AGE, HELLO_TIME, FORWARD_DELAY, WAIT, COMPILE

// INSTRUCTION: Declare the elected Root Bridge switch (Priority 4096).
HOST root_switch {
    IP 10.0.1.1
    MAC 00:05:73:a0:00:01
}

// INSTRUCTION: Declare the downstream Designated Bridge switch (Priority 32768).
HOST downstream_switch {
    IP 10.0.1.2
    MAC 00:05:73:a0:00:02
}

// INSTRUCTION: Define classic STP root BPDU advertisement followed by RSTP Proposal and Agreement BPDUs.
FLOW stp_and_rstp_convergence(root, access) {
    root -> access STP ROOT_ID "4096/00:05:73:a0:00:01" BRIDGE_ID "4096/00:05:73:a0:00:01" COST 0 MAX_AGE 20 HELLO_TIME 2 FORWARD_DELAY 15 FLAGS 0x00 WAIT 2ms
    root -> access STP RSTP ROOT_ID "4096/00:05:73:a0:00:01" BRIDGE_ID "4096/00:05:73:a0:00:01" COST 0 MAX_AGE 20 HELLO_TIME 2 FORWARD_DELAY 15 FLAGS 0x0e WAIT 2ms
    root <- access STP RSTP ROOT_ID "4096/00:05:73:a0:00:01" BRIDGE_ID "32768/00:05:73:a0:00:02" COST 2000 MAX_AGE 20 HELLO_TIME 2 FORWARD_DELAY 15 FLAGS 0x7c WAIT 2ms
}

// INSTRUCTION: Compile the STP and RSTP BPDU sequence.
COMPILE {
    stp_and_rstp_convergence(root_switch, downstream_switch)
}
```

---

## 6. Link Aggregation Control Protocol (`LACP` — IEEE 802.3ad / 802.1AX)

LACP negotiates dynamic link aggregation groups (LAGs / Port-Channels) using Slow Protocols EtherType `0x8809` (Subtype `0x01`) sent to `01:80:c2:00:00:02`.

### 6.1 Canonical `LACP` Modifiers

| Modifier | Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **Actor System MAC** | `ACTOR_SYS <mac>` | 48-bit MAC | Transmitting switch's LACP System Identifier MAC |
| **Actor Key** | `ACTOR_KEY <u16>` | `u16` | Administrative aggregation key assigned to the Actor port |
| **Actor Port Number** | `ACTOR_PORT <u16>` | `u16` | Physical port index on the Actor switch |
| **Actor State Byte** | `ACTOR_STATE <u8>` | `u8` (`0x00..0xFF`)| Bitmask (`0x3d` = Active/Long/Agg/Sync/Col/Dist; `0x3f` = Active/Short/Agg/Sync/Col/Dist) |
| **Partner System MAC**| `PARTNER_SYS <mac>` | 48-bit MAC | Remote peer's LACP System Identifier MAC learned by the Actor |
| **Partner Key** | `PARTNER_KEY <u16>` | `u16` | Remote peer's operational aggregation key |
| **Partner Port** | `PARTNER_PORT <u16>`| `u16` | Remote peer's physical port index |
| **Partner State Byte**| `PARTNER_STATE <u8>`| `u8` (`0x00..0xFF`)| Remote peer's LACP state bitmask |

### 6.2 Verified `LACP` Example

```frameassembly
// PROMPT: IEEE 802.3ad LACP fast-rate Port-Channel negotiation from initial defaulted state to full collecting/distributing sync.
// TOKENS: HOST, IP, MAC, FLOW, LACP, ACTOR_SYS, ACTOR_KEY, ACTOR_PORT, ACTOR_STATE, PARTNER_SYS, PARTNER_KEY, PARTNER_PORT, PARTNER_STATE, WAIT, COMPILE

// INSTRUCTION: Declare ToR Switch A member port.
HOST tor_switch_a {
    IP 10.0.2.1
    MAC 00:e0:f7:01:02:03
}

// INSTRUCTION: Declare Spine Switch B member port.
HOST spine_switch_b {
    IP 10.0.2.2
    MAC 00:e0:f7:04:05:06
}

// INSTRUCTION: Negotiate LACP Port-Channel 100 from unbundled (0x47) to synchronized collecting/distributing (0x3f).
FLOW lacp_lag_bringup(swa, swb) {
    swa -> swb LACP ACTOR_SYS 00:e0:f7:01:02:03 ACTOR_KEY 100 ACTOR_PORT 1 ACTOR_STATE 0x47 PARTNER_SYS 00:00:00:00:00:00 PARTNER_KEY 0 PARTNER_PORT 0 PARTNER_STATE 0x00 WAIT 5ms
    swa <- swb LACP ACTOR_SYS 00:e0:f7:04:05:06 ACTOR_KEY 100 ACTOR_PORT 1 ACTOR_STATE 0x0f PARTNER_SYS 00:e0:f7:01:02:03 PARTNER_KEY 100 PARTNER_PORT 1 PARTNER_STATE 0x07 WAIT 5ms
    swa -> swb LACP ACTOR_SYS 00:e0:f7:01:02:03 ACTOR_KEY 100 ACTOR_PORT 1 ACTOR_STATE 0x3f PARTNER_SYS 00:e0:f7:04:05:06 PARTNER_KEY 100 PARTNER_PORT 1 PARTNER_STATE 0x3f WAIT 5ms
    swa <- swb LACP ACTOR_SYS 00:e0:f7:04:05:06 ACTOR_KEY 100 ACTOR_PORT 1 ACTOR_STATE 0x3f PARTNER_SYS 00:e0:f7:01:02:03 PARTNER_KEY 100 PARTNER_PORT 1 PARTNER_STATE 0x3f WAIT 5ms
}

// INSTRUCTION: Compile the LACP state machine bringup flow.
COMPILE {
    lacp_lag_bringup(tor_switch_a, spine_switch_b)
}
```

---

## 7. Extensible Authentication Protocol over LAN (`EAPOL` — IEEE 802.1X)

EAPOL provides port-based Network Access Control (NAC) over EtherType `0x888E` between an 802.1X Supplicant (client workstation/IoT device) and an Authenticator (access switch or wireless controller).

### 7.1 Canonical `EAPOL` Modifiers

| Modifier | Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **Protocol Version** | `VERSION <u8>` | `u8` (`1`, `2`, `3`) | IEEE 802.1X protocol version (`1` = 2001, `2` = 2004, `3` = 2010/2020) |
| **Packet Type** | `TYPE <START\|LOGOFF\|KEY\|EAP_PACKET>` | Keyword | Sets EAPOL Packet Type (`START` = 1, `LOGOFF` = 2, `KEY` = 3, `EAP_PACKET` = 0) |
| **EAP Code** | `EAP_CODE <u8>` | `u8` (`1..4`) | `1` = Request, `2` = Response, `3` = Success, `4` = Failure (RFC 3748 §4.2: Codes `3` and `4` emit a 4-byte EAP header without a `Type` byte when payload is empty) |
| **EAP Identifier** | `EAP_ID <u8>` | `u8` (`0..255`) | Matches EAP Responses to EAP Requests |
| **EAP Method Type** | `EAP_METHOD <u8>` | `u8` | `1` = Identity, `4` = MD5-Challenge, `13` = EAP-TLS, `25` = PEAP |
| **Identity String** | `IDENTITY "<str>"` | Quoted string | Populates the EAP Identity string payload |

> **Important Syntax Rule**: Always prefix the EAPOL packet type keyword with `TYPE` (e.g., `EAPOL VERSION 2 TYPE START`, `EAPOL VERSION 2 TYPE EAP_PACKET`, `EAPOL VERSION 2 TYPE KEY`, `EAPOL VERSION 2 TYPE LOGOFF`).

### 7.2 Verified `EAPOL` Example

```frameassembly
// PROMPT: Complete IEEE 802.1X EAP-TLS port authentication lifecycle from EAPOL-Start to EAP-Success and WPA2 4-way EAPOL-Key handshake.
// TOKENS: HOST, IP, MAC, FLOW, EAPOL, VERSION, TYPE, START, EAP_PACKET, EAP_CODE, EAP_ID, EAP_METHOD, IDENTITY, KEY, LOGOFF, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare the 802.1X supplicant endpoint.
HOST corp_laptop {
    IP 10.50.10.25
    MAC 00:24:d7:11:22:33
}

// INSTRUCTION: Declare the 802.1X authenticator switch port.
HOST dot1x_switch {
    IP 10.50.10.1
    MAC 00:1c:73:80:21:10
}

// INSTRUCTION: Define the 802.1X EAP-TLS authentication, EAP-Success, EAPOL-Key exchange, and EAPOL-Logoff.
FLOW dot1x_eap_tls_lifecycle(supp, auth) {
    supp -> auth EAPOL VERSION 2 TYPE START WAIT 2ms
    supp <- auth EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 1 EAP_ID 1 EAP_METHOD 1 WAIT 2ms
    supp -> auth EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 2 EAP_ID 1 EAP_METHOD 1 IDENTITY "host/corp-laptop.corp.example.com" WAIT 2ms
    supp <- auth EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 1 EAP_ID 2 EAP_METHOD 13 PAYLOAD "EAP_TLS_START" WAIT 4ms
    supp -> auth EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 2 EAP_ID 2 EAP_METHOD 13 PAYLOAD "EAP_TLS_CLIENT_HELLO_CERT" WAIT 4ms
    supp <- auth EAPOL VERSION 2 TYPE EAP_PACKET EAP_CODE 3 EAP_ID 2 WAIT 2ms
    supp <- auth EAPOL VERSION 2 TYPE KEY PAYLOAD "WPA2_ANONCE_MSG1" WAIT 2ms
    supp -> auth EAPOL VERSION 2 TYPE KEY PAYLOAD "WPA2_SNONCE_MIC_MSG2" WAIT 2ms
    supp -> auth EAPOL VERSION 2 TYPE LOGOFF WAIT 2ms
}

// INSTRUCTION: Compile the IEEE 802.1X EAPOL lifecycle.
COMPILE {
    dot1x_eap_tls_lifecycle(corp_laptop, dot1x_switch)
}
```

---

## 8. Multi-Protocol Label Switching (`MPLS` — RFC 3031 / RFC 3032)

MPLS inserts a 32-bit shim header (EtherType `0x8847`) carrying a 20-bit label, 3-bit Traffic Class (`EXP`), 1-bit Bottom-of-Stack (`BOS`), and 8-bit `MPLS_TTL`. It can be used as a standalone Layer 2.5 protocol or as an encapsulation modifier on any L3/L4/L7 statement.

### 8.1 Canonical `MPLS` Modifiers

| Modifier | Syntax | Range | Description & Default |
| :--- | :--- | :--- | :--- |
| **Label (Primary)** | `MPLS <u20>` or `LABEL <u20>` | `0..1048575` | Sets 20-bit MPLS label value (use either `MPLS <label>` or `LABEL <label>`, not both) |
| **Traffic Class** | `EXP <u8>` or `TC <u8>` | `0..7` | Sets 3-bit MPLS Experimental / Traffic Class QoS bits (default `0`) |
| **Bottom of Stack** | `BOS <u8>` | `0..1` | Sets 1-bit Bottom-of-Stack indicator (`1` = innermost label, default `1`) |
| **MPLS Hop Limit** | `MPLS_TTL <u8>` | `0..255` | Sets 8-bit MPLS shim TTL independent of the inner IP TTL (default `64`) |

### 8.2 Verified `MPLS` Example

```frameassembly
// PROMPT: Service provider MPLS L3VPN label switching with Traffic Engineering EXP markings and Penultimate Hop Popping (PHP).
// TOKENS: HOST, IP, MAC, FLOW, MPLS, EXP, BOS, MPLS_TTL, ICMP, ECHO_REQUEST, ECHO_REPLY, ID, SEQ, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare Ingress Provider Edge router (PE1).
HOST ingress_pe1 {
    IP 10.250.0.1
    MAC 00:1c:73:f0:00:01
}

// INSTRUCTION: Declare Egress Provider Edge router (PE2).
HOST egress_pe2 {
    IP 10.250.0.2
    MAC 00:1c:73:f0:00:02
}

// INSTRUCTION: Define an MPLS-labeled ICMP customer probe with explicit EXP 5 QoS and MPLS_TTL decrement.
FLOW mpls_l3vpn_forwarding(pe1, pe2) {
    pe1 -> pe2 MPLS 24010 EXP 5 BOS 1 MPLS_TTL 64 ICMP ECHO_REQUEST ID 3001 SEQ 1 PAYLOAD "L3VPN_VRF_FINANCE_PING" WAIT 2ms
    pe1 <- pe2 MPLS 24020 EXP 5 BOS 1 MPLS_TTL 63 ICMP ECHO_REPLY ID 3001 SEQ 1 PAYLOAD "L3VPN_VRF_FINANCE_PONG" WAIT 2ms
}

// INSTRUCTION: Compile the MPLS L3VPN forwarding capture.
COMPILE {
    mpls_l3vpn_forwarding(ingress_pe1, egress_pe2)
}
```
