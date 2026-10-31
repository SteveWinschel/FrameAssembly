# Layer 2 Data Link Protocols & Encapsulation Reference

FrameAssembly supports **8 Layer 2 and Layer 2.5 protocols** natively—generating valid Ethernet II / IEEE 802.3 LLC framing, multicast MACs, and protocol TLVs automatically when optional fields are omitted.

| Protocol | Keyword | Standard | EtherType / Multicast MAC | Primary Use Cases |
| :--- | :--- | :--- | :--- | :--- |
| **ARP** | `ARP` | RFC 826 / 5227 | `0x0806` / `ff:ff:ff:ff:ff:ff` | Gateway MAC lookup, Gratuitous ARP (`GARP`) VIP failover, IP conflict probes |
| **VLAN** | `VLAN` | IEEE 802.1Q / 802.1p | `0x8100` | 12-bit VLAN ID (`1..4094`), 3-bit CoS priority (`PCP`), 1-bit drop bit (`DEI`) |
| **QinQ** | `QINQ` | IEEE 802.1ad | `0x88A8` (S-Tag) + `0x8100` (C-Tag) | Carrier Metro Ethernet double-tagging (`QINQ <s_vid> INNER_VLAN <c_vid>`) |
| **LLDP** | `LLDP` | IEEE 802.1AB | `0x88CC` / `01:80:c2:00:00:0e` | Chassis ID, Port ID, TTL, System Name, and System Description TLVs |
| **STP / RSTP**| `STP` | IEEE 802.1D / 802.1w | 802.3 LLC / `01:80:c2:00:00:00` | Root Bridge elections, RSTP Proposal/Agreement BPDUs, BPDU Guard tests |
| **LACP** | `LACP` | IEEE 802.3ad / 802.1AX| `0x8809` / `01:80:c2:00:00:02` | Port-Channel / LAG Actor & Partner state synchronization |
| **EAPOL** | `EAPOL` | IEEE 802.1X | `0x888E` / `01:80:c2:00:00:03` | Port NAC (`START`, `EAP_PACKET` Identity/MD5/TLS, WPA `KEY`, `LOGOFF`) |
| **MPLS** | `MPLS` | RFC 3031 / 3032 | `0x8847` | 20-bit label switching (`MPLS` / `LABEL`), Traffic Class (`EXP`), `BOS`, `MPLS_TTL` |

### Universal Ethernet II Header Overrides
Any statement in FrameAssembly also accepts outer Ethernet header overrides:
* `SRCMAC <mac>`: Overrides the 48-bit source MAC address.
* `DSTMAC <mac>`: Overrides the 48-bit destination MAC address.
* `ETHERTYPE <u16>`: Overrides the 16-bit EtherType field.

---

## 1. Address Resolution Protocol (`ARP` — RFC 826)

Maps IPv4 addresses (`0x0800`) to 48-bit Ethernet MAC addresses. *(If an `ARP` flow is run with IPv6 hosts in `compile`, FrameAssembly automatically emits an RFC 4861 ICMPv6 Neighbor Solicitation / Advertisement packet with Hop Limit `255`.)*

| Modifier | Syntax | Description | Default |
| :--- | :--- | :--- | :--- |
| **Operation** | `REQUEST` / `REPLY` | ARP Opcode (`1` = Request, `2` = Reply) | `REQUEST` (`1`) |
| **Gratuitous Mode**| `GRATUITOUS` or `GARP` | Sets Sender IP = Target IP for VIP failover or duplicate address detection | Disabled |
| **Sender MAC** | `SHA <mac>` or `SENDERMAC <mac>` | 48-bit Sender Hardware Address | Source host MAC |
| **Sender IP** | `SPA <ipv4>` or `SENDERIP <ipv4>` | 32-bit Sender Protocol Address | Source host IP |
| **Target MAC** | `THA <mac>` or `TARGETMAC <mac>` | 48-bit Target Hardware Address (`00:00:00:00:00:00` on Request) | Dest host MAC |
| **Target IP** | `TPA <ipv4>` or `TARGETIP <ipv4>` | 32-bit Target Protocol Address | Dest host IP |

```frameassembly
host workstation { ip 192.168.1.105 mac 00:50:56:a1:00:20 }
host gateway     { ip 192.168.1.1   mac 00:50:56:fe:00:01 }
host broadcast   { ip 192.168.1.255 mac ff:ff:ff:ff:ff:ff }

flow arp_and_failover_garp(client, gw, bcast) {
    // Standard broadcast ARP Request and unicast Reply
    client -> gw arp request dstmac ff:ff:ff:ff:ff:ff tha 00:00:00:00:00:00 wait 1ms
    client <- gw arp reply wait 5ms

    // RFC 5227 ARP Probe (senderip 0.0.0.0) followed by Gratuitous ARP VIP announcement
    gw -> bcast arp request sendermac 00:50:56:fe:00:01 senderip 0.0.0.0 targetmac 00:00:00:00:00:00 targetip 192.168.1.1 wait 5ms
    gw -> bcast arp reply gratuitous sendermac 00:50:56:fe:00:01 senderip 192.168.1.1 targetmac ff:ff:ff:ff:ff:ff targetip 192.168.1.1
}

compile {
    arp_and_failover_garp(workstation, gateway, broadcast)
}
```

---

## 2. Virtual LAN (`VLAN` — 802.1Q) & Provider Bridging (`QINQ` — 802.1ad)

Both `VLAN` and `QINQ` can be used as standalone Layer 2 frames or attached as modifiers to any upper-layer protocol (`TCP`, `UDP`, `HTTP`, `OSPF`, `SIP`, `MODBUS`, etc.).

| Modifier | Syntax | Range | Description |
| :--- | :--- | :--- | :--- |
| **802.1Q VLAN ID** | `VLAN <u16>` | `0..4095` | Inserts an 802.1Q tag (`0x8100`) with 12-bit VLAN ID |
| **Priority (CoS)** | `PCP <u8>` | `0..7` | 3-bit IEEE 802.1p priority (`5` = Voice, `6` = Control, `7` = Network) |
| **Drop Eligible** | `DEI <u8>` | `0..1` | 1-bit Drop Eligible Indicator for congestion policing |
| **Outer S-VLAN** | `QINQ <u16>` | `0..4095` | Inserts outer IEEE 802.1ad Service VLAN tag (`0x88A8`) |
| **Inner C-VLAN** | `INNER_VLAN <u16>` | `0..4095` | Sets inner Customer VLAN tag (`0x8100`) paired with `QINQ` |

> **Syntax Rule:** For double-tagged 802.1ad frames, always write `QINQ <outer_svid> INNER_VLAN <inner_cvid>`. Do not combine `QINQ` and `VLAN` on the same statement.

```frameassembly
host site_a { ip 172.20.10.1 mac 00:50:56:ce:0a:01 }
host site_b { ip 172.20.10.2 mac 00:50:56:ce:0b:02 }

flow trunk_and_qinq(a, b) {
    // Single-tagged 802.1Q voice and bulk frames
    a -> b vlan 100 pcp 5 dei 0 udp srcport 16384 dstport 16384 payload "VOICE_RTP" wait 1ms
    a -> b vlan 300 pcp 1 dei 1 udp srcport 49200 dstport 873 payload "BULK_BACKUP" wait 2ms

    // Double-tagged 802.1ad Metro Ethernet L2VPN carrying BGP
    a -> b qinq 2500 inner_vlan 40 pcp 6 tcp syn srcport 52000 dstport 179 wait 1ms
    a <- b qinq 2500 inner_vlan 40 pcp 6 tcp syn ack
}

compile {
    trunk_and_qinq(site_a, site_b)
}
```

---

## 3. Link Layer Discovery Protocol (`LLDP` — IEEE 802.1AB)

Advertises switch/server identity, interface names, and software versions to directly connected neighbors (`01:80:c2:00:00:0e`, EtherType `0x88CC`).

| Modifier | Syntax | TLV & Description |
| :--- | :--- | :--- |
| **Chassis ID** | `CHASSIS_ID "<str>"` | TLV Type `1` (Mandatory): Chassis MAC or identifier string |
| **Port ID** | `PORT_ID "<str>"` or `<u16>` | TLV Type `2` (Mandatory): Interface name (e.g. `"Ethernet1/1"`) or index |
| **Hold Time** | `TTL <u8>` | TLV Type `3` (Mandatory): Neighbor hold time in seconds (default `120`) |
| **System Name** | `SYSNAME "<str>"` | TLV Type `5` (Optional): Device FQDN / hostname |
| **System Desc** | `SYSDESC "<str>"` | TLV Type `6` (Optional): OS version and hardware platform string |

```frameassembly
host spine_sw { ip 10.255.0.1  mac 00:1c:73:a0:01:01 }
host leaf_sw  { ip 10.255.0.11 mac 00:1c:73:b0:11:49 }

flow lldp_neighbor_exchange(spine, leaf) {
    spine -> leaf lldp chassis_id "00:1c:73:a0:01:01" port_id "Ethernet1/1" ttl 120 sysname "spine-01.dc1" sysdesc "SONiC 202511 400G" wait 5ms
    spine <- leaf lldp chassis_id "00:1c:73:b0:11:49" port_id "Ethernet49/1" ttl 120 sysname "leaf-01.dc1" sysdesc "SONiC 202511 ToR"
}

compile {
    lldp_neighbor_exchange(spine_sw, leaf_sw)
}
```

---

## 4. Spanning Tree Protocol (`STP` / `RSTP` — IEEE 802.1D / 802.1w)

Emits classic STP Configuration BPDUs or 36-byte Rapid Spanning Tree (`RSTP`) BPDUs to `01:80:c2:00:00:00`.

| Modifier | Syntax | Description & Default |
| :--- | :--- | :--- |
| **Rapid STP** | `RSTP` | Emits IEEE 802.1w Version `2` Rapid Spanning Tree BPDU |
| **BPDU Flags** | `FLAGS <u8>` | Topology Change (`0x01`), Proposal (`0x02`), Role/State bits, TCA (`0x80`) |
| **Root Bridge ID**| `ROOT_ID "<prio>/<mac>"` | Root priority and MAC (e.g. `"4096/00:05:73:a0:00:01"`) |
| **Sender Bridge**| `BRIDGE_ID "<prio>/<mac>"` | Transmitting bridge priority and MAC |
| **Path Cost** | `COST <u32>` | Root path cost (`0` on root bridge, `2000` for 10GbE) |
| **Port & Timers** | `PORT_ID <u16>`, `MAX_AGE <u16>`, `HELLO_TIME <u16>`, `FORWARD_DELAY <u16>` | Port ID (`0x8001`) and timers (defaults: Max Age `20`s, Hello `2`s, Fwd Delay `15`s) |

```frameassembly
host root_sw   { ip 10.0.1.1 mac 00:05:73:a0:00:01 }
host access_sw { ip 10.0.1.2 mac 00:05:73:a0:00:02 }

flow rstp_proposal_agreement(root, acc) {
    root -> acc stp rstp root_id "4096/00:05:73:a0:00:01" bridge_id "4096/00:05:73:a0:00:01" cost 0 max_age 20 hello_time 2 forward_delay 15 flags 0x0e wait 2ms
    root <- acc stp rstp root_id "4096/00:05:73:a0:00:01" bridge_id "32768/00:05:73:a0:00:02" cost 2000 max_age 20 hello_time 2 forward_delay 15 flags 0x7c
}

compile {
    rstp_proposal_agreement(root_sw, access_sw)
}
```

---

## 5. Link Aggregation Control Protocol (`LACP` — IEEE 802.3ad)

Negotiates dynamic LAG / Port-Channel bundles (`01:80:c2:00:00:02`, EtherType `0x8809`).

| Modifier | Syntax | Description |
| :--- | :--- | :--- |
| **Actor Fields** | `ACTOR_SYS <mac>`, `ACTOR_KEY <u16>`, `ACTOR_PORT <u16>`, `ACTOR_STATE <u8>` | Local switch system MAC, admin key, port number, and state bitmask (`0x3f` = Active/Short/Agg/Sync/Col/Dist) |
| **Partner Fields**| `PARTNER_SYS <mac>`, `PARTNER_KEY <u16>`, `PARTNER_PORT <u16>`, `PARTNER_STATE <u8>` | Remote peer's system MAC, key, port, and state bitmask |

```frameassembly
host sw_a { ip 10.0.2.1 mac 00:e0:f7:01:02:03 }
host sw_b { ip 10.0.2.2 mac 00:e0:f7:04:05:06 }

flow lacp_port_channel_sync(a, b) {
    a -> b lacp actor_sys 00:e0:f7:01:02:03 actor_key 100 actor_port 1 actor_state 0x47 partner_sys 00:00:00:00:00:00 partner_key 0 partner_port 0 partner_state 0x00 wait 5ms
    a <- b lacp actor_sys 00:e0:f7:04:05:06 actor_key 100 actor_port 1 actor_state 0x3f partner_sys 00:e0:f7:01:02:03 partner_key 100 partner_port 1 partner_state 0x3f wait 5ms
    a -> b lacp actor_sys 00:e0:f7:01:02:03 actor_key 100 actor_port 1 actor_state 0x3f partner_sys 00:e0:f7:04:05:06 partner_key 100 partner_port 1 partner_state 0x3f
}

compile {
    lacp_port_channel_sync(sw_a, sw_b)
}
```

---

## 6. 802.1X Port Authentication (`EAPOL`) & MPLS (`MPLS`)

### `EAPOL` Modifiers (EtherType `0x888E`)
* `VERSION <1|2|3>`: 802.1X version (`2` = 2004, `3` = 2010/2020).
* `TYPE <START|LOGOFF|KEY|EAP_PACKET>`: Always include the `TYPE` keyword before the packet type.
* `EAP_CODE <1..4>`: `1` = Request, `2` = Response, `3` = Success, `4` = Failure.
* `EAP_ID <u8>`, `EAP_METHOD <u8>` (`1` = Identity, `4` = MD5, `13` = EAP-TLS, `25` = PEAP), `IDENTITY "<str>"`.

### `MPLS` Modifiers (EtherType `0x8847`)
* `MPLS <0..1048575>` (or `LABEL <u20>`): 20-bit MPLS label value.
* `EXP <0..7>` (or `TC <0..7>`): 3-bit Traffic Class QoS marking.
* `BOS <0|1>`: Bottom-of-Stack bit (`1` default).
* `MPLS_TTL <0..255>`: MPLS shim TTL independent of the inner IP TTL (`64` default).

```frameassembly
host laptop   { ip 10.50.10.25 mac 00:24:d7:11:22:33 }
host auth_sw  { ip 10.50.10.1  mac 00:1c:73:80:21:10 }

flow dot1x_and_mpls_forwarding(supp, sw) {
    // 802.1X EAP-TLS onboarding
    supp -> sw eapol version 2 type start wait 2ms
    supp <- sw eapol version 2 type eap_packet eap_code 1 eap_id 1 eap_method 1 wait 2ms
    supp -> sw eapol version 2 type eap_packet eap_code 2 eap_id 1 eap_method 1 identity "host/laptop.corp" wait 2ms
    supp <- sw eapol version 2 type eap_packet eap_code 3 eap_id 1 wait 5ms

    // MPLS L3VPN labeled ICMP exchange
    supp -> sw mpls 24010 exp 5 bos 1 mpls_ttl 64 icmp echo_request id 301 seq 1 payload "VRF_PING" wait 2ms
    supp <- sw mpls 24020 exp 5 bos 1 mpls_ttl 63 icmp echo_reply id 301 seq 1 payload "VRF_PONG"
}

compile {
    dot1x_and_mpls_forwarding(laptop, auth_sw)
}
```