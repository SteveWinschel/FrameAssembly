# Layer 4 — Stateful TCP, UDP & Telecom SCTP (`docs/l4_transports.md`)

[**Use Cases**](#layer-4-testing-and-security-use-cases) • [**Auto-SEQ & Checksums**](#what-frameassembly-handles-at-layer-4) • [**TCP Reference**](#1-tcp--stateful-streams-flags-and-rfc-7323-options) • [**UDP Reference**](#2-udp--stateless-datagrams-tunnels-and-broadcasts) • [**SCTP & Telecom PPIDs**](#3-sctp--multi-stream-associations-and-5gtelecom-ppids) • [**Inspect & Replay**](#inspecting-and-replaying-layer-4-captures)

## Why Use FrameAssembly for Layer 4?

Testing Layer 4 transport edge cases is where manual packet crafting usually falls apart.

Fire a single spoofed `PSH ACK` payload at a stateful firewall and it silently drops it because there was no 3-way handshake. Try to hand-craft a `TCP ZeroWindow` stall, a 3x Duplicate-ACK fast retransmit, or a 5G `NGAP` multi-stream `SCTP` association, and you are suddenly stuck computing TCP `SEQ`/`ACK` byte offsets on a notepad or debugging RFC 9260 Castagnoli `CRC-32c` checksums in Python :)

With **FrameAssembly**, the compiler tracks TCP ports and sequence numbers for you when you want clean streams—and steps out of the way the instant you want broken windows, stealth flag combinations, fragmented UDP bursts, or multi-homed `SCTP` failovers:

```frameassembly
host app_node { ip 10.20.1.10 mac 00:1b:21:aa:00:0a }
host db_srv   { ip 10.20.1.54 mac 00:1b:21:aa:00:36 }

flow quick_l4_demo(c, s) {
    // Stateful TCP: set ports once on SYN -> auto-swapped ports & exact SEQ/ACK math
    c -> s tcp syn srcport 52400 dstport 5432 win 64240 mss 1460 wscale 7 sack_perm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sack_perm wait 1ms
    c -> s tcp ack wait 1ms
    c -> s tcp psh ack payload "SELECT 1;" wait 2ms
    c <- s tcp psh ack payload "ROW 1" wait 2ms
    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile { quick_l4_demo(app_node, db_srv) }
```

```console
$ frameassembly show l4_demo.fasm
$ frameassembly l4_demo.fasm -o l4_demo.pcap && sudo tcpreplay -i eth0 l4_demo.pcap
```

| Protocol | Keyword | IP Proto | Checksum Engine | Best For |
| :--- | :--- | :---: | :--- | :--- |
| **TCP** | `tcp` | `6` | Auto IPv4/IPv6 Pseudo-Header | Stateful firewall rules, `ZeroWindow` stalls, fast retransmits, `ECN`, `PAWS`, stealth scans |
| **UDP** | `udp` | `17` | Auto IPv4/IPv6 Pseudo-Header | `RoCEv2` RDMA, `GTP-U` 5G bearers, `IPsec NAT-T`, `DTLS`, Paris Traceroute, `WoL` broadcasts |
| **SCTP** | `sctp` | `132` | Auto Castagnoli `CRC-32c` | 5G `NGAP`/`XnAP`/`F1AP`, 4G `S1AP`, `Diameter` `S6a`/`Gy`, `SIGTRAN` SS7, `WebRTC` DataChannels |

## Layer 4 Testing and Security Use Cases

### 1. Reproduce `TCP ZeroWindow` Stalls, 3x Dup-ACK Fast Retransmits & `PAWS` Wraparounds
Waiting for a production storage target to choke just to verify your packet broker or APM alerts on `TCP ZeroWindow` and `TCP Fast Retransmission` is no fun. Override `seq`, `acknum`, `win 0`, or 32-bit `tsval` timestamps (`2^32 - 1 -> 10`) to trigger Wireshark's TCP analysis flags on demand:

```frameassembly
host sender   { ip 10.20.0.10 mac 00:1b:21:aa:00:01 }
host receiver { ip 10.20.0.20 mac 00:1b:21:aa:00:02 }

flow tcp_anomalies(tx, rx) {
    tx -> rx tcp syn srcport 42000 dstport 9100 seq 1000 win 64240 mss 1460 wscale 7 sack_perm tsval 4294967294 tsecr 0 wait 1ms
    tx <- rx tcp syn ack seq 5000 acknum 1001 win 4096 mss 1460 wscale 7 sack_perm tsval 900000 tsecr 4294967294 wait 1ms
    tx -> rx tcp ack seq 1001 acknum 5001 win 64240 tsval 4294967295 tsecr 900000 wait 1ms

    // 1. Buffer fills -> receiver advertises ZeroWindow (win 0) -> 1-byte ZeroWindow probe -> recovery
    tx -> rx tcp psh ack seq 1001 acknum 5001 win 64240 tsval 10 tsecr 900000 payload "CHUNK_FILLING_BUFFER" wait 5ms
    tx <- rx tcp ack seq 5001 acknum 1021 win 0 tsval 900005 tsecr 10 wait 500ms
    tx -> rx tcp ack seq 1020 acknum 5001 win 64240 payload "Z" wait 5ms
    tx <- rx tcp ack seq 5001 acknum 1021 win 65535 wait 2ms

    // 2. Out-of-order segment (seq 1031 skips 1021..1030) -> Dup-ACK -> missing segment retransmit
    tx -> rx tcp psh ack seq 1031 acknum 5001 win 64240 payload "SEG_000003" wait 2ms
    tx <- rx tcp ack seq 5001 acknum 1021 win 65535 wait 1ms
    tx -> rx tcp psh ack seq 1021 acknum 5001 win 64240 payload "SEG_000002" wait 2ms
    tx <- rx tcp ack seq 5001 acknum 1041 win 65535
}

compile { tcp_anomalies(sender, receiver) }
```

### 2. Test DDoS `SYN` Proxies, Stateful Firewall `ACK` Rules & Stealth Flag Scans
Verify that inline DDoS scrubbers splice `SYN`-cookie sequence numbers properly and that **Suricata**, **Zeek**, or perimeter firewalls catch unsolicited `ACK` rule-mapping probes, Nmap `Xmas` scans (`fin psh urg`), and all-8-flag "Kamikaze" packets:

```frameassembly
host client  { ip 198.51.100.88 mac 00:16:3e:10:20:30 }
host mitigator { ip 203.0.113.10 mac 00:16:3e:40:50:60 }
host origin  { ip 10.200.80.10  mac 00:16:3e:70:80:90 }

flow syn_proxy_and_scan_audit(cli, proxy, srv) {
    // 1. DDoS SYN-Proxy split handshake: validate client ACK before opening backend TCP connection
    cli -> proxy tcp syn srcport 54888 dstport 443 seq 1000 win 64240 mss 1460 wait 1ms
    cli <- proxy tcp syn ack srcport 443 dstport 54888 seq 88442211 acknum 1001 win 0 mss 1460 wait 1ms
    cli -> proxy tcp psh ack srcport 54888 dstport 443 seq 1001 acknum 88442212 win 64240 payload "TLS_CLIENT_HELLO" wait 1ms
    proxy -> srv tcp syn srcport 54888 dstport 443 seq 1000 win 64240 mss 1460 wait 500us
    proxy <- srv tcp syn ack srcport 443 dstport 54888 seq 500000 acknum 1001 win 65535 mss 1460 wait 500us
    proxy -> srv tcp psh ack srcport 54888 dstport 443 seq 1001 acknum 500001 win 64240 payload "TLS_CLIENT_HELLO" wait 5ms

    // 2. Unsolicited ACK probe + Nmap Xmas scan (FIN+PSH+URG) + all-8-flags fuzz packet
    cli -> proxy tcp ack srcport 44100 dstport 22 seq 7777 acknum 1 win 4096 wait 2ms
    cli -> proxy tcp fin psh urg srcport 60001 dstport 22 win 1024 wait 2ms
    cli -> proxy tcp syn ack fin rst psh urg ece cwr srcport 65535 dstport 80 seq 424242 acknum 424242 win 8192 payload "ALL_8_FLAGS" wait 1ms
    cli <- proxy tcp rst ack srcport 80 dstport 65535 seq 0 acknum 424254 win 0
}

compile { syn_proxy_and_scan_audit(client, mitigator, origin) }
```

### 3. Simulate 5G `NGAP`, `Diameter` Charging & Multi-Homed `SCTP` Failovers
Spinning up a 5G Core (`Open5GS` / `free5GC`) or SS7 `SIGTRAN` stack just to test a firewall SCTP inspection policy or Wireshark dissector is overkill. FrameAssembly builds the 4-way `INIT` -> `COOKIE_ACK` handshake, multiplexes independent `stream` IDs with exact `ppid` codes, and computes Castagnoli `CRC-32c` checksums automatically:

```frameassembly
host gnb_n2  { ip 2001:db8:5000:a2::10 }
host amf_n2  { ip 2001:db8:5000:a2::1 }
host pgw_pri { ip 10.71.1.1 }
host ocs_pri { ip 10.71.1.10 }
host pgw_sec { ip 10.71.2.1 }
host ocs_sec { ip 10.71.2.10 }

flow sctp_5g_n2_setup(gnb, amf) {
    // 4-way SCTP Cookie handshake + 5G NGAP Setup on UDP-like message stream 0 (Port 38412, PPID 60)
    gnb -> amf dscp 46 sctp chunk init vtag 0 srcport 38412 dstport 38412 wait 1ms
    gnb <- amf dscp 46 sctp chunk init_ack vtag 384120 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk cookie_echo vtag 384120 srcport 38412 dstport 38412 payload "state_cookie_n2" wait 1ms
    gnb <- amf dscp 46 sctp chunk cookie_ack vtag 384120 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk data vtag 384120 stream 0 ssn 0 ppid 60 srcport 38412 dstport 38412 payload "ngap_ng_setup_request_gnb_001" wait 2ms
    gnb <- amf dscp 46 sctp chunk sack vtag 384120 srcport 38412 dstport 38412
}

flow sctp_multihomed_diameter_failover(p1, o1, p2, o2) {
    // Unanswered HEARTBEAT on primary path -> Diameter Gy (Port 3868, PPID 46) fails over to secondary path
    p1 -> o1 dscp 34 sctp chunk heartbeat vtag 710001 srcport 3868 dstport 3868 payload "hb_primary_probe" wait 50ms
    p2 -> o2 dscp 34 sctp chunk data vtag 710001 stream 1 ssn 10 ppid 46 srcport 3868 dstport 3868 payload "DIAMETER_CCR_FAILOVER_SECONDARY" wait 2ms
    p2 <- o2 dscp 34 sctp chunk sack vtag 710001 srcport 3868 dstport 3868
}

compile {
    sctp_5g_n2_setup(gnb_n2, amf_n2)
    sctp_multihomed_diameter_failover(pgw_pri, ocs_pri, pgw_sec, ocs_sec)
}
```

### 4. Craft Lossless AI `RoCEv2` (`ECN`/`CNP`), 5G `GTP-U` & `IPsec NAT-T` Over `UDP`
Many high-speed fabric and mobile user-plane protocols ride directly inside `UDP` (`4791` RoCEv2, `2152` GTPv1-U, `4500` IPsec NAT-T, `6635` MPLS-in-UDP). Combine outer `vlan`, `pcp`, `dscp`, `ecn`, and `df` modifiers with `hexpayload` to test switch QoS queues and tunnel middleboxes:

```frameassembly
host gpu_tx { ip 10.200.47.11 mac 0c:42:a1:2f:00:0b }
host gpu_rx { ip 10.200.47.12 mac 0c:42:a1:2f:00:0c }

flow rocev2_gtpu_and_natt(a, b) {
    // 1. RoCEv2 RDMA Write (UDP 4791) marked ECN=3 (CE) -> receiver returns Priority 6 CNP (Opcode 0x81)
    a -> b vlan 470 pcp 3 dscp 26 ecn 3 df udp srcport 53111 dstport 4791 hexpayload "0a40ffff0000020080000010" wait 50us
    a <- b vlan 470 pcp 6 dscp 48 ecn 0 df udp srcport 53111 dstport 4791 hexpayload "8100ffff000002000000000000000000" wait 2ms

    // 2. 5G N3 GTPv1-U Echo Request/Reply + G-PDU bearer packet on UDP 2152
    a -> b dscp 46 udp srcport 2152 dstport 2152 hexpayload "320100040000000000010000" wait 1ms
    a <- b dscp 46 udp srcport 2152 dstport 2152 hexpayload "3202000600000000000100000e00" wait 2ms

    // 3. RFC 3948 IPsec NAT-Traversal on UDP 4500: Non-ESP Marker (0x00000000) + 1-byte 0xff keepalive
    a -> b udp srcport 4500 dstport 4500 hexpayload "00000000a1b2c3d4e5f607181122334455667788" wait 5ms
    a -> b udp srcport 4500 dstport 4500 hexpayload "ff"
}

compile { rocev2_gtpu_and_natt(gpu_tx, gpu_rx) }
```

### 5. Build Paris Traceroutes (`TTL` Expiry), Fragmented `UDP` & `Wake-on-LAN` Broadcasts
Test how routers, NAT gateways, and SIEMs handle incrementing `TTL` UDP traceroute probes (`33434..33435`), multi-fragment `UDP` telemetry batches (`mf` + `fragoffset`), and directed `Wake-on-LAN` magic broadcasts (`UDP 9`):

```frameassembly
host workstation { ip 10.88.1.10  mac 00:50:56:88:01:0a }
host hop1_rtr    { ip 10.88.1.1   mac 00:1c:73:88:01:01 }
host target_srv  { ip 10.88.2.50  mac 00:50:56:88:02:32 }
host lan_bcast   { ip 10.88.1.255 mac ff:ff:ff:ff:ff:ff }

flow udp_diagnostics_and_wol(src, rtr, dst, bcast) {
    // 1. Paris Traceroute: TTL 1 -> ICMP Time Exceeded; TTL 2 -> ICMP Port Unreachable (Code 3)
    src -> rtr ttl 1 udp srcport 54321 dstport 33434 payload "paris_probe_hop1" wait 1ms
    src <- rtr icmp time_exceeded code 0 wait 2ms
    src -> dst ttl 2 udp srcport 54321 dstport 33435 payload "paris_probe_hop2" wait 1ms
    src <- dst icmp dest_unreach code 3 wait 5ms

    // 2. Fragmented IPv4 StatsD UDP batch sharing IPID 4242
    src -> dst ipid 4242 mf fragoffset 0 udp srcport 51000 dstport 8125 payload "statsd.batch.part_a:1|c" wait 500us
    src -> dst ipid 4242 fragoffset 185  udp srcport 51000 dstport 8125 payload "statsd.batch.part_b:1|c" wait 5ms

    // 3. Wake-on-LAN (WoL) magic packet broadcast on VLAN 25 UDP port 9
    src -> bcast vlan 25 dstmac ff:ff:ff:ff:ff:ff udp srcport 49152 dstport 9 hexpayload "ffffffffffff001b21aabbcc001b21aabbcc001b21aabbcc001b21aabbcc"
}

compile { udp_diagnostics_and_wol(workstation, hop1_rtr, target_srv, lan_bcast) }
```

## What FrameAssembly Handles at Layer 4

* **Two-Way Port Inheritance & Swapping:** Set `srcport` and `dstport` on the opening packet of a `flow(c, s)`. Every `c <- s` reply automatically flips the source and destination ports, and subsequent `c -> s` packets keep them aligned.
* **Automatic Stateful TCP `SEQ`/`ACK` Tracking:** Unless you explicitly override `seq` or `acknum`, FrameAssembly tracks sequence numbers across both directions (`+1` for `syn` and `fin`, plus exact payload byte length for `tcp` and every TCP-based Layer 7 protocol like `http`, `tls`, `ssh`, `bgp`, `smtp`, `redis`, `mqtt`, or `modbus`).
* **Zero-Config Checksums:** IPv4 and IPv6 pseudo-header checksums for `tcp` and `udp`—plus hardware-grade RFC 9260 Castagnoli **CRC-32c** checksums for `sctp`—are computed automatically on every frame.
* **Dual-Transport L7 Switching:** Building a Layer 7 flow (`dns`, `syslog`, `sip`, etc.) and want it over TCP instead of UDP (or vice versa)? Add `transport tcp` or `transport udp` directly on that Layer 7 line.

## Layer 4 Protocol Reference & Cheat Sheets

### 1. `TCP` — Stateful Streams, Flags and RFC 7323 Options

A bare `c -> s tcp` compiles into a valid RFC 793 `SYN` segment to `dstport 80`. Combine any of the **8 TCP flags** on a single statement (`syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`):

| Category | Modifier / Flag | Range / Example | Wire Behavior |
| :--- | :--- | :--- | :--- |
| **Ports** | `srcport <p>` / `dstport <p>` | `srcport 52100 dstport 443` | 16-bit TCP ports (inherited & flipped on `<-` replies) |
| **Control Flags** | `syn`, `ack`, `fin`, `rst`, `psh`, `urg` | `tcp fin psh urg` | Classic RFC 793 control bits (combinable in any order) |
| **ECN Flags** | `ece`, `cwr` | `tcp syn ece cwr` | RFC 3168 ECN-Echo & Congestion Window Reduced bits |
| **Sequence / Ack**| `seq <u32>` / `acknum <u32>` | `seq 1000 acknum 5001` | Overrides automatic TCP state-machine sequence/ack numbers |
| **Window Size** | `win <u16>` | `win 64240` / `win 0` | 16-bit receive window (`win 0` for `ZeroWindow` or `RST`) |
| **MSS Option** | `mss <u16>` | `mss 1460` / `mss 8960` | Option Kind `2`: Max Segment Size (`8960` for 9000B HPC jumbo) |
| **Window Scale** | `wscale <0..14>` | `wscale 7` / `wscale 14` | Option Kind `3`: RFC 7323 Window Scale shift count |
| **Selective ACK** | `sack_perm` | `sack_perm` | Option Kind `4`: RFC 2018 SACK Permitted negotiation flag |
| **Timestamps** | `tsval <u32>` / `tsecr <u32>` | `tsval 1000 tsecr 0` | Option Kind `8`: RFC 7323 RTTM & PAWS 32-bit timestamps |
| **Payload** | `payload "<str>"` / `hexpayload "<hex>"`| `payload "SELECT 1;"` | Raw ASCII or hex segment body (advances auto-`SEQ` by length) |

> **Quick Syntax Check (`ack` vs. `acknum`):** Bare `ack` sets the 1-bit TCP ACK flag, while `acknum <u32>` sets the 32-bit acknowledgment number (`c <- s tcp syn ack seq 5000 acknum 1001`). Likewise, always write `srcport` and `dstport` rather than `sport` / `dport`.

### 2. `UDP` — Stateless Datagrams, Tunnels and Broadcasts

A bare `tx -> rx udp` emits an empty RFC 768 datagram to `dstport 80` (handy for quick firewall or traceroute probes).

| Modifier | Example | Common Ports & Patterns |
| :--- | :--- | :--- |
| `srcport <0..65535>` | `srcport 53111` | Vary `srcport` across packets to test ECMP / NIC RSS hashing |
| `dstport <0..65535>` | `dstport 4791` | `7` Echo, `9` WoL, `53` DNS, `67`/`68` DHCP, `319`/`320` PTP, `500`/`4500` IPsec, `2152` GTP-U, `3784`/`3785` BFD, `4789` VXLAN, `4791` RoCEv2, `5246`/`5247` CAPWAP, `5684` DTLS, `6081` GENEVE, `6635` MPLS-in-UDP, `8125` StatsD, `33434+` Traceroute |
| `payload` / `hexpayload` | `hexpayload "ff"` | Binary tunnel headers (`GTP-U`, `RoCEv2` BTH, `DTLS` records, `NAT-T` keepalives) |

### 3. `SCTP` — Multi-Stream Associations and 5G/Telecom PPIDs

Every `sctp` frame specifies a `chunk` type (or defaults to `init` on a bare `a -> b sctp`) and automatically writes a valid 32-bit Castagnoli `CRC-32c` checksum.

| Modifier | Applies To | Default | What It Controls |
| :--- | :--- | :--- | :--- |
| `chunk <type>` | All `sctp` | `init` | `init`, `init_ack`, `cookie_echo`, `cookie_ack`, `data`, `sack`, `heartbeat`, `heartbeat_ack`, `shutdown`, `shutdown_ack`, `abort` |
| `vtag <u32>` | All `sctp` | `0` (`init`) | 32-bit Verification Tag (`0` on `init`; peer's tag on established/teardown chunks) |
| `stream <u16>` | `chunk data` | `0` | Independent Stream ID (`0..65535`) preventing Head-of-Line blocking |
| `ssn <u16>` | `chunk data` | `0` | Per-stream sequence number (`0, 1, 2...`) |
| `ppid <u32>` | `chunk data` | `0` | Payload Protocol ID—tells Wireshark and middleboxes which L7 dissector to run |
| `srcport` / `dstport`| All `sctp` | Ephemeral / `80` | 16-bit SCTP source and destination port numbers |

#### Handy 5G, Telecom & WebRTC `SCTP` Ports and `PPID`s

| Interface / Protocol | Typical Port | `ppid` | Example `.fasm` Snippet |
| :--- | :---: | :---: | :--- |
| **5G NGAP (`N2` gNB <-> AMF)** | `38412` | `60` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 60 srcport 38412 dstport 38412` |
| **5G XnAP (`Xn-C` gNB <-> gNB)** | `38422` | `61` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 61 srcport 38422 dstport 38422` |
| **5G O-RAN F1AP (`O-DU` <-> `CU-CP`)**| `38472` | `62` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 62 srcport 38472 dstport 38472` |
| **5G O-RAN E1AP (`CU-CP` <-> `CU-UP`)**| `38462` | `64` | `sctp chunk data vtag 100 stream 1 ssn 0 ppid 64 srcport 38462 dstport 38462` |
| **4G LTE S1AP / X2AP** | `36412` / `36422` | `18` / `27` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 18 srcport 36412 dstport 36412` |
| **Diameter (`S6a` / `Gy` / `Rx`)** | `3868` | `46` | `sctp chunk data vtag 100 stream 1 ssn 0 ppid 46 srcport 3868 dstport 3868` |
| **SIGTRAN `M2UA` / `M3UA` / `M2PA`** | `2904` / `2905` / `3565`| `2` / `3` / `5` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 3 srcport 2905 dstport 2905` |
| **SIGTRAN `SUA` / `H.248` Megaco** | `14001` / `2944` | `4` / `7` | `sctp chunk data vtag 100 stream 1 ssn 0 ppid 4 srcport 14001 dstport 14001` |
| **3G/4G Small-Cell `Iuh` (`RUA`/`HNBAP`)**| `29169` | `19` / `20` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 20 srcport 29169 dstport 29169` |
| **WebRTC DataChannel (`DCEP` / UTF-8)**| `5000` | `50` / `51` | `sctp chunk data vtag 100 stream 1 ssn 1 ppid 51 srcport 5000 dstport 5000` |

## Inspecting and Replaying Layer 4 Captures

```console
# Verify TCP SEQ/ACK progression, window sizes, and ZeroWindow / Fast Retransmission analysis flags
$ tshark -r tcp_anomalies.pcap -T fields -e frame.number -e tcp.seq -e tcp.ack -e tcp.window_size_value -e _ws.col.Info

# Inspect SCTP chunk types, Verification Tags, Stream IDs, PPIDs, and CRC-32c validation
$ tshark -r sctp_5g.pcap -Y "sctp" -T fields -e frame.number -e sctp.verif_tag -e sctp.chunk_type -e sctp.data_sid -e sctp.payload_proto_id

# Test stateful firewall / Suricata IDS detection on custom TCP scans or UDP tunnels
$ suricata -r syn_proxy_and_scan_audit.pcap -k none
$ sudo tcpreplay -i eth0 l4_demo.pcap
```

## Related Documentation

* [**Getting Started (`getting_started.md`)**](getting_started.md) — Core `host` / `flow` / `compile` mechanics, `wait` intervals, and `loop` blocks.
* [**Real-World Use Cases (`use_cases.md`)**](use_cases.md) — Copy-paste recipes for stateful firewall audits, QoS trunks, SNMPv3 alerts, and SIEM testing.
* [**Layer 2 — Switching & Data Link (`l2_protocols.md`)**](l2_protocols.md) — Wrap TCP, UDP, and SCTP flows in `vlan`, `qinq`, and `mpls` tags.
* [**Layer 3 — Network, Routing & Tunnels (`l3_protocols.md`)**](l3_protocols.md) — Native keywords for `vxlan`, `geneve`, `bfd`, `ikev2`, `esp`, and `wireguard`.
* [**Layer 7 — Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — First-class builders for `dns`, `dhcp`, `ntp`, `ptp`, `radius`, `syslog`, and `netflow`.
* [**Layer 7 — Web, Cloud, Security & VoIP (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md) — Dedicated builders for `http`, `http2`, `grpc`, `tls`, `quic`, `ssh`, `sip`, and `rtp`.