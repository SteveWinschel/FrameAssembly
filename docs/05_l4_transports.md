# Layer 4: Stateful TCP, UDP Tunnels & Telecom SCTP

[← Main README](../README.md) • [Docs Index](README.md) • [Use-Case Cookbook](02_use_cases.md)

A stateful firewall that receives one lonely `psh ack` with no handshake behind it does the only reasonable thing: it drops the packet and tells nobody. Your carefully spoofed payload never reaches the logs, and you spend an afternoon wondering whether the rule is wrong or the packet is. The usual fix is a notepad full of TCP sequence numbers. The fix for SCTP is a Python script that computes the Castagnoli `CRC-32c` and is, statistically, off by one byte.

FrameAssembly tracks TCP ports, `seq`, and `acknum` for you while you want a valid stream, and gets out of the way the moment you want it broken: a zero window, a skipped segment, a Christmas-tree flag combination, a fragmented UDP burst, a multi-homed SCTP failover. IPv4 and IPv6 pseudo-header checksums and SCTP `CRC-32c` are computed on every frame.

* **Port inheritance:** set `srcport` and `dstport` on the opening packet of a `flow(c, s)`. Replies flip them automatically, and later packets in the original direction keep them aligned.
* **Automatic TCP state:** unless you override `seq` or `acknum`, sequence numbers advance across both directions (`+1` for `syn` and `fin`, plus the payload length). That includes every TCP-based Layer 7 protocol: `http`, `tls`, `ssh`, `bgp`, `smtp`, `redis`, `mqtt`, `modbus`, and the rest.
* **Transport switching:** want `dns`, `syslog`, `sip`, or another dual-transport Layer 7 protocol over TCP instead of UDP, or the other way around? Add `transport tcp` or `transport udp` on that line.

| Protocol | Keyword | IP Proto | Checksum | Typical Use |
| :--- | :--- | :---: | :--- | :--- |
| **TCP** | `tcp` | `6` | IPv4/IPv6 pseudo-header | Firewall rules, ZeroWindow stalls, fast retransmits, ECN, PAWS, stealth scans |
| **UDP** | `udp` | `17` | IPv4/IPv6 pseudo-header | RoCEv2, GTP-U, IPsec NAT-T, DTLS, Paris traceroute, Wake-on-LAN |
| **SCTP** | `sctp` | `132` | Castagnoli `CRC-32c` | 5G NGAP/XnAP/F1AP, 4G S1AP, Diameter, SIGTRAN, WebRTC DataChannels |

---

## 1. `tcp`: Valid Streams, and Streams Broken on Purpose

A bare `tcp` statement compiles into a valid RFC 793 `syn` segment to `dstport 80`. Set the ports once on the `syn` and the rest of the conversation follows.

```frameassembly
host app_node { ip 10.20.1.10 mac 00:1b:21:aa:00:0a }
host db_srv   { ip 10.20.1.54 mac 00:1b:21:aa:00:36 }

flow tcp_session(c, s) {
    // Ports set once on the SYN. Replies flip them; seq and acknum are tracked automatically.
    c -> s tcp syn srcport 52400 dstport 5432 win 64240 mss 1460 wscale 7 sackperm wait 1ms
    c <- s tcp syn ack win 65535 mss 1460 wscale 7 sackperm wait 1ms
    c -> s tcp ack wait 1ms
    c -> s tcp psh ack payload "SELECT 1;" wait 2ms
    c <- s tcp psh ack payload "ROW 1" wait 2ms
    c -> s tcp fin ack wait 1ms
    c <- s tcp fin ack wait 1ms
    c -> s tcp ack
}

compile { tcp_session(app_node, db_srv) }
```

```console
$ frameassembly show tcp_session.frasm
$ frameassembly tcp_session.frasm tcp_session.pcap && sudo tcpreplay -i eth0 tcp_session.pcap
```

### Reproducing ZeroWindow, Dup-ACK and PAWS on demand

Waiting for a production storage target to choke so you can confirm your packet broker flags TCP ZeroWindow is a bad plan. Override `seq`, `acknum`, `win 0`, or the 32-bit `tsval` and Wireshark's TCP analysis lights up exactly when you want it to.

ZeroWindow stall, one-byte probe, and recovery (the timestamps start close to `2^32` to exercise PAWS wraparound):

```frameassembly
host sender   { ip 10.20.0.10 mac 00:1b:21:aa:00:01 }
host receiver { ip 10.20.0.20 mac 00:1b:21:aa:00:02 }

flow tcp_zerowindow(tx, rx) {
    tx -> rx tcp syn srcport 42000 dstport 9100 seq 1000 win 64240 mss 1460 wscale 7 sackperm tsval 4294967294 tsecr 0 wait 1ms
    tx <- rx tcp syn ack seq 5000 acknum 1001 win 4096 mss 1460 wscale 7 sackperm tsval 900000 tsecr 4294967294 wait 1ms
    tx -> rx tcp ack seq 1001 acknum 5001 win 64240 tsval 4294967295 tsecr 900000 wait 1ms

    // Buffer fills, receiver advertises win 0, sender sends a 1-byte probe, window reopens
    tx -> rx tcp psh ack seq 1001 acknum 5001 win 64240 tsval 10 tsecr 900000 payload "CHUNK_FILLING_BUFFER" wait 5ms
    tx <- rx tcp ack seq 5001 acknum 1021 win 0 tsval 900005 tsecr 10 wait 500ms
    tx -> rx tcp ack seq 1020 acknum 5001 win 64240 payload "Z" wait 5ms
    tx <- rx tcp ack seq 5001 acknum 1021 win 65535
}

compile { tcp_zerowindow(sender, receiver) }
```

Out-of-order segment, Dup-ACK, retransmit (the `seq 1031` segment skips `1021..1030`):

```frameassembly
host sender   { ip 10.20.0.10 mac 00:1b:21:aa:00:01 }
host receiver { ip 10.20.0.20 mac 00:1b:21:aa:00:02 }

flow tcp_dupack(tx, rx) {
    tx -> rx tcp syn srcport 42000 dstport 9100 seq 1000 win 64240 wait 1ms
    tx <- rx tcp syn ack seq 5000 acknum 1001 win 65535 wait 1ms
    tx -> rx tcp ack seq 1001 acknum 5001 win 64240 wait 1ms

    tx -> rx tcp psh ack seq 1001 acknum 5001 win 64240 payload "SEG_000001_" wait 1ms
    tx <- rx tcp ack seq 5001 acknum 1012 win 65535 wait 1ms
    tx -> rx tcp psh ack seq 1022 acknum 5001 win 64240 payload "SEG_000003" wait 2ms
    tx <- rx tcp ack seq 5001 acknum 1012 win 65535 wait 1ms
    tx -> rx tcp psh ack seq 1012 acknum 5001 win 64240 payload "SEG_000002" wait 2ms
    tx <- rx tcp ack seq 5001 acknum 1032 win 65535
}

compile { tcp_dupack(sender, receiver) }
```

### SYN proxies, stateful `ack` rules and stealth scans

Do inline DDoS scrubbers splice `syn`-cookie sequence numbers correctly? Do Suricata, Zeek, or the perimeter firewall notice an unsolicited `ack`, an Nmap Xmas scan (`fin psh urg`), or a packet with all eight flags lit up?

```frameassembly
host client    { ip 198.51.100.88 mac 00:16:3e:10:20:30 }
host mitigator { ip 203.0.113.10  mac 00:16:3e:40:50:60 }
host origin    { ip 10.200.80.10  mac 00:16:3e:70:80:90 }

flow syn_proxy_split_handshake(cli, proxy, srv) {
    // Proxy validates the client ACK before opening the backend connection
    cli -> proxy tcp syn srcport 54888 dstport 443 seq 1000 win 64240 mss 1460 wait 1ms
    cli <- proxy tcp syn ack srcport 443 dstport 54888 seq 88442211 acknum 1001 win 0 mss 1460 wait 1ms
    cli -> proxy tcp psh ack srcport 54888 dstport 443 seq 1001 acknum 88442212 win 64240 payload "TLS_CLIENT_HELLO" wait 1ms
    proxy -> srv tcp syn srcport 54888 dstport 443 seq 1000 win 64240 mss 1460 wait 500us
    proxy <- srv tcp syn ack srcport 443 dstport 54888 seq 500000 acknum 1001 win 65535 mss 1460 wait 500us
    proxy -> srv tcp psh ack srcport 54888 dstport 443 seq 1001 acknum 500001 win 64240 payload "TLS_CLIENT_HELLO"
}

flow stealth_probes(cli, proxy) {
    // Unsolicited ACK, Xmas scan, and an all-8-flags fuzz packet
    cli -> proxy tcp ack srcport 44100 dstport 22 seq 7777 acknum 1 win 4096 wait 2ms
    cli -> proxy tcp fin psh urg srcport 60001 dstport 22 win 1024 wait 2ms
    cli -> proxy tcp syn ack fin rst psh urg ece cwr srcport 65535 dstport 80 seq 424242 acknum 424242 win 8192 payload "ALL_8_FLAGS" wait 1ms
    cli <- proxy tcp rst ack srcport 80 dstport 65535 seq 0 acknum 424254 win 0
}

compile {
    syn_proxy_split_handshake(client, mitigator, origin)
    stealth_probes(client, mitigator)
}
```

### Modifier & Wire Cheat-Sheet: `tcp`

| Category | Modifier / Flag | Example | Wire Behavior |
| :--- | :--- | :--- | :--- |
| **Ports** | `srcport <p>` / `dstport <p>` | `srcport 52100 dstport 443` | 16-bit ports, inherited, and flipped on replies |
| **Control flags** | `syn`, `ack`, `fin`, `rst`, `psh`, `urg` | `tcp fin psh urg` | RFC 793 control bits, combinable in any order |
| **ECN flags** | `ece`, `cwr` | `tcp syn ece cwr` | RFC 3168 ECN-Echo and Congestion Window Reduced |
| **Sequence / ack** | `seq <u32>` / `acknum <u32>` | `seq 1000 acknum 5001` | Overrides the automatic sequence and acknowledgment numbers |
| **Window** | `win <u16>` | `win 64240` / `win 0` | 16-bit receive window (`win 0` for ZeroWindow or `rst`) |
| **MSS option** | `mss <u16>` | `mss 1460` / `mss 8960` | Option Kind `2` (`8960` for 9000-byte jumbo frames) |
| **Window scale** | `wscale <0..14>` | `wscale 7` | Option Kind `3`, RFC 7323 shift count |
| **SACK permitted** | `sackperm` | `sackperm` | Option Kind `4`, RFC 2018 |
| **Timestamps** | `tsval <u32>` / `tsecr <u32>` | `tsval 1000 tsecr 0` | Option Kind `8`, RFC 7323 RTTM and PAWS |
| **Payload** | `payload "<str>"` / `hexpayload "<hex>"` | `payload "SELECT 1;"` | Segment body; advances the automatic `seq` by its length |

Bare `ack` sets the 1-bit ACK flag. `acknum <u32>` sets the 32-bit acknowledgment number: `tcp syn ack seq 5000 acknum 1001` uses both. Ports are always `srcport` and `dstport`, never `sport` or `dport`.

---

## 2. `udp`: Tunnels, Traceroutes and Checksums You Did Not Compute

A bare `udp` statement emits an empty RFC 768 datagram to `dstport 80`, which is handy as a firewall or traceroute probe. The pseudo-header checksum is filled in for IPv4 and IPv6 alike, so the usual IPv6 surprise (UDP checksum is mandatory there) is handled before it becomes your problem.

Many fast fabrics and mobile user planes live directly inside `udp`: RoCEv2 on `4791`, GTP-U on `2152`, IPsec NAT-T on `4500`, MPLS-in-UDP on `6635`. Combine the outer `vlan`, `pcp`, `dscp`, `ecn`, and `df` modifiers with `hexpayload` to exercise switch QoS queues and tunnel middleboxes.

```frameassembly
host gpu_tx { ip 10.200.47.11 mac 0c:42:a1:2f:00:0b }
host gpu_rx { ip 10.200.47.12 mac 0c:42:a1:2f:00:0c }

flow rocev2_gtpu_natt(a, b) {
    // RoCEv2 RDMA write marked ECN CE (3); the receiver answers with a priority 6 CNP
    a -> b vlan 470 pcp 3 dscp 26 ecn 3 df udp srcport 53111 dstport 4791 hexpayload "0a40ffff0000020080000010" wait 50us
    a <- b vlan 470 pcp 6 dscp 48 ecn 0 df udp srcport 53111 dstport 4791 hexpayload "8100ffff000002000000000000000000" wait 2ms

    // 5G N3 GTPv1-U echo request and reply on UDP 2152
    a -> b dscp 46 udp srcport 2152 dstport 2152 hexpayload "320100040000000000010000" wait 1ms
    a <- b dscp 46 udp srcport 2152 dstport 2152 hexpayload "3202000600000000000100000e00" wait 2ms

    // RFC 3948 NAT-T on UDP 4500: Non-ESP Marker, then a 1-byte 0xff keepalive
    a -> b udp srcport 4500 dstport 4500 hexpayload "00000000a1b2c3d4e5f607181122334455667788" wait 5ms
    a -> b udp srcport 4500 dstport 4500 hexpayload "ff"
}

compile { rocev2_gtpu_natt(gpu_tx, gpu_rx) }
```

Paris-style traceroute with `ttl` expiry, a fragmented StatsD batch, and a Wake-on-LAN broadcast:

```frameassembly
host workstation { ip 10.88.1.10 mac 00:50:56:88:01:0a }
host hop1_rtr    { ip 10.88.1.1  mac 00:1c:73:88:01:01 }
host target_srv  { ip 10.88.2.50 mac 00:50:56:88:02:32 }
host lan_bcast   { ip 10.88.1.255 mac ff:ff:ff:ff:ff:ff }

flow udp_diagnostics(src, rtr, dst, bcast) {
    // TTL 1 expires at the first hop; TTL 2 reaches the target and draws Port Unreachable
    src -> rtr ttl 1 udp srcport 54321 dstport 33434 payload "paris_probe_hop1" wait 1ms
    src <- rtr icmp timeexceeded code 0 wait 2ms
    src -> dst ttl 2 udp srcport 54321 dstport 33435 payload "paris_probe_hop2" wait 1ms
    src <- dst icmp destunreach code 3 wait 5ms

    // Two IPv4 fragments sharing IPID 4242
    src -> dst ipid 4242 mf fragoffset 0 udp srcport 51000 dstport 8125 payload "statsd.batch.part_a:1|c" wait 500us
    src -> dst ipid 4242 fragoffset 185 udp srcport 51000 dstport 8125 payload "statsd.batch.part_b:1|c" wait 5ms

    // Wake-on-LAN magic packet on VLAN 25, UDP port 9
    src -> bcast vlan 25 dstmac ff:ff:ff:ff:ff:ff udp srcport 49152 dstport 9 hexpayload "ffffffffffff001b21aabbcc001b21aabbcc001b21aabbcc001b21aabbcc"
}

compile { udp_diagnostics(workstation, hop1_rtr, target_srv, lan_bcast) }
```

### Modifier & Wire Cheat-Sheet: `udp`

| Modifier | Example | Notes |
| :--- | :--- | :--- |
| `srcport <0..65535>` | `srcport 53111` | Vary it across packets to test ECMP and NIC RSS hashing |
| `dstport <0..65535>` | `dstport 4791` | `7` Echo, `9` WoL, `53` DNS, `67`/`68` DHCP, `319`/`320` PTP, `500`/`4500` IPsec, `2152` GTP-U, `3784`/`3785` BFD, `4789` VXLAN, `4791` RoCEv2, `5246`/`5247` CAPWAP, `5684` DTLS, `6081` GENEVE, `6635` MPLS-in-UDP, `8125` StatsD, `33434+` traceroute |
| `payload` / `hexpayload` | `hexpayload "ff"` | Binary tunnel headers: GTP-U, RoCEv2 BTH, DTLS records, NAT-T keepalives |
| `ttl`, `dscp`, `ecn`, `df`, `mf`, `ipid`, `fragoffset` | `ttl 1`, `ecn 3` | Outer IP header controls (IPv4 TTL, IPv6 Hop Limit) |

---

## 3. `sctp`: 5G and SIGTRAN Associations Without a Core Network

Standing up Open5GS, free5GC, or an SS7 SIGTRAN stack just to check a firewall's SCTP inspection policy is a lot of ceremony for one policy. `sctp` builds the 4-way `init`, `initack`, `cookieecho`, `cookieack` handshake, multiplexes independent `stream` IDs with the correct `ppid`, and computes the `CRC-32c` checksum. A bare `sctp` statement defaults to `chunk init`.

5G NGAP setup between a gNB and an AMF over IPv6 (port `38412`, PPID `60`):

```frameassembly
host gnb_n2 { ip 2001:db8:5000:a2::10 }
host amf_n2 { ip 2001:db8:5000:a2::1 }

flow sctp_5g_n2_setup(gnb, amf) {
    gnb -> amf dscp 46 sctp chunk init vtag 0 srcport 38412 dstport 38412 wait 1ms
    gnb <- amf dscp 46 sctp chunk initack vtag 384120 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk cookieecho vtag 384120 srcport 38412 dstport 38412 payload "state_cookie_n2" wait 1ms
    gnb <- amf dscp 46 sctp chunk cookieack vtag 384120 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk data vtag 384120 stream 0 ssn 0 ppid 60 srcport 38412 dstport 38412 payload "ngap_ng_setup_request_gnb_001" wait 2ms
    gnb <- amf dscp 46 sctp chunk sack vtag 384120 srcport 38412 dstport 38412
}

compile { sctp_5g_n2_setup(gnb_n2, amf_n2) }
```

Multi-homed Diameter failover: the primary path's heartbeat goes unanswered, so Gy traffic (port `3868`, PPID `46`) moves to the secondary path:

```frameassembly
host pgw_pri { ip 10.71.1.1 }
host ocs_pri { ip 10.71.1.10 }
host pgw_sec { ip 10.71.2.1 }
host ocs_sec { ip 10.71.2.10 }

flow sctp_diameter_failover(p1, o1, p2, o2) {
    p1 -> o1 dscp 34 sctp chunk heartbeat vtag 710001 srcport 3868 dstport 3868 payload "hb_primary_probe" wait 50ms
    p2 -> o2 dscp 34 sctp chunk data vtag 710001 stream 1 ssn 10 ppid 46 srcport 3868 dstport 3868 payload "DIAMETER_CCR_FAILOVER_SECONDARY" wait 2ms
    p2 <- o2 dscp 34 sctp chunk sack vtag 710001 srcport 3868 dstport 3868
}

compile { sctp_diameter_failover(pgw_pri, ocs_pri, pgw_sec, ocs_sec) }
```

### Modifier & Wire Cheat-Sheet: `sctp`

| Modifier | Applies To | Default | What It Controls |
| :--- | :--- | :--- | :--- |
| `chunk <type>` | All `sctp` | `init` | `init`, `initack`, `cookieecho`, `cookieack`, `data`, `sack`, `heartbeat`, `heartbeatack`, `shutdown`, `shutdownack`, `abort` |
| `vtag <u32>` | All `sctp` | `0` | 32-bit Verification Tag (`0` on `init`, the peer's tag afterwards) |
| `stream <u16>` | `chunk data` | `0` | Stream ID (`0..65535`); independent streams avoid head-of-line blocking |
| `ssn <u16>` | `chunk data` | `0` | Per-stream sequence number |
| `ppid <u32>` | `chunk data` | `0` | Payload Protocol ID, which tells Wireshark and middleboxes which dissector to run |
| `srcport` / `dstport` | All `sctp` | Ephemeral / `80` | 16-bit SCTP ports |

| Interface / Protocol | Typical Port | `ppid` | Snippet |
| :--- | :---: | :---: | :--- |
| **5G NGAP** (N2, gNB ↔ AMF) | `38412` | `60` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 60 srcport 38412 dstport 38412` |
| **5G XnAP** (Xn-C, gNB ↔ gNB) | `38422` | `61` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 61 srcport 38422 dstport 38422` |
| **5G O-RAN F1AP** (O-DU ↔ CU-CP) | `38472` | `62` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 62 srcport 38472 dstport 38472` |
| **5G O-RAN E1AP** (CU-CP ↔ CU-UP) | `38462` | `64` | `sctp chunk data vtag 100 stream 1 ssn 0 ppid 64 srcport 38462 dstport 38462` |
| **4G LTE S1AP / X2AP** | `36412` / `36422` | `18` / `27` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 18 srcport 36412 dstport 36412` |
| **Diameter** (S6a / Gy / Rx) | `3868` | `46` | `sctp chunk data vtag 100 stream 1 ssn 0 ppid 46 srcport 3868 dstport 3868` |
| **SIGTRAN M2UA / M3UA / M2PA** | `2904` / `2905` / `3565` | `2` / `3` / `5` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 3 srcport 2905 dstport 2905` |
| **SIGTRAN SUA / H.248 Megaco** | `14001` / `2944` | `4` / `7` | `sctp chunk data vtag 100 stream 1 ssn 0 ppid 4 srcport 14001 dstport 14001` |
| **3G/4G small-cell Iuh** (RUA / HNBAP) | `29169` | `19` / `20` | `sctp chunk data vtag 100 stream 0 ssn 0 ppid 20 srcport 29169 dstport 29169` |
| **WebRTC DataChannel** (DCEP / UTF-8) | `5000` | `50` / `51` | `sctp chunk data vtag 100 stream 1 ssn 1 ppid 51 srcport 5000 dstport 5000` |

---

## Inspect, Reverse and Replay

```console
# TCP sequence and ack progression, window sizes, ZeroWindow / Fast Retransmission flags
$ tshark -r tcp_zerowindow.pcap -T fields -e frame.number -e tcp.seq -e tcp.ack -e tcp.window_size_value -e _ws.col.Info

# SCTP chunk types, verification tags, stream IDs, PPIDs, and CRC-32c validation
$ tshark -r sctp_5g.pcap -Y "sctp" -T fields -e frame.number -e sctp.verif_tag -e sctp.chunk_type -e sctp.data_sid -e sctp.payload_proto_id

# Turn an existing TCP, UDP, or SCTP capture into .frasm code (defaults to <input_stem>.frasm)
$ frameassembly reverse tcp_zerowindow.pcap edited_tcp.frasm

# Check Suricata detection on custom scans, then replay onto a lab interface
$ suricata -r syn_proxy_split_handshake.pcap -k none
$ sudo tcpreplay -i eth0 tcp_session.pcap
```
