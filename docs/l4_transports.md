# Layer 4 Transport Protocols Reference (`TCP`, `UDP`, `SCTP`)

This guide is a practical reference for Linux network administrators, firewall engineers, security operations (SOC) analysts, and mobile core / telecom engineers looking for a **TCP 3-way handshake, RFC 7323 options, UDP multicast, and 5G NGAP / 4G S1AP / SIGTRAN M3UA SCTP pcap generator**.

Whether you are validating stateful firewall connection tables, testing IDS/IPS signature engines against out-of-order TCP segments and zero-window stalls, verifying UDP multicast feeds, or troubleshooting 4G/5G (`S1AP`/`NGAP`) and SS7 SIGTRAN (`M3UA`) SCTP multi-stream associations, every Layer 4 protocol in FrameAssembly works out of the box with **zero mandatory keywords** while allowing you to override any header field, flag, or option on the wire.

---

## Quick Navigation & Protocol Summary

| `.fasm` Keyword | Protocol Name | IP Proto | Default Ports (`->`) | Wire Checksum | Primary Networking Use Cases |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [**`tcp`**](#1-tcp--transmission-control-protocol-rfc-9293--rfc-7323) | Transmission Control Protocol (RFC 9293 / RFC 7323) | `6` | `12345 -> 80` (swapped on `<-`) | 16-bit one's complement over IPv4/IPv6 pseudo-header + TCP header + payload | 3-way handshakes, stateful firewall ACLs, MSS/WSCALE/SACK/Timestamp negotiation, retransmissions, zero-window probes, `RST` teardown |
| [**`udp`**](#2-udp--user-datagram-protocol-rfc-768--rfc-8200) | User Datagram Protocol (RFC 768 / RFC 8200) | `17` | `12345 -> 80` (swapped on `<-`) | 16-bit one's complement over IPv4/IPv6 pseudo-header (`0x0000` mapped to `0xFFFF`) | Connectionless request/reply datagrams, multicast media/telemetry streams, UDP flood/ACL testing, forcing dual-stack L7 protocols over UDP |
| [**`sctp`**](#3-sctp--stream-control-transmission-protocol-rfc-9260) | Stream Control Transmission Protocol (RFC 9260) | `132` | `12345 -> 80` (swapped on `<-`) | 32-bit little-endian Castagnoli **CRC32c** (`0x1EDC6F41`) at bytes `8..12` | 4-way cookie handshakes (`INIT`/`INIT_ACK`/`COOKIE_ECHO`/`COOKIE_ACK`), 5G `NGAP` (`PPID 60`), 4G `S1AP` (`PPID 18`), `M3UA` (`PPID 3`), Diameter (`PPID 46`) |

---

## 1. `TCP` — Transmission Control Protocol (RFC 9293 & RFC 7323)

### Plain-English Networking Overview

When capturing or crafting TCP traffic manually with traditional packet tools, the hardest part is computing **Sequence Numbers (`SEQ`)**, **Acknowledgment Numbers (`ACKNUM`)**, and **reversed source/destination ports** across multi-packet conversations—especially when mixing raw TCP handshake frames (`SYN`, `SYN ACK`, `ACK`) with Layer 7 application payloads (`HTTP`, `TLS`, `SSH`, `BGP`, `SMB`, `MODBUS`, etc.). A single off-by-one sequence byte causes Wireshark to flag `[TCP Previous segment not captured]` or `[TCP Spurious Retransmission]`, and causes stateful firewalls (`nftables`/`conntrack`, Palo Alto, FortiGate, CheckPoint) to drop the packet as out-of-window.

FrameAssembly solves this automatically with a **Shared 4-Tuple TCP State Machine** and **Automatic Reply-Port Swapping**:

1. **1 Statement = 1 Frame**: Every line inside a `FLOW` block emits exactly one Ethernet frame. A raw `tcp` statement emits a TCP segment; a TCP-based Layer 7 statement (such as `http get "/index.html"` or `tls client_hello`) emits a TCP `PSH ACK` segment carrying that Layer 7 wire payload on the protocol's well-known port.
2. **Automatic 4-Tuple `SEQ` & `ACKNUM` Tracking**:
   - FrameAssembly tracks every active TCP connection by its canonical bidirectional 4-tuple `(Endpoint A IP + Port, Endpoint B IP + Port)`.
   - Both endpoints start at initial sequence number **`1000`** (`seq = 1000`).
   - Whenever a packet carries the **`SYN`** flag or the **`FIN`** flag, the sender's sequence counter automatically advances by **`+1`** (consuming 1 sequence number on the wire, exactly per RFC 9293).
   - Whenever a packet carries a wire payload—whether via `payload "..."`, `hexpayload "..."`, or any TCP-based Layer 7 protocol (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `RTSP`, `SMTP`, `IMAP`, `POP3`, `LDAP`, `SMB`, `REDIS`, `MYSQL`, `POSTGRES`, `MQTT`, `AMQP`, `BGP`, `OPENFLOW`, `TACACS`, `MODBUS`, `S7COMM`, `OPCUA`, etc.)—the sender's sequence counter automatically advances by **the exact byte length of the Layer 7 payload**.
   - Every outgoing segment automatically sets its **Acknowledgment Number (`ACKNUM`)** to the peer's current expected sequence number (or `0` on an initial `SYN` where `ACK` is not set).
3. **Automatic Reply-Port Swapping (`->` vs. `<-`)**:
   - When you send a forward packet (`client -> server tcp srcport 51420 dstport 443 syn`) or an L7 request (`client -> server https` / `http` / `ssh`), FrameAssembly remembers the `(51420, 443)` port pair for that host pair.
   - On the reverse arrow (`client <- server tcp syn ack`), FrameAssembly **automatically flips the ports** so the server replies from `srcport 443` to `dstport 51420` without you having to retype `srcport` or `dstport`.

### How to Override `SEQ`, `ACKNUM`, or `WIN` for Firewall & IDS Testing

While automatic state tracking builds clean, RFC-compliant streams by default, security and firewall engineers frequently need to inject **deliberate anomalies** to verify that middleboxes detect or block bad traffic:

- **Simulating Packet Retransmissions**: Specify `seq <n>` with an earlier sequence number (for example, `seq 1001` after already sending 100 bytes of payload) so Wireshark and IDS sensors see an exact `[TCP Retransmission]`.
- **Out-of-Order / Out-of-Window Probes**: Set `seq 50000` or `acknum 999999` to test whether a stateful firewall drops segments outside the negotiated TCP receive window (`nf_conntrack_tcp_be_liberal = 0`).
- **Zero-Window Stalls (`win 0`) & Window Updates**: Set `win 0` (or `window 0`) on an `ack` segment from an overloaded server to simulate a receiver buffer exhaustion (`[TCP ZeroWindow]`), followed later by `win 64240` (`[TCP Window Update]`).
- **Stateless `SYN` Floods / Split Handshakes**: Emit `syn` segments with custom `seq` values or send `psh ack` data segments without a preceding 3-way handshake to verify that stateful firewall rules reject mid-stream pickup (`ct state INVALID`).

> **Canonical Syntax Reminder**: Always write **`srcport`** and **`dstport`** (never `sport` or `dport`), **`acknum <0..4294967295>`** for the acknowledgment number (never `ack <number>`, because bare `ack` is the TCP ACK control flag), and write TCP flags as **bare space-separated keywords** like `syn ack` or `psh ack` (never `flags [syn, ack]`).

### Default TCP Wire Behavior (When Modifiers Are Omitted)

- **Source & Destination Ports**: Defaults to `srcport 12345` and `dstport 80` on forward (`->`) statements unless inherited from an earlier statement between the same two hosts. Automatically reverses to `srcport 80` and `dstport 12345` on reply (`<-`) statements.
- **Control Flags (`0x00`–`0xFF`)**:
  - If a raw `tcp` statement has **no flags and no payload**, it defaults to **`SYN`** (`0x02`).
  - If a raw `tcp` statement includes **`payload`** or **`hexpayload`** (and no explicit flags), it defaults to **`PSH ACK`** (`0x18`).
  - All TCP-based Layer 7 protocol statements emit **`PSH ACK`** (`0x18`) by default unless you explicitly specify TCP flags on the same line.
- **Window Size**: Defaults to **`64240`** bytes (`0xFAF0`), matching modern Linux/Windows initial receive windows.
- **Data Offset & Options**: Defaults to a standard 20-byte TCP header (`Data Offset = 5` 32-bit words). When any RFC 7323 / RFC 793 TCP option (`mss`, `wscale`, `sack_perm`, `tsval`, `tsecr`) is specified, FrameAssembly automatically encodes the TLV options, pads the option block to a 4-byte boundary with `NOP` (`0x01`) / `EOL` (`0x00`) bytes, and updates the TCP `Data Offset` field accordingly.

### Complete `TCP` Modifier Reference

| Keyword / Flag | Value Type / Syntax | Default Wire Value | Wire Field & Networking Description |
| :--- | :--- | :--- | :--- |
| **`srcport`** | `<0..65535>` | `12345` (or inherited) | 16-bit TCP Source Port (bytes `0..2`). Automatically swapped on `<-` replies. |
| **`dstport`** | `<0..65535>` | `80` (or L7 default) | 16-bit TCP Destination Port (bytes `2..4`). Automatically swapped on `<-` replies. |
| **`syn`** | Bare flag keyword | Set if no flags/payload | **Synchronize** (`0x02`) sequence numbers to initiate a connection. Advances sender `SEQ` by `+1`. |
| **`ack`** | Bare flag keyword | Set on `PSH ACK` | **Acknowledgment** (`0x10`) indicating the `ACKNUM` field is significant. |
| **`psh`** | Bare flag keyword | Set when payload present | **Push** (`0x08`) instructing the receiver to deliver buffered data to the application immediately. |
| **`fin`** | Bare flag keyword | Unset (`0`) | **Finish** (`0x01`) orderly connection close from sender. Advances sender `SEQ` by `+1`. |
| **`rst`** | Bare flag keyword | Unset (`0`) | **Reset** (`0x04`) immediate abort of the connection (e.g., closed port or firewall reject). |
| **`urg`** | Bare flag keyword | Unset (`0`) | **Urgent** (`0x20`) marks the Urgent Pointer (`urgent`) field as valid. |
| **`ece`** | Bare flag keyword | Unset (`0`) | **ECN-Echo** (`0x40`, RFC 3168) signals congestion experienced or ECN capability during `SYN`. |
| **`cwr`** | Bare flag keyword | Unset (`0`) | **Congestion Window Reduced** (`0x80`, RFC 3168) acknowledges receipt of an `ECE` notification. |
| **`seq`** | `<0..4294967295>` | Auto-tracked (`1000+`) | 32-bit TCP Sequence Number override (bytes `4..8`). |
| **`acknum`** | `<0..4294967295>` | Auto-tracked peer `SEQ` | 32-bit TCP Acknowledgment Number override (bytes `8..12`). |
| **`win`** / **`window`** | `<0..65535>` | `64240` | 16-bit TCP Receive Window size in bytes (bytes `14..16`). Use `win 0` to simulate a zero-window stall. |
| **`urgent`** | `<0..65535>` | `0` | 16-bit Urgent Pointer offset (bytes `18..20`), used together with the `urg` flag. |
| **`mss`** | `<0..65535>` | Omitted | **TCP Option Kind 2 (Maximum Segment Size)**: 4-byte option advertising max payload size (e.g., `mss 1460` for Ethernet, `mss 1400` for VPN tunnels). |
| **`wscale`** | `<0..14>` | Omitted | **TCP Option Kind 3 (Window Scale, RFC 7323)**: 3-byte option shifting window size left by `N` bits (`wscale 7` multiplies window by `128`). Clamped to RFC 7323 max `14`. |
| **`sack_perm`** / **`sackperm`** | Bare keyword | Omitted | **TCP Option Kind 4 (SACK Permitted, RFC 2018)**: 2-byte option negotiating Selective Acknowledgment support during the `SYN` handshake. |
| **`tsval`** | `<0..4294967295>` | Omitted (`0` if `tsecr` set) | **TCP Option Kind 8 (Timestamps, RFC 7323)**: 10-byte option setting the sender's 32-bit Timestamp Value (`TSval`). |
| **`tsecr`** | `<0..4294967295>` | Omitted (`0` if `tsval` set) | **TCP Option Kind 8 (Timestamps, RFC 7323)**: Sets the 32-bit Timestamp Echo Reply (`TSecr`) echoing the peer's latest `TSval`. |
| **`transport tcp`** | Bare keyword pair | Default on TCP L7 | Forces dual-transport Layer 7 protocols (`DNS`, `SIP`, `SYSLOG`, `KERBEROS`, `MODBUS`, `NFS`, `MEMCACHED`, `DNP3`, `ETHERNETIP`) to run over **TCP** instead of UDP. |
| **`payload`** | `"<ascii_string>"` | Empty | Appends raw UTF-8/ASCII payload bytes and advances the 4-tuple `SEQ` counter by the payload byte length. |
| **`hexpayload`** | `"<hex_bytes>"` | Empty | Appends raw hexadecimal payload bytes and advances the 4-tuple `SEQ` counter by the decoded byte count. |

### Dual-Transport Layer 7 Protocols (`transport tcp` vs. `transport udp`)

Nine Layer 7 protocols in FrameAssembly support both TCP and UDP transport in real-world networks. You can switch their underlying Layer 4 header at any time by appending `transport tcp` or `transport udp`:

| L7 Protocol | Default Transport | Default Port | How to Switch Transport | Common Operational Scenario |
| :--- | :--- | :--- | :--- | :--- |
| **`DNS`** | `UDP` | `53` | Append `transport tcp` | DNS zone transfers (`AXFR`) or large DNSSEC / EDNS0 responses exceeding 512 bytes |
| **`SIP`** | `UDP` | `5060` | Append `transport tcp` | Enterprise VoIP SIP trunks over stateful TCP (`5060`) to avoid UDP fragmentation |
| **`SYSLOG`** | `UDP` | `514` | Append `transport tcp` | Reliable RFC 6587 TCP Syslog forwarding to a central SIEM collector |
| **`KERBEROS`** | `UDP` | `88` | Append `transport tcp` | Active Directory Kerberos tickets carrying large PAC group memberships over TCP `88` |
| **`MODBUS`** | `TCP` | `502` | Append `transport udp` | Modbus UDP/IP encapsulation on low-overhead industrial PLC telemetry links |
| **`NFS`** | `TCP` | `2049` | Append `transport udp` | Legacy NFSv3 stateless UDP mount traffic vs. modern NFSv4 TCP `2049` |
| **`MEMCACHED`** | `TCP` | `11211` | Append `transport udp` | Memcached UDP binary/ASCII cache lookups vs. persistent TCP connections |
| **`DNP3`** | `TCP` | `20000` | Append `transport udp` | Substation SCADA DNP3 over UDP datagrams vs. TCP connections |
| **`ETHERNETIP`** | `TCP` | `44818` | Append `transport udp` | CIP explicit messaging over TCP `44818` vs. implicit real-time I/O over UDP |

### Compilable Example 1A: Full TCP Handshake with RFC 7323 Options, Shared `HTTP` State & Graceful Teardown

This scenario demonstrates a complete web transaction between a Linux client and an Nginx server. Notice how the `SYN` handshake negotiates `MSS 1460`, `WSCALE 7`, `SACK_PERM`, and TCP Timestamps (`TSVAL`/`TSECR`), and how the subsequent `HTTP` request and response automatically inherit port `80` and advance the TCP sequence and acknowledgment numbers without a single manual `seq` or `acknum` calculation:

```frameassembly
// Complete TCP lifecycle: RFC 7323 handshake, HTTP/1.1 exchange, and 4-way FIN close
host web_client {
    ip 10.20.1.50
    mac 00:16:3e:10:01:50
}

host nginx_srv {
    ip 10.20.1.10
    mac 00:16:3e:10:01:10
}

flow web_transaction(c, s) {
    // 1. 3-Way TCP Handshake (c starts at SEQ=1000, s starts at SEQ=1000)
    c -> s tcp srcport 52400 dstport 80 syn mss 1460 wscale 7 sack_perm tsval 105000 tsecr 0
    c <- s tcp syn ack mss 1460 wscale 7 sack_perm tsval 890100 tsecr 105000 wait 1ms
    c -> s tcp ack tsval 105001 tsecr 890100 wait 1ms

    // 2. Layer 7 HTTP Request & Response (shares the 4-tuple SEQ/ACK state on port 80!)
    c -> s http srcport 52400 dstport 80 get uri "/api/v1/health" host_hdr "api.internal.corp" wait 2ms
    c <- s http status 200 reason "OK" content_type "application/json" body "{\"status\":\"healthy\"}" wait 3ms
    c -> s tcp ack tsval 105006 tsecr 890105 wait 1ms

    // 3. Orderly 4-Way FIN Teardown
    c -> s tcp fin ack tsval 105010 tsecr 890105 wait 5ms
    c <- s tcp ack tsval 890110 tsecr 105010 wait 1ms
    c <- s tcp fin ack tsval 890111 tsecr 105010 wait 1ms
    c -> s tcp ack tsval 105012 tsecr 890111 wait 1ms
}

compile {
    web_transaction(web_client, nginx_srv)
}
```

### Compilable Example 1B: Firewall & IDS State-Table Stress Test (Retransmission, Zero-Window, ECN, Urgent & `RST`)

This scenario exercises explicit `seq`, `acknum`, `win 0`, ECN (`ece`/`cwr`), `urg`/`urgent`, and `rst` overrides to test deep packet inspection (Suricata/Snort/Zeek) and stateful firewall anomaly counters:

```frameassembly
// TCP anomaly & congestion stress test: ECN negotiation, retransmission, ZeroWindow, and RST abort
host client_node {
    ip 192.168.100.25
    mac 00:50:56:aa:10:25
}

host app_gateway {
    ip 192.168.100.1
    mac 00:50:56:aa:10:01
}

flow tcp_anomaly_suite(cli, gw) {
    // 1. ECN-capable SYN handshake (SYN + ECE + CWR per RFC 3168)
    cli -> gw tcp srcport 49152 dstport 8443 syn ece cwr mss 1400 wscale 8 sack_perm
    cli <- gw tcp syn ack ece mss 1400 wscale 8 sack_perm wait 1ms
    cli -> gw tcp ack wait 1ms

    // 2. Send initial 16-byte application payload at SEQ=1001..1017
    cli -> gw tcp psh ack payload "PING-STREAM-0001" wait 2ms

    // 3. Simulate a TCP Retransmission by explicitly re-sending SEQ=1001
    cli -> gw tcp psh ack seq 1001 acknum 1001 payload "PING-STREAM-0001" wait 15ms

    // 4. Gateway acknowledges SEQ 1017 but advertises a Zero Window (buffer full) with ECN-Echo
    cli <- gw tcp ack seq 1001 acknum 1017 win 0 ece wait 2ms

    // 5. Client acknowledges ECN congestion (CWR) and sends a 1-byte Urgent out-of-band probe
    cli -> gw tcp urg psh ack cwr urgent 1 payload "!" wait 10ms

    // 6. Gateway recovers receive buffer (Window Update to 64240) and then aborts with RST
    cli <- gw tcp ack win 64240 wait 5ms
    cli <- gw tcp rst ack wait 1ms
}

compile {
    tcp_anomaly_suite(client_node, app_gateway)
}
```

---

## 2. `UDP` — User Datagram Protocol (RFC 768 & RFC 8200)

### Plain-English Networking Overview

**UDP (`IP Protocol 17`)** provides connectionless, zero-handshake datagram delivery with an 8-byte header (`Source Port`, `Destination Port`, `Length`, and `Checksum`). Network engineers rely on raw and L7-backed UDP captures to validate:

- **Unicast Request/Reply Services**: Custom internal RPCs, game/voice media relays, health probes, and firewall port-allow rules where the responder flips the UDP ports on the return path (`<-`).
- **Multicast Telemetry & Market Data Feeds**: Sending UDP datagrams to IPv4 multicast (`224.0.0.0/4` or `239.x.x.x`) or IPv6 multicast (`ff02::/16`, `ff05::/16`), where FrameAssembly automatically derives the RFC 1112 (`01:00:5e:xx:xx:xx`) or RFC 2464 (`33:33:xx:xx:xx:xx`) destination MAC address.
- **RFC 8200 §8.1 IPv6 Zero-Checksum Protection**: In IPv4, a UDP checksum of `0x0000` means "checksum unused," which is illegal over IPv6 (where Linux and router ASICs drop `0x0000` UDPv6 packets immediately). FrameAssembly always computes the full IPv4 (12-byte) or IPv6 (40-byte) pseudo-header checksum and automatically converts a calculated `0x0000` result to **`0xFFFF`** so every IPv4 and IPv6 UDP frame passes hardware checksum offload verification.

### Default UDP Wire Behavior (When Modifiers Are Omitted)

- **Source & Destination Ports**: Defaults to `srcport 12345` and `dstport 80` on forward (`->`) statements unless inherited from an earlier statement between the same host pair. Automatically reverses ports (`80 -> 12345`) on reply (`<-`) statements.
- **Length Field**: Automatically set to `8` bytes plus the payload byte length.
- **Checksum Field**: Automatically computed over the IPv4/IPv6 pseudo-header, 8-byte UDP header, and payload bytes.

### Complete `UDP` Modifier Reference

| Keyword | Value Type / Syntax | Default Wire Value | Wire Field & Networking Description |
| :--- | :--- | :--- | :--- |
| **`srcport`** | `<0..65535>` | `12345` (or inherited) | 16-bit UDP Source Port (bytes `0..2`). Automatically swapped on `<-` replies. |
| **`dstport`** | `<0..65535>` | `80` (or L7 default) | 16-bit UDP Destination Port (bytes `2..4`). Automatically swapped on `<-` replies. |
| **`transport udp`** | Bare keyword pair | Default on UDP L7 | Forces dual-transport Layer 7 protocols (`MODBUS`, `NFS`, `MEMCACHED`, `DNP3`, `ETHERNETIP`, `DNS`, `SIP`, `SYSLOG`, `KERBEROS`) to run over **UDP**. |
| **`payload`** | `"<ascii_string>"` | Empty (`0` bytes) | Appends raw UTF-8/ASCII payload bytes and updates the 16-bit UDP `Length` and `Checksum`. |
| **`hexpayload`** | `"<hex_bytes>"` | Empty (`0` bytes) | Appends raw hexadecimal payload bytes and updates the 16-bit UDP `Length` and `Checksum`. |

> **Guardrail**: Never combine TCP-only modifiers (`syn`, `ack`, `fin`, `rst`, `psh`, `seq`, `acknum`, `win`, `mss`, `wscale`, `tsval`) with a `udp` statement; FrameAssembly rejects TCP flags on UDP datagrams with a clear validation error highlighting the invalid flag in your `.fasm` file.

### Compilable Example 2: Unicast Request/Reply, IPv6 Multicast Feed & Dual-Transport `MODBUS` over UDP

```frameassembly
// UDP unicast request/reply port reversal, multicast telemetry, and Modbus over UDP
host sensor_gw {
    ip 10.40.0.10
    mac 00:1b:21:40:00:10
}

host collector_srv {
    ip 10.40.0.20
    mac 00:1b:21:40:00:20
}

host mcast_feed {
    // IPv4 Organization-Local Multicast -> auto-derives MAC 01:00:5e:01:01:64
    ip 239.1.1.100
}

flow udp_operations(gw, srv, mcast) {
    // 1. Unicast UDP probe on port 9999 and automatic port-swapped reply (9999 -> 54321)
    gw -> srv udp srcport 54321 dstport 9999 payload "HEARTBEAT:NODE-01:OK"
    gw <- srv udp hexpayload "41434b3a4e4f44452d3031" wait 2ms

    // 2. Multicast UDP telemetry burst with DSCP EF (46) and TTL 16
    gw -> mcast udp srcport 50000 dstport 50001 dscp 46 ttl 16 payload "TICK:AAPL:228.45:VOL:1500" wait 5ms

    // 3. Force a traditionally TCP protocol (Modbus port 502) to run over UDP
    gw -> srv modbus transport udp srcport 55100 dstport 502 unitid 1 read_holding_registers addr 100 count 4 wait 3ms
    gw <- srv modbus transport udp unitid 1 read_holding_registers count 4 value 250 is_response wait 2ms
}

compile {
    udp_operations(sensor_gw, collector_srv, mcast_feed)
}
```

---

## 3. `SCTP` — Stream Control Transmission Protocol (RFC 9260)

### Plain-English Networking Overview

**SCTP (`IP Protocol 132`, RFC 9260 / RFC 4960)** is a message-oriented, reliable transport protocol heavily used in **4G LTE / 5G Core mobile networks** (`S1AP` between eNodeB and MME, `NGAP` between gNodeB and AMF, `X2AP`/`XnAP`), **Diameter AAA signaling**, **SS7 SIGTRAN (`M3UA`)** telecom PSTN gateways, and **WebRTC Data Channels**.

Unlike TCP (which treats data as an unstructured byte stream vulnerable to Head-of-Line blocking and uses a 3-way handshake), SCTP introduces four key architectural features that FrameAssembly models natively:

1. **12-Byte Common Header & Little-Endian Castagnoli `CRC32c` Checksum**:
   - Every SCTP packet begins with a 12-byte common header: `Source Port` (2B), `Destination Port` (2B), `Verification Tag / VTAG` (4B), and a 32-bit **Castagnoli CRC32c** checksum (`bytes 8..12`, polynomial `0x1EDC6F41`) written in **little-endian byte order** per RFC 9260 §3.3.10.
   - FrameAssembly computes the hardware-valid CRC32c over the entire SCTP packet automatically, so Wireshark and Linux kernel SCTP stacks validate every frame without checksum errors.
2. **4-Way Cookie Handshake (`INIT` -> `INIT_ACK` -> `COOKIE_ECHO` -> `COOKIE_ACK`)**:
   - Instead of allocating state on the first packet (which makes TCP vulnerable to `SYN` floods), an SCTP server responds to an **`INIT`** chunk with an **`INIT_ACK`** containing a signed `State Cookie` parameter (`Type 0x0007`). The client echoes that cookie back in **`COOKIE_ECHO`**, and the server finalizes the association with **`COOKIE_ACK`**.
3. **Multi-Streaming without Head-of-Line Blocking (`STREAM`, `SSN`, `TSN`)**:
   - Within a single SCTP association, applications multiplex independent logical channels using a 16-bit **Stream Identifier (`stream`)** and a 16-bit per-stream **Stream Sequence Number (`ssn`)**, while reliability across the whole association is tracked by a 32-bit **Transmission Sequence Number (`tsn` / `seq`)**.
4. **Payload Protocol Identifier (`PPID`) Dissector Routing**:
   - SCTP `DATA` chunks carry a 32-bit **`ppid`** field that tells Wireshark and telecom endpoints which upper-layer signaling protocol is inside the chunk—regardless of the UDP/TCP port numbers.

### Common Telecom & Signaling `PPID` Values (`ppid <0..4294967295>`)

| `PPID` Value | Upper-Layer Protocol | Default SCTP Port | Telecom / Signaling Architecture Role |
| :--- | :--- | :--- | :--- |
| **`0`** | Unspecified / Raw Data | `80` / Custom | Generic SCTP data payload (default when `ppid` is omitted) |
| **`3`** | **M3UA** (SS7 MTP3 User Adaptation) | `2905` | SIGTRAN signaling over IP between Signaling Gateways (SGW) and Media Gateway Controllers |
| **`18`** | **S1AP** (S1 Application Protocol) | `36412` | 4G LTE control plane between eNodeB base stations and the Mobility Management Entity (MME) |
| **`27`** | **X2AP** (X2 Application Protocol) | `36422` | 4G LTE direct handover and coordination interface between neighboring eNodeBs |
| **`46`** | **Diameter** (RFC 6733 over SCTP) | `3868` | 4G/5G AAA, HSS/UDM subscriber lookups (`S6a`/`Cx`/`Gx`/`Rx` interfaces) |
| **`50`** | **WebRTC DCEP** | Dynamic | WebRTC Data Channel Establishment Protocol control messages |
| **`51`** | **WebRTC UTF-8 String** | Dynamic | WebRTC Data Channel application text messages |
| **`60`** | **NGAP** (NG Application Protocol) | `38412` | **5G Core (`5GC`) N2 interface** between gNodeB radio nodes and the Access and Mobility Management Function (AMF) |

### SCTP Chunk Types Supported (`chunk <type>` or Bare Keyword)

You can select an SCTP chunk type either by writing **`chunk <TYPE>`** (e.g., `sctp chunk init_ack`) or by writing the chunk name directly as a **bare keyword** (e.g., `sctp init_ack`). All chunks are automatically padded to a 4-byte boundary per RFC 9260:

| Chunk Keyword | Wire Type | Default Packet Format Emitted by FrameAssembly |
| :--- | :--- | :--- |
| **`init`** *(Default)* | `1` (`0x01`) | 20-byte **INIT** chunk: Initiate Tag (`vtag`, or `0x12345678` if `vtag 0`), Advertised Receiver Window Credit (`a_rwnd = 65536`), `10` Outbound Streams, `10` Inbound Streams, and Initial TSN (`tsn`, or `1000`). |
| **`init_ack`** | `2` (`0x02`) | 28-byte **INIT_ACK** chunk: 20-byte Initiate header plus an 8-byte RFC 9260 `State Cookie` TLV parameter (`Type 0x0007`, `Len 8`, value `0xdeadbeef`). |
| **`cookie_echo`** | `10` (`0x0A`) | 8-byte **COOKIE_ECHO** chunk echoing the 4-byte `0xdeadbeef` State Cookie back to the server. |
| **`cookie_ack`** | `11` (`0x0B`) | 4-byte **COOKIE_ACK** chunk completing the 4-way SCTP handshake. |
| **`data`** | `0` (`0x00`) | **DATA** chunk (`Flags = 0x03` `B=1, E=1` unfragmented message): 16-byte header (`TSN`, `Stream ID`, `SSN`, `PPID`) + payload (`"SCTP DATA"` if omitted), padded to 4-byte alignment. |
| **`sack`** | `3` (`0x03`) | 16-byte **Selective Acknowledgment (SACK)** chunk acknowledging Cumulative TSN Ack (`tsn`, or `1000`), `a_rwnd = 65536`, `0` Gap Ack Blocks, and `0` Duplicate TSNs. |
| **`heartbeat`** | `4` (`0x04`) | 12-byte **HEARTBEAT** chunk containing a Heartbeat Info TLV parameter (`Type 0x0001`, `Len 8`, payload `"HB\x00\x00"`). |
| **`heartbeat_ack`** | `5` (`0x05`) | 12-byte **HEARTBEAT_ACK** chunk echoing the 8-byte Heartbeat Info TLV parameter. |
| **`shutdown`** | `7` (`0x07`) | 8-byte **SHUTDOWN** chunk carrying the final Cumulative TSN Ack (`tsn`, or `1000`) to initiate graceful association termination. |
| **`abort`** | `6` (`0x06`) | 4-byte **ABORT** chunk immediately tearing down the SCTP association (analogous to TCP `RST`). |

### Complete `SCTP` Modifier Reference

| Keyword | Value Type / Syntax | Default Wire Value | Wire Field & Networking Description |
| :--- | :--- | :--- | :--- |
| **`chunk`** | `<INIT\|INIT_ACK\|COOKIE_ECHO\|COOKIE_ACK\|DATA\|SACK\|HEARTBEAT\|HEARTBEAT_ACK\|SHUTDOWN\|ABORT>` | `INIT` | Sets the 8-bit SCTP Chunk Type. Every chunk type above can also be written as a bare keyword without `chunk`. |
| **`srcport`** | `<0..65535>` | `12345` (or inherited) | 16-bit SCTP Source Port (bytes `0..2`). Automatically reversed on `<-` replies. |
| **`dstport`** | `<0..65535>` | `80` (or inherited) | 16-bit SCTP Destination Port (bytes `2..4`). Use `38412` for 5G `NGAP`, `36412` for 4G `S1AP`, `2905` for `M3UA`, `3868` for `Diameter`. |
| **`vtag`** | `<0..4294967295>` | `0` (`0x12345678` in `INIT` body) | 32-bit **Verification Tag** in the Common Header (bytes `4..8`, must be `0` on `INIT`) and the Initiate Tag inside `INIT`/`INIT_ACK`. |
| **`tsn`** / **`seq`** | `<0..4294967295>` | `1000` (`0` on `DATA` if unset) | 32-bit **Transmission Sequence Number**: sets Initial TSN on `INIT`/`INIT_ACK`, chunk TSN on `DATA`, or Cumulative TSN Ack on `SACK`/`SHUTDOWN`. |
| **`stream`** | `<0..65535>` | `0` | 16-bit **Stream Identifier (`SI`)** on `DATA` chunks (`0` for non-UE signaling, `1+` for per-UE or multi-stream bearer signaling). |
| **`ssn`** | `<0..65535>` | `0` | 16-bit **Stream Sequence Number (`SSN`)** ordering messages within a specific SCTP `stream`. |
| **`ppid`** | `<0..4294967295>` | `0` | 32-bit **Payload Protocol Identifier** on `DATA` chunks (`60` = 5G NGAP, `18` = 4G S1AP, `3` = M3UA, `46` = Diameter). |
| **`payload`** | `"<ascii_string>"` | `"SCTP DATA"` on `DATA` | Custom ASCII payload inside an SCTP `DATA` chunk (automatically 4-byte zero-padded on the wire). |
| **`hexpayload`** | `"<hex_bytes>"` | `"SCTP DATA"` on `DATA` | Custom binary/ASN.1 PER hexadecimal payload inside an SCTP `DATA` chunk. |

### Compilable Example 3A: 5G Core (`5GC`) N2 `NGAP` 4-Way Handshake, Multi-Stream Data & Heartbeat

This scenario models a 5G gNodeB base station establishing an SCTP association to a 5G Core AMF on UDP/SCTP port **`38412`** with DiffServ **`DSCP 48` (`CS6` Network Control)**, exchanging multi-stream `NGAP` (`PPID 60`) `DATA` chunks and `SACK` acknowledgments, probing path liveness with `HEARTBEAT` / `HEARTBEAT_ACK`, and performing a clean `SHUTDOWN`:

```frameassembly
// 5G Core N2 interface (SCTP port 38412, PPID 60 NGAP): 4-way handshake, multi-streaming & heartbeat
host gnodeb_du01 {
    ip 10.50.12.10
    mac 00:25:90:50:12:10
}

host amf_core01 {
    ip 10.50.12.1
    mac 00:25:90:50:12:01
}

flow n2_ngap_association(gnb, amf) {
    // 1. 4-Way SCTP Cookie Handshake (INIT carries VTAG=0 in Common Header, Initial TSN=1000)
    gnb -> amf sctp srcport 38412 dstport 38412 dscp 48 init vtag 0 tsn 1000
    gnb <- amf sctp dscp 48 init_ack vtag 305419896 tsn 2000 wait 1ms
    gnb -> amf sctp dscp 48 cookie_echo vtag 305419896 wait 1ms
    gnb <- amf sctp dscp 48 cookie_ack vtag 305419896 wait 1ms

    // 2. Stream 0 (Non-UE NGSetupRequest & NGSetupResponse, PPID 60 = NGAP)
    gnb -> amf sctp dscp 48 data vtag 305419896 tsn 1000 stream 0 ssn 0 ppid 60 hexpayload "00150011000002001b00080054f01000000100" wait 2ms
    gnb <- amf sctp dscp 48 sack vtag 305419896 tsn 1000 wait 1ms
    gnb <- amf sctp dscp 48 data vtag 305419896 tsn 2000 stream 0 ssn 0 ppid 60 hexpayload "2015000e0000020001000340010100564001ff" wait 2ms
    gnb -> amf sctp dscp 48 sack vtag 305419896 tsn 2000 wait 1ms

    // 3. Stream 1 (UE-Associated InitialUEMessage on independent Stream ID 1)
    gnb -> amf sctp dscp 48 data vtag 305419896 tsn 1001 stream 1 ssn 0 ppid 60 hexpayload "000f40180000020055000200010026000a097e00" wait 3ms
    gnb <- amf sctp dscp 48 sack vtag 305419896 tsn 1001 wait 1ms

    // 4. Path Liveness Probe (HEARTBEAT & HEARTBEAT_ACK) and Graceful SHUTDOWN
    gnb -> amf sctp dscp 48 heartbeat vtag 305419896 wait 10ms
    gnb <- amf sctp dscp 48 heartbeat_ack vtag 305419896 wait 1ms
    gnb -> amf sctp dscp 48 shutdown vtag 305419896 tsn 2000 wait 5ms
}

compile {
    n2_ngap_association(gnodeb_du01, amf_core01)
}
```

### Compilable Example 3B: Dual-Stack IPv6 SS7 SIGTRAN (`M3UA` Port 2905) & `ABORT` Failover

This scenario demonstrates SCTP over **IPv6** for telecom SS7 `M3UA` (`PPID 3`, port `2905`) signaling, using explicit `chunk <type>` syntax and terminating with an immediate **`abort`** chunk:

```frameassembly
// IPv6 SS7 SIGTRAN M3UA (SCTP port 2905, PPID 3) signaling and emergency ABORT teardown
host sgw_ipv6 {
    ip 2001:db8:500::10
    mac 00:1e:67:50:00:10
}

host mgc_ipv6 {
    ip 2001:db8:500::20
    mac 00:1e:67:50:00:20
}

flow sigtran_m3ua_failover(sgw, mgc) {
    // Establish SCTP association on M3UA port 2905 over IPv6
    sgw -> mgc sctp srcport 2905 dstport 2905 chunk init vtag 0 tsn 500
    sgw <- mgc sctp chunk init_ack vtag 900100 tsn 800 wait 1ms
    sgw -> mgc sctp chunk cookie_echo vtag 900100 wait 1ms
    sgw <- mgc sctp chunk cookie_ack vtag 900100 wait 1ms

    // Send M3UA ASP Up (Class 3, Type 1) over Stream 0 with PPID 3 (M3UA)
    sgw -> mgc sctp chunk data vtag 900100 tsn 500 stream 0 ssn 0 ppid 3 hexpayload "0100030100000008" wait 2ms
    sgw <- mgc sctp chunk sack vtag 900100 tsn 500 wait 1ms

    // Simulate signaling link fault triggering an immediate SCTP ABORT chunk
    sgw <- mgc sctp chunk abort vtag 900100 wait 5ms
}

compile {
    sigtran_m3ua_failover(sgw_ipv6, mgc_ipv6)
}
```

---

## 4. Inspecting & Replaying Layer 4 Captures (`tshark` & `tcpreplay`)

Once you build a `.fasm` packet capture (`frameassembly transport_test.fasm -o transport_test.pcap`), use these commands to verify TCP sequence tracking, UDP checksums, and SCTP CRC32c / PPID dissection:

```console
# 1. Inspect TCP sequence/ack numbers, relative/raw numbering, window sizes, and RFC 7323 options
tshark -r transport_test.pcap -o tcp.relative_sequence_numbers:FALSE \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e tcp.dstport \
  -e tcp.flags.str -e tcp.seq -e tcp.ack -e tcp.window_size_value -e tcp.options.mss_val

# 2. Verify zero bad TCP, UDP, or SCTP CRC32c checksums across the entire capture
tshark -r transport_test.pcap -Y "tcp.checksum.status == \"Bad\" || udp.checksum.status == \"Bad\" || sctp.checksum_bad == 1"

# 3. Inspect SCTP chunk types, Verification Tags (VTAG), Stream IDs, TSNs, and 5G NGAP / M3UA PPIDs
tshark -r transport_test.pcap -Y "sctp" \
  -T fields -e frame.number -e sctp.srcport -e sctp.dstport \
  -e sctp.verification_tag -e sctp.chunk_type -e sctp.data_tsn -e sctp.data_sid -e sctp.payload_proto_id

# 4. Replay the Layer 4 capture onto a lab test interface at exact nanosecond/millisecond WAIT timing
sudo tcpreplay --intf1=eth1 transport_test.pcap
```

---

## Related Documentation

- [**Getting Started Guide (`getting_started.md`)**](getting_started.md) — `.fasm` file anatomy, automatic defaults vs. explicit overrides, and step-by-step Wireshark workflows.
- [**Practical Use-Case Cookbook (`use_cases.md`)**](use_cases.md) — End-to-end recipes for firewall ACL testing, IDS/IPS validation, and network troubleshooting.
- [**Layer 2 Switching & Data-Link Protocols (`l2_protocols.md`)**](l2_protocols.md) — `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, and `MPLS`.
- [**Layer 3 Control, Tunneling, VPN & Routing Protocols (`l3_protocols.md`)**](l3_protocols.md) — Universal IPv4/IPv6 headers (`TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `DF`, `MF`), `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IKEV2`, `IPSEC`/`ESP`/`AH`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `PIM`, `VRRP`, `HSRP`, `BFD`, and `OPENFLOW`.
- [**Layer 7 Network Management (`l7_snmp.md`)**](l7_snmp.md) & [**Layer 7 Infrastructure & Telemetry (`l7_infra_and_telemetry.md`)**](l7_infra_and_telemetry.md) — `SNMP1`/`SNMP2`/`SNMP3`, `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW`.
- [**Layer 7 Web, Cloud & Transport Security (`l7_web_and_cloud.md`)**](l7_web_and_cloud.md), [**Layer 7 Mail, Auth, Storage & Databases (`l7_mail_auth_storage_db.md`)**](l7_mail_auth_storage_db.md) & [**Layer 7 Industrial Control Systems & SCADA/OT (`l7_industrial_ot.md`)**](l7_industrial_ot.md) — All 47 TCP and UDP Layer 7 application protocols.
- [**Multi-Host Topologies & Dual-Stack Scenarios (`topologies_and_dual_stack.md`)**](topologies_and_dual_stack.md) — Multi-device enterprise, data center, and service-mesh architectures.
- [**`.fasm` File Format & Media Type Specification (`fasm-specification.md`)**](fasm-specification.md) — Normative `text/vnd.frameassembly` media type specification, lexical rules, and `.fasm` extension disambiguation.
