# Layer 4 Transport Protocols & Stateful 4-Tuple Engine Reference

FrameAssembly provides native, zero-dependency packet crafting, checksum computation, and stateful 4-tuple connection tracking for all three core IETF Layer 4 (Transport) protocols: **TCP (RFC 9293 / RFC 7323 / RFC 3168)**, **UDP (RFC 768 / RFC 8200)**, and **SCTP (RFC 9260 / RFC 4960)**.

Every Layer 4 transport statement supports both dual-stack IPv4 (`0x0800`) and IPv6 (`0x86DD`) endpoints, automatic pseudo-header checksum calculation, bidirectional port reversal across `->` and `<-` operators, and full integration with Layer 2 (`VLAN`, `QINQ`, `MPLS`) and Layer 3 (`TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `IPID`, `DF`, `MF`, `FRAGOFFSET`) modifiers.

---

## 1. Layer 4 Transport Architecture & RFC Matrix

| Protocol | Keyword | Standard RFCs | IP Protocol Number | Checksum Algorithm | Corpus Directory | Primary Capabilities |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TCP** | `TCP` | RFC 9293, RFC 7323, RFC 3168, RFC 2018 | `6` (`0x06`) | 16-bit RFC 1071 One's Complement + IPv4/IPv6 Pseudo-Header | [`examples/l4/tcp/`](../examples/l4/tcp) | Stateful 3-way handshake, 8 control flags, `SEQ`/`ACKNUM` tracking, `WIN`, `MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`/`TSECR` |
| **UDP** | `UDP` | RFC 768, RFC 8200 | `17` (`0x11`) | 16-bit RFC 1071 One's Complement + IPv4/IPv6 Pseudo-Header | [`examples/l4/udp/`](../examples/l4/udp) | Connectionless low-latency datagrams, multicast/anycast streaming, RoCEv2 RDMA, IP SLA jitter probes |
| **SCTP** | `SCTP` | RFC 9260, RFC 4960 | `132` (`0x84`) | 32-bit CRC32c (Castagnoli) over Common Header + Chunks | [`examples/l4/sctp/`](../examples/l4/sctp) | 4-way `INIT`/`COOKIE_ECHO` handshake, `VTAG`, multi-streaming (`STREAM`, `SSN`, `TSN`, `PPID`), 5G NGAP / SIGTRAN M3UA / WebRTC |

---

## 2. Transmission Control Protocol (`TCP` — RFC 9293)

The Transmission Control Protocol provides reliable, ordered, byte-stream delivery with congestion control, flow control, and selective acknowledgment.

### 2.1 RFC 9293 TCP Header Layout (20–60 Bytes)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (0..40 Bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Canonical `TCP` Modifiers, Flags & Options

| Category | Modifier Syntax | Argument Type | Description & Wire Default |
| :--- | :--- | :--- | :--- |
| **Source Port** | `SRCPORT <u16>` | `u16` (`1..65535`) | Overrides TCP source port (tracked and swapped across `<-`) |
| **Destination Port**| `DSTPORT <u16>` | `u16` (`1..65535`) | Overrides TCP destination port (default `80`) |
| **Sequence Number** | `SEQ <u32>` | `u32` | Overrides 32-bit TCP Sequence Number (auto-tracked if omitted) |
| **Ack Number** | `ACKNUM <u32>` | `u32` | Overrides 32-bit Acknowledgment Number (auto-tracked if omitted) |
| **Receive Window** | `WIN <u16>` or `WINDOW <u16>` | `u16` (`0..65535`) | Sets 16-bit TCP receive window size (default `65535`) |
| **Urgent Pointer** | `URGENT <u16>` | `u16` (`0..65535`) | Sets 16-bit Urgent Pointer offset when `URG` flag is set |
| **Control Flags** | `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR` | Bare flags (0-arg) | Any combination of the 8 TCP control bits may be specified on a statement |
| **Option: MSS** | `MSS <u16>` | `u16` | RFC 9293 Kind `2` Maximum Segment Size option (e.g. `1460` Ethernet, `8960` Jumbo) |
| **Option: WSCALE** | `WSCALE <u8>` | `u8` (`0..14`) | RFC 7323 Kind `3` Window Scale shift count (e.g. `7` = $128\times$ multiplier) |
| **Option: SACK** | `SACK_PERM` or `SACKPERM` | Bare flag (0-arg) | RFC 2018 Kind `4` Selective Acknowledgment Permitted option |
| **Option: TSval** | `TSVAL <u32>` | `u32` | RFC 7323 Kind `8` TCP Timestamp Value |
| **Option: TSecr** | `TSECR <u32>` | `u32` | RFC 7323 Kind `8` TCP Timestamp Echo Reply |
| **Transport Override**| `TRANSPORT TCP` | Keyword | Forces upper-layer dual-transport protocols (such as `DNS` or `SIP`) over TCP |

> **Important Syntax Rule**: Never use `SPORT`, `DPORT`, or `ACK_NUM`. Always use `SRCPORT`, `DSTPORT`, `SEQ`, `ACKNUM`, and `WIN` (or `WINDOW`).

### 2.3 Stateful 4-Tuple Tracking & Sequence Progression
When `SEQ`, `ACKNUM`, or ports are omitted on subsequent frames in a flow, the FrameAssembly backend (`src/backend/mod.rs`) automatically maintains connection state per 4-tuple:
1. **Port Swapping**: If `c -> s TCP SYN SRCPORT 52000 DSTPORT 443` is followed by `c <- s TCP SYN ACK`, the return frame automatically sets `SRCPORT 443` and `DSTPORT 52000`.
2. **Ghost Byte Accounting**: `SYN` and `FIN` flags consume `1` sequence number in the virtual byte stream (`SEQ + 1`), while `PSH ACK` data segments advance `SEQ` by `payload.len()` octets.

### 2.4 Verified `TCP` Examples

#### Example A: RFC 7323 High-Performance TCP Handshake, Payload Transfer & Graceful FIN Teardown
```frameassembly
// PROMPT: Full TCP connection lifecycle with RFC 7323 high-speed options (MSS, WSCALE, SACK_PERM, TSVAL/TSECR), data transfer, and 4-way FIN close.
// TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, ACK, PSH, FIN, SRCPORT, DSTPORT, SEQ, ACKNUM, WIN, MSS, WSCALE, SACK_PERM, TSVAL, TSECR, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare the client application node.
host app_client {
    ip 10.10.20.50
    mac 00:50:56:a1:20:50
}

// INSTRUCTION: Declare the backend API server node.
host api_server {
    ip 10.10.20.10
    mac 00:50:56:a1:20:10
}

// INSTRUCTION: Define a complete TCP session negotiating MSS 1460, WSCALE 7, SACK_PERM, and TCP Timestamps.
flow tcp_rfc7323_full_lifecycle(c, s) {
    c -> s tcp syn srcport 54321 dstport 443 seq 1000 win 65535 mss 1460 wscale 7 sack_perm tsval 10000 tsecr 0 wait 1ms
    c <- s tcp syn ack srcport 443 dstport 54321 seq 5000 acknum 1001 win 65535 mss 1460 wscale 7 sack_perm tsval 20000 tsecr 10000 wait 1ms
    c -> s tcp ack srcport 54321 dstport 443 seq 1001 acknum 5001 win 512 tsval 10002 tsecr 20000 wait 1ms
    c -> s tcp psh ack srcport 54321 dstport 443 seq 1001 acknum 5001 win 512 tsval 10005 tsecr 20000 payload "GET /v1/health HTTP/1.1\r\nHost: api.internal\r\n\r\n" wait 2ms
    c <- s tcp psh ack srcport 443 dstport 54321 seq 5001 acknum 1048 win 512 tsval 20005 tsecr 10005 payload "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK" wait 2ms
    c -> s tcp fin ack srcport 54321 dstport 443 seq 1048 acknum 5041 win 512 tsval 10010 tsecr 20005 wait 1ms
    c <- s tcp fin ack srcport 443 dstport 54321 seq 5041 acknum 1049 win 512 tsval 20010 tsecr 10010 wait 1ms
    c -> s tcp ack srcport 54321 dstport 443 seq 1049 acknum 5042 win 512 tsval 10012 tsecr 20010 wait 1ms
}

// INSTRUCTION: Compile the RFC 7323 TCP session.
compile {
    tcp_rfc7323_full_lifecycle(app_client, api_server)
}
```

#### Example B: RFC 3168 Explicit Congestion Notification (`ECE`/`CWR`), Urgent Pointer (`URG`), Zero-Window & `RST` Abort
```frameassembly
// PROMPT: TCP Explicit Congestion Notification (ECN ECE/CWR), Out-of-Band Urgent Pointer, Zero-Window backpressure, and RST abort.
// TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, ACK, PSH, URG, ECE, CWR, RST, SRCPORT, DSTPORT, SEQ, ACKNUM, WINDOW, URGENT, ECN, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv6 sender and receiver endpoints.
host sender_v6 {
    ip 2001:db8:40::10
    mac 00:1c:73:40:00:10
}

// INSTRUCTION: Declare the IPv6 receiver endpoint.
host receiver_v6 {
    ip 2001:db8:40::20
    mac 00:1c:73:40:00:20
}

// INSTRUCTION: Define ECN capability negotiation, congestion feedback (ECE/CWR), Urgent pointer signaling, Zero-Window stall, and RST teardown.
flow tcp_ecn_urg_zwin_rst(a, b) {
    a -> b tcp syn ece cwr srcport 58000 dstport 9000 seq 100 window 65535 ecn 2 wait 1ms
    a <- b tcp syn ack ece srcport 9000 dstport 58000 seq 200 acknum 101 window 65535 ecn 2 wait 1ms
    a -> b tcp psh ack srcport 58000 dstport 9000 seq 101 acknum 201 window 65535 ecn 3 payload "CONGESTED_BURST_SEGMENT" wait 1ms
    a <- b tcp ack ece srcport 9000 dstport 58000 seq 201 acknum 124 window 16384 ecn 2 wait 1ms
    a -> b tcp psh ack cwr srcport 58000 dstport 9000 seq 124 acknum 201 window 32768 ecn 2 payload "CWND_HALVED_SEGMENT" wait 1ms
    a -> b tcp psh ack urg srcport 58000 dstport 9000 seq 143 acknum 201 window 32768 urgent 1 payload "!" wait 1ms
    a <- b tcp ack srcport 9000 dstport 58000 seq 201 acknum 144 window 0 wait 5ms
    a <- b tcp ack srcport 9000 dstport 58000 seq 201 acknum 144 window 65535 wait 1ms
    a -> b tcp rst ack srcport 58000 dstport 9000 seq 144 acknum 201 window 0 wait 1ms
}

// INSTRUCTION: Compile the ECN, Urgent, Zero-Window, and RST edge-case flow.
compile {
    tcp_ecn_urg_zwin_rst(sender_v6, receiver_v6)
}
```

---

## 3. User Datagram Protocol (`UDP` — RFC 768)

The User Datagram Protocol provides minimal-overhead connectionless datagram delivery with an 8-byte header (`Source Port`, `Destination Port`, `Length`, `Checksum`).

### 3.1 RFC 768 UDP Header Layout (8 Bytes)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Canonical `UDP` Modifiers

| Modifier | Syntax | Argument Type | Description |
| :--- | :--- | :--- | :--- |
| **Protocol** | `UDP` | Keyword | Selects RFC 768 User Datagram Protocol (IP Protocol `17`) |
| **Source Port** | `SRCPORT <u16>` | `u16` (`1..65535`) | Sets UDP source port (automatically swapped on `<-` responses) |
| **Destination Port**| `DSTPORT <u16>` | `u16` (`1..65535`) | Sets UDP destination port (default `53`) |
| **Transport Override**| `TRANSPORT UDP` | Keyword | Forces dual-transport L7 protocols (e.g. `DNS`, `SIP`, `NFS`, `SYSLOG`) over UDP |
| **Payload** | `PAYLOAD "<str>"` / `HEXPAYLOAD "<hex>"` | Quoted string | Appends application datagram payload and updates UDP Length & Checksum |

### 3.3 Verified `UDP` Example (Unicast RoCEv2 RDMA & Multicast Market Data)

```frameassembly
// PROMPT: High-frequency UDP transport covering RoCEv2 RDMA over Converged Ethernet (Port 4791) and multicast market data feeds.
// TOKENS: HOST, IP, MAC, FLOW, VLAN, PCP, DSCP, ECN, UDP, SRCPORT, DSTPORT, PAYLOAD, HEXPAYLOAD, WAIT, COMPILE, LOOP

// INSTRUCTION: Declare GPU compute node A and node B for lossless RoCEv2 over UDP port 4791.
host gpu_worker_a {
    ip 10.88.1.10
    mac 00:02:c9:88:01:10
}

// INSTRUCTION: Declare peer GPU compute node B.
host gpu_worker_b {
    ip 10.88.1.20
    mac 00:02:c9:88:01:20
}

// INSTRUCTION: Declare multicast market feed publisher and multicast group receiver.
host feed_publisher {
    ip 10.99.1.1
    mac 00:1c:73:99:01:01
}

// INSTRUCTION: Declare the RFC 1112 multicast group 239.192.10.1.
host market_mcast_group {
    ip 239.192.10.1
    mac 01:00:5e:40:0a:01
}

// INSTRUCTION: Define lossless Priority Flow Control (PCP 3, DSCP 26, ECN 2) RoCEv2 RDMA Write and CNP congestion feedback.
flow rocev2_rdma_exchange(a, b) {
    a -> b vlan 88 pcp 3 dscp 26 ecn 3 udp srcport 51001 dstport 4791 payload "IB_BTH_RDMA_WRITE_ONLY_QP_000100_PSN_101" wait 200us
    a <- b vlan 88 pcp 6 dscp 48 ecn 0 udp srcport 4791 dstport 4791 hexpayload "81000000000001000000000000000000" wait 100us
    a <- b vlan 88 pcp 3 dscp 26 ecn 2 udp srcport 51001 dstport 4791 payload "IB_BTH_RDMA_ACK_SYNDROME_00_PSN_101" wait 200us
}

// INSTRUCTION: Define a multicast UDP market data tick burst.
flow multicast_market_tick(pub_host, mcast_grp) {
    pub_host -> mcast_grp dscp 34 udp srcport 30001 dstport 15500 payload "ITCH_50_ADD_ORDER_NVDA_100_SHARES" wait 500us
}

// INSTRUCTION: Compile the RoCEv2 RDMA exchange and 4 multicast market ticks.
compile {
    rocev2_rdma_exchange(gpu_worker_a, gpu_worker_b)
    loop 4 {
        multicast_market_tick(feed_publisher, market_mcast_group)
    }
}
```

---

## 4. Stream Control Transmission Protocol (`SCTP` — RFC 9260 / RFC 4960)

The Stream Control Transmission Protocol (`SCTP`, IP Protocol `132`) is a message-oriented, multi-homed, multi-stream transport protocol used extensively in **5G Standalone Core (`NGAP` over N2, port `38412`)**, **4G LTE (`S1AP` port `36412`, `X2AP` port `36422`, `Diameter` port `3868`)**, **Telecom SS7 SIGTRAN (`M3UA` port `2905`, `SUA` port `14001`)**, and **WebRTC DataChannels (RFC 8831, port `5000`)**.

### 4.1 RFC 9260 SCTP Common Header & Chunk Structure
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Verification Tag (VTAG)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Checksum (CRC32c Castagnoli)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Chunk Type  |  Chunk Flags  |          Chunk Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Chunk Value / Payload ...                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 Canonical `SCTP` Modifiers & Chunk Types

| Modifier | Syntax | Argument Type | Description & Standard |
| :--- | :--- | :--- | :--- |
| **Protocol** | `SCTP` | Keyword | Selects RFC 9260 SCTP (IP Protocol `132`) with hardware-valid CRC32c |
| **Chunk Type** | `CHUNK <TYPE>` | Keyword / String | `INIT` (`1`), `INIT_ACK` (`2`), `COOKIE_ECHO` (`10`), `COOKIE_ACK` (`11`), `DATA` (`0`), `SACK` (`3`), `HEARTBEAT` (`4`), `HEARTBEAT_ACK` (`5`), `ABORT` (`6`), `SHUTDOWN` (`7`), `SHUTDOWN_ACK` (`8`), `SHUTDOWN_COMPLETE` (`14`) |
| **Verification Tag**| `VTAG <u32>` | `u32` | 32-bit SCTP Verification Tag (`0` on initial `INIT`, peer tag thereafter) |
| **Stream ID** | `STREAM <u16>` | `u16` (`0..65535`) | 16-bit SCTP Stream Identifier within the association (`DATA` chunks) |
| **Stream Seq Num** | `SSN <u16>` | `u16` (`0..65535`) | 16-bit Stream Sequence Number for ordered delivery within a stream |
| **Trans Seq Num** | `TSN <u32>` or `SEQ <u32>` | `u32` | 32-bit Transmission Sequence Number for association-wide reliability |
| **Payload Proto ID**| `PPID <u32>` | `u32` | IANA Payload Protocol ID (`60` = 5G NGAP, `18` = S1AP, `27` = X2AP, `3` = M3UA, `46` = Diameter, `50` = WebRTC DCEP, `51` = WebRTC String) |
| **Ports** | `SRCPORT <u16>` / `DSTPORT <u16>` | `u16` | Overrides SCTP source and destination port numbers (default `2905`) |

> **Important Syntax Rule**: Always use `CHUNK <CHUNK_TYPE>` (e.g. `SCTP CHUNK INIT`, `SCTP CHUNK INIT_ACK`, `SCTP CHUNK COOKIE_ECHO`, `SCTP CHUNK COOKIE_ACK`, `SCTP CHUNK DATA`, `SCTP CHUNK SACK`, `SCTP CHUNK HEARTBEAT`, `SCTP CHUNK HEARTBEAT_ACK`, `SCTP CHUNK SHUTDOWN`, `SCTP CHUNK ABORT`).

### 4.3 Verified `SCTP` Examples

#### Example A: 5G Standalone N2 Control Plane (`NGAP`, Port `38412`, `PPID 60`) 4-Way Handshake & Multi-Stream Session
```frameassembly
// PROMPT: 5G SA N2 interface SCTP 4-way cookie handshake, multi-stream NGAP signaling (PPID 60), heartbeat monitoring, and graceful shutdown.
// TOKENS: HOST, IP, MAC, FLOW, DSCP, SCTP, CHUNK, INIT, INIT_ACK, COOKIE_ECHO, COOKIE_ACK, DATA, SACK, HEARTBEAT, HEARTBEAT_ACK, SHUTDOWN, VTAG, SEQ, STREAM, SSN, PPID, SRCPORT, DSTPORT, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare 5G gNodeB radio base station.
host gnb_n2 {
    ip 10.50.2.10
    mac 00:1c:73:50:02:10
}

// INSTRUCTION: Declare 5G Core Access and Mobility Management Function (AMF).
host amf_n2 {
    ip 10.50.2.1
    mac 00:1c:73:50:02:01
}

// INSTRUCTION: Execute 4-way SCTP association setup, NGAP Stream 0 & Stream 1 DATA transfer, SACK, Heartbeat, and Shutdown.
flow sctp_5g_ngap_lifecycle(gnb, amf) {
    gnb -> amf dscp 46 sctp chunk init vtag 0 srcport 38412 dstport 38412 wait 1ms
    gnb <- amf dscp 46 sctp chunk init_ack vtag 3841201 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk cookie_echo vtag 3841201 srcport 38412 dstport 38412 payload "HMAC_STATE_COOKIE_5G_AMF" wait 1ms
    gnb <- amf dscp 46 sctp chunk cookie_ack vtag 3841201 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk data vtag 3841201 seq 100 stream 0 ssn 0 ppid 60 srcport 38412 dstport 38412 payload "NGAP_NG_SETUP_REQUEST_GNB_ID_001" wait 2ms
    gnb <- amf dscp 46 sctp chunk sack vtag 3841201 seq 100 srcport 38412 dstport 38412 wait 1ms
    gnb <- amf dscp 46 sctp chunk data vtag 3841201 seq 200 stream 0 ssn 0 ppid 60 srcport 38412 dstport 38412 payload "NGAP_NG_SETUP_RESPONSE_PLMN_00101" wait 2ms
    gnb -> amf dscp 46 sctp chunk data vtag 3841201 seq 101 stream 1 ssn 0 ppid 60 srcport 38412 dstport 38412 payload "NGAP_INITIAL_UE_MESSAGE_REGISTRATION_REQ" wait 2ms
    gnb <- amf dscp 46 sctp chunk sack vtag 3841201 seq 101 srcport 38412 dstport 38412 wait 1ms
    gnb -> amf dscp 46 sctp chunk heartbeat vtag 3841201 srcport 38412 dstport 38412 payload "HB_INFO_PATH_PRIMARY" wait 5ms
    gnb <- amf dscp 46 sctp chunk heartbeat_ack vtag 3841201 srcport 38412 dstport 38412 payload "HB_INFO_PATH_PRIMARY" wait 5ms
    gnb -> amf dscp 46 sctp chunk shutdown vtag 3841201 seq 200 srcport 38412 dstport 38412 wait 1ms
}

// INSTRUCTION: Compile the 5G N2 SCTP association lifecycle.
compile {
    sctp_5g_ngap_lifecycle(gnb_n2, amf_n2)
}
```

#### Example B: Dual-Stack IPv6 Telecom SIGTRAN M3UA (`PPID 3`, Port `2905`) & WebRTC DataChannel (`PPID 50/51`, Port `5000`)
```frameassembly
// PROMPT: IPv6 SCTP multi-stream transport for SS7 SIGTRAN M3UA (PPID 3) and WebRTC DataChannels (PPID 50 and PPID 51) with ABORT teardown.
// TOKENS: HOST, IP, MAC, FLOW, SCTP, CHUNK, DATA, SACK, ABORT, VTAG, SEQ, STREAM, SSN, PPID, SRCPORT, DSTPORT, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv6 Signaling Gateway A.
host sgw_v6_a {
    ip 2001:db8:2905::1
    mac 00:50:56:29:05:01
}

// INSTRUCTION: Declare IPv6 Softswitch MGC B.
host mgc_v6_b {
    ip 2001:db8:2905::2
    mac 00:50:56:29:05:02
}

// INSTRUCTION: Define SIGTRAN M3UA signaling on Stream 1 (PPID 3) and WebRTC DataChannel messages on Stream 2 (PPID 50/51).
flow ipv6_sctp_m3ua_and_webrtc(a, b) {
    a -> b sctp chunk data vtag 290501 seq 1 stream 1 ssn 0 ppid 3 srcport 2905 dstport 2905 payload "M3UA_PAYLOAD_DATA_ISUP_IAM" wait 2ms
    a <- b sctp chunk sack vtag 290501 seq 1 srcport 2905 dstport 2905 wait 1ms
    a -> b sctp chunk data vtag 500051 seq 10 stream 2 ssn 0 ppid 50 srcport 5000 dstport 5000 payload "DCEP_DATA_CHANNEL_OPEN_RELIABLE" wait 2ms
    a <- b sctp chunk data vtag 500051 seq 20 stream 2 ssn 0 ppid 51 srcport 5000 dstport 5000 payload "{\"channel\":\"telemetry\",\"status\":\"connected\"}" wait 2ms
    a -> b sctp chunk abort vtag 500051 srcport 5000 dstport 5000 payload "USER_INITIATED_ABORT_CAUSE_0x000C" wait 1ms
}

// INSTRUCTION: Compile the IPv6 SCTP M3UA and WebRTC DataChannel capture.
compile {
    ipv6_sctp_m3ua_and_webrtc(sgw_v6_a, mgc_v6_b)
}
```
