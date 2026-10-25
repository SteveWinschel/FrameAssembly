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
HOST app_client {
    IP 10.10.20.50
    MAC 00:50:56:a1:20:50
}

// INSTRUCTION: Declare the backend API server node.
HOST api_server {
    IP 10.10.20.10
    MAC 00:50:56:a1:20:10
}

// INSTRUCTION: Define a complete TCP session negotiating MSS 1460, WSCALE 7, SACK_PERM, and TCP Timestamps.
FLOW tcp_rfc7323_full_lifecycle(c, s) {
    c -> s TCP SYN SRCPORT 54321 DSTPORT 443 SEQ 1000 WIN 65535 MSS 1460 WSCALE 7 SACK_PERM TSVAL 10000 TSECR 0 WAIT 1ms
    c <- s TCP SYN ACK SRCPORT 443 DSTPORT 54321 SEQ 5000 ACKNUM 1001 WIN 65535 MSS 1460 WSCALE 7 SACK_PERM TSVAL 20000 TSECR 10000 WAIT 1ms
    c -> s TCP ACK SRCPORT 54321 DSTPORT 443 SEQ 1001 ACKNUM 5001 WIN 512 TSVAL 10002 TSECR 20000 WAIT 1ms
    c -> s TCP PSH ACK SRCPORT 54321 DSTPORT 443 SEQ 1001 ACKNUM 5001 WIN 512 TSVAL 10005 TSECR 20000 PAYLOAD "GET /v1/health HTTP/1.1\r\nHost: api.internal\r\n\r\n" WAIT 2ms
    c <- s TCP PSH ACK SRCPORT 443 DSTPORT 54321 SEQ 5001 ACKNUM 1048 WIN 512 TSVAL 20005 TSECR 10005 PAYLOAD "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK" WAIT 2ms
    c -> s TCP FIN ACK SRCPORT 54321 DSTPORT 443 SEQ 1048 ACKNUM 5041 WIN 512 TSVAL 10010 TSECR 20005 WAIT 1ms
    c <- s TCP FIN ACK SRCPORT 443 DSTPORT 54321 SEQ 5041 ACKNUM 1049 WIN 512 TSVAL 20010 TSECR 10010 WAIT 1ms
    c -> s TCP ACK SRCPORT 54321 DSTPORT 443 SEQ 1049 ACKNUM 5042 WIN 512 TSVAL 10012 TSECR 20010 WAIT 1ms
}

// INSTRUCTION: Compile the RFC 7323 TCP session.
COMPILE {
    tcp_rfc7323_full_lifecycle(app_client, api_server)
}
```

#### Example B: RFC 3168 Explicit Congestion Notification (`ECE`/`CWR`), Urgent Pointer (`URG`), Zero-Window & `RST` Abort
```frameassembly
// PROMPT: TCP Explicit Congestion Notification (ECN ECE/CWR), Out-of-Band Urgent Pointer, Zero-Window backpressure, and RST abort.
// TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, ACK, PSH, URG, ECE, CWR, RST, SRCPORT, DSTPORT, SEQ, ACKNUM, WINDOW, URGENT, ECN, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv6 sender and receiver endpoints.
HOST sender_v6 {
    IP 2001:db8:40::10
    MAC 00:1c:73:40:00:10
}

// INSTRUCTION: Declare the IPv6 receiver endpoint.
HOST receiver_v6 {
    IP 2001:db8:40::20
    MAC 00:1c:73:40:00:20
}

// INSTRUCTION: Define ECN capability negotiation, congestion feedback (ECE/CWR), Urgent pointer signaling, Zero-Window stall, and RST teardown.
FLOW tcp_ecn_urg_zwin_rst(a, b) {
    a -> b TCP SYN ECE CWR SRCPORT 58000 DSTPORT 9000 SEQ 100 WINDOW 65535 ECN 2 WAIT 1ms
    a <- b TCP SYN ACK ECE SRCPORT 9000 DSTPORT 58000 SEQ 200 ACKNUM 101 WINDOW 65535 ECN 2 WAIT 1ms
    a -> b TCP PSH ACK SRCPORT 58000 DSTPORT 9000 SEQ 101 ACKNUM 201 WINDOW 65535 ECN 3 PAYLOAD "CONGESTED_BURST_SEGMENT" WAIT 1ms
    a <- b TCP ACK ECE SRCPORT 9000 DSTPORT 58000 SEQ 201 ACKNUM 124 WINDOW 16384 ECN 2 WAIT 1ms
    a -> b TCP PSH ACK CWR SRCPORT 58000 DSTPORT 9000 SEQ 124 ACKNUM 201 WINDOW 32768 ECN 2 PAYLOAD "CWND_HALVED_SEGMENT" WAIT 1ms
    a -> b TCP PSH ACK URG SRCPORT 58000 DSTPORT 9000 SEQ 143 ACKNUM 201 WINDOW 32768 URGENT 1 PAYLOAD "!" WAIT 1ms
    a <- b TCP ACK SRCPORT 9000 DSTPORT 58000 SEQ 201 ACKNUM 144 WINDOW 0 WAIT 5ms
    a <- b TCP ACK SRCPORT 9000 DSTPORT 58000 SEQ 201 ACKNUM 144 WINDOW 65535 WAIT 1ms
    a -> b TCP RST ACK SRCPORT 58000 DSTPORT 9000 SEQ 144 ACKNUM 201 WINDOW 0 WAIT 1ms
}

// INSTRUCTION: Compile the ECN, Urgent, Zero-Window, and RST edge-case flow.
COMPILE {
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
HOST gpu_worker_a {
    IP 10.88.1.10
    MAC 00:02:c9:88:01:10
}

// INSTRUCTION: Declare peer GPU compute node B.
HOST gpu_worker_b {
    IP 10.88.1.20
    MAC 00:02:c9:88:01:20
}

// INSTRUCTION: Declare multicast market feed publisher and multicast group receiver.
HOST feed_publisher {
    IP 10.99.1.1
    MAC 00:1c:73:99:01:01
}

// INSTRUCTION: Declare the RFC 1112 multicast group 239.192.10.1.
HOST market_mcast_group {
    IP 239.192.10.1
    MAC 01:00:5e:40:0a:01
}

// INSTRUCTION: Define lossless Priority Flow Control (PCP 3, DSCP 26, ECN 2) RoCEv2 RDMA Write and CNP congestion feedback.
FLOW rocev2_rdma_exchange(a, b) {
    a -> b VLAN 88 PCP 3 DSCP 26 ECN 3 UDP SRCPORT 51001 DSTPORT 4791 PAYLOAD "IB_BTH_RDMA_WRITE_ONLY_QP_000100_PSN_101" WAIT 200us
    a <- b VLAN 88 PCP 6 DSCP 48 ECN 0 UDP SRCPORT 4791 DSTPORT 4791 HEXPAYLOAD "81000000000001000000000000000000" WAIT 100us
    a <- b VLAN 88 PCP 3 DSCP 26 ECN 2 UDP SRCPORT 51001 DSTPORT 4791 PAYLOAD "IB_BTH_RDMA_ACK_SYNDROME_00_PSN_101" WAIT 200us
}

// INSTRUCTION: Define a multicast UDP market data tick burst.
FLOW multicast_market_tick(pub_host, mcast_grp) {
    pub_host -> mcast_grp DSCP 34 UDP SRCPORT 30001 DSTPORT 15500 PAYLOAD "ITCH_50_ADD_ORDER_NVDA_100_SHARES" WAIT 500us
}

// INSTRUCTION: Compile the RoCEv2 RDMA exchange and 4 multicast market ticks.
COMPILE {
    rocev2_rdma_exchange(gpu_worker_a, gpu_worker_b)
    LOOP 4 {
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
HOST gnb_n2 {
    IP 10.50.2.10
    MAC 00:1c:73:50:02:10
}

// INSTRUCTION: Declare 5G Core Access and Mobility Management Function (AMF).
HOST amf_n2 {
    IP 10.50.2.1
    MAC 00:1c:73:50:02:01
}

// INSTRUCTION: Execute 4-way SCTP association setup, NGAP Stream 0 & Stream 1 DATA transfer, SACK, Heartbeat, and Shutdown.
FLOW sctp_5g_ngap_lifecycle(gnb, amf) {
    gnb -> amf DSCP 46 SCTP CHUNK INIT VTAG 0 SRCPORT 38412 DSTPORT 38412 WAIT 1ms
    gnb <- amf DSCP 46 SCTP CHUNK INIT_ACK VTAG 3841201 SRCPORT 38412 DSTPORT 38412 WAIT 1ms
    gnb -> amf DSCP 46 SCTP CHUNK COOKIE_ECHO VTAG 3841201 SRCPORT 38412 DSTPORT 38412 PAYLOAD "HMAC_STATE_COOKIE_5G_AMF" WAIT 1ms
    gnb <- amf DSCP 46 SCTP CHUNK COOKIE_ACK VTAG 3841201 SRCPORT 38412 DSTPORT 38412 WAIT 1ms
    gnb -> amf DSCP 46 SCTP CHUNK DATA VTAG 3841201 SEQ 100 STREAM 0 SSN 0 PPID 60 SRCPORT 38412 DSTPORT 38412 PAYLOAD "NGAP_NG_SETUP_REQUEST_GNB_ID_001" WAIT 2ms
    gnb <- amf DSCP 46 SCTP CHUNK SACK VTAG 3841201 SEQ 100 SRCPORT 38412 DSTPORT 38412 WAIT 1ms
    gnb <- amf DSCP 46 SCTP CHUNK DATA VTAG 3841201 SEQ 200 STREAM 0 SSN 0 PPID 60 SRCPORT 38412 DSTPORT 38412 PAYLOAD "NGAP_NG_SETUP_RESPONSE_PLMN_00101" WAIT 2ms
    gnb -> amf DSCP 46 SCTP CHUNK DATA VTAG 3841201 SEQ 101 STREAM 1 SSN 0 PPID 60 SRCPORT 38412 DSTPORT 38412 PAYLOAD "NGAP_INITIAL_UE_MESSAGE_REGISTRATION_REQ" WAIT 2ms
    gnb <- amf DSCP 46 SCTP CHUNK SACK VTAG 3841201 SEQ 101 SRCPORT 38412 DSTPORT 38412 WAIT 1ms
    gnb -> amf DSCP 46 SCTP CHUNK HEARTBEAT VTAG 3841201 SRCPORT 38412 DSTPORT 38412 PAYLOAD "HB_INFO_PATH_PRIMARY" WAIT 5ms
    gnb <- amf DSCP 46 SCTP CHUNK HEARTBEAT_ACK VTAG 3841201 SRCPORT 38412 DSTPORT 38412 PAYLOAD "HB_INFO_PATH_PRIMARY" WAIT 5ms
    gnb -> amf DSCP 46 SCTP CHUNK SHUTDOWN VTAG 3841201 SEQ 200 SRCPORT 38412 DSTPORT 38412 WAIT 1ms
}

// INSTRUCTION: Compile the 5G N2 SCTP association lifecycle.
COMPILE {
    sctp_5g_ngap_lifecycle(gnb_n2, amf_n2)
}
```

#### Example B: Dual-Stack IPv6 Telecom SIGTRAN M3UA (`PPID 3`, Port `2905`) & WebRTC DataChannel (`PPID 50/51`, Port `5000`)
```frameassembly
// PROMPT: IPv6 SCTP multi-stream transport for SS7 SIGTRAN M3UA (PPID 3) and WebRTC DataChannels (PPID 50 and PPID 51) with ABORT teardown.
// TOKENS: HOST, IP, MAC, FLOW, SCTP, CHUNK, DATA, SACK, ABORT, VTAG, SEQ, STREAM, SSN, PPID, SRCPORT, DSTPORT, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv6 Signaling Gateway A.
HOST sgw_v6_a {
    IP 2001:db8:2905::1
    MAC 00:50:56:29:05:01
}

// INSTRUCTION: Declare IPv6 Softswitch MGC B.
HOST mgc_v6_b {
    IP 2001:db8:2905::2
    MAC 00:50:56:29:05:02
}

// INSTRUCTION: Define SIGTRAN M3UA signaling on Stream 1 (PPID 3) and WebRTC DataChannel messages on Stream 2 (PPID 50/51).
FLOW ipv6_sctp_m3ua_and_webrtc(a, b) {
    a -> b SCTP CHUNK DATA VTAG 290501 SEQ 1 STREAM 1 SSN 0 PPID 3 SRCPORT 2905 DSTPORT 2905 PAYLOAD "M3UA_PAYLOAD_DATA_ISUP_IAM" WAIT 2ms
    a <- b SCTP CHUNK SACK VTAG 290501 SEQ 1 SRCPORT 2905 DSTPORT 2905 WAIT 1ms
    a -> b SCTP CHUNK DATA VTAG 500051 SEQ 10 STREAM 2 SSN 0 PPID 50 SRCPORT 5000 DSTPORT 5000 PAYLOAD "DCEP_DATA_CHANNEL_OPEN_RELIABLE" WAIT 2ms
    a <- b SCTP CHUNK DATA VTAG 500051 SEQ 20 STREAM 2 SSN 0 PPID 51 SRCPORT 5000 DSTPORT 5000 PAYLOAD "{\"channel\":\"telemetry\",\"status\":\"connected\"}" WAIT 2ms
    a -> b SCTP CHUNK ABORT VTAG 500051 SRCPORT 5000 DSTPORT 5000 PAYLOAD "USER_INITIATED_ABORT_CAUSE_0x000C" WAIT 1ms
}

// INSTRUCTION: Compile the IPv6 SCTP M3UA and WebRTC DataChannel capture.
COMPILE {
    ipv6_sctp_m3ua_and_webrtc(sgw_v6_a, mgc_v6_b)
}
```
