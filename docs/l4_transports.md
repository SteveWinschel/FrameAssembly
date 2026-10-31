# Layer 4 Transport Protocols Reference (`TCP`, `UDP`, `SCTP`)

FrameAssembly supports **TCP**, **UDP**, and **SCTP** across IPv4 and IPv6, automatically computing IPv4/IPv6 pseudo-header checksums (`TCP`/`UDP`) and hardware-valid 32-bit Castagnoli CRC32c checksums (`SCTP`).

| Protocol | Keyword | IP Proto | Checksum | Key Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **TCP** | `TCP` | `6` | RFC 1071 + IPv4/IPv6 Pseudo-Header | Automatic `SEQ`/`ACKNUM` & port tracking, all 8 flags, `MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`/`TSECR` |
| **UDP** | `UDP` | `17` | RFC 1071 + IPv4/IPv6 Pseudo-Header | Unicast/multicast datagrams, bidirectional port reversal, custom payloads, fragmentation tests |
| **SCTP** | `SCTP` | `132` | 32-bit CRC32c (Castagnoli) | 4-way `INIT`/`COOKIE_ECHO` handshake, `VTAG`, multi-streaming (`STREAM`, `SSN`, `TSN`, `PPID`) |

---

## 1. Transmission Control Protocol (`TCP` — RFC 9293)

### Automatic Connection State vs. Manual Overrides
When `SEQ`, `ACKNUM`, or ports are omitted on follow-up packets in a flow, FrameAssembly maintains connection state automatically:
* **Bidirectional port swapping:** If `c -> s tcp syn srcport 52000 dstport 443` is followed by `c <- s tcp syn ack`, the reply automatically sets `srcport 443` and `dstport 52000`.
* **Sequence accounting:** `SYN` and `FIN` consume `1` sequence number (`SEQ + 1`), while data packets advance `SEQ` by the exact payload byte count—including Layer 7 TCP protocols (`HTTP`, `TLS`, `SSH`, `POSTGRES`, etc.) on the same connection.
* **Explicit overrides:** Specifying `SEQ`, `ACKNUM`, or `WIN` on any statement overrides the tracked value for that packet (useful for testing retransmissions, out-of-window drops, or zero-window stalls).

| Category | Modifier Syntax | Description & Default |
| :--- | :--- | :--- |
| **Ports** | `SRCPORT <u16>`, `DSTPORT <u16>` | Source and destination ports (default `DSTPORT 80`; never write `SPORT`/`DPORT`) |
| **Control Flags** | `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR` | Combine any flags separated by spaces (e.g. `tcp syn ack` or `tcp rst ack`) |
| **Sequence / Ack**| `SEQ <u32>`, `ACKNUM <u32>` | 32-bit Sequence and Acknowledgment numbers (never write `ACK_NUM`) |
| **Window & Urgent**| `WIN <u16>` (or `WINDOW <u16>`), `URGENT <u16>` | Receive window size (default `65535`) and Urgent Pointer offset |
| **RFC 7323 Options**| `MSS <u16>`, `WSCALE <0..14>`, `SACK_PERM`, `TSVAL <u32>`, `TSECR <u32>` | Max Segment Size, Window Scale shift count, SACK Permitted, and Timestamps |
| **Dual-Mode L7** | `TRANSPORT TCP` | Forces dual-transport L7 protocols (`DNS`, `SIP`, `SYSLOG`, `NFS`) over TCP |

### Example A: Full TCP Handshake with Options, Data Transfer & FIN Close
```frameassembly
host app_client { ip 10.10.20.50 }
host api_server { ip 10.10.20.10 }

flow tcp_full_lifecycle(c, s) {
    c -> s tcp syn srcport 54321 dstport 443 mss 1460 wscale 7 sack_perm tsval 10000 tsecr 0 wait 1ms
    c <- s tcp syn ack mss 1460 wscale 7 sack_perm tsval 20000 tsecr 10000 wait 1ms
    c -> s tcp ack win 512 tsval 10002 tsecr 20000 wait 1ms
    c -> s tcp psh ack win 512 tsval 10005 tsecr 20000 payload "GET /v1/status HTTP/1.1\r\nHost: api.internal\r\n\r\n" wait 2ms
    c <- s tcp psh ack win 512 tsval 20005 tsecr 10005 payload "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK" wait 2ms
    c -> s tcp fin ack win 512 tsval 10010 tsecr 20005 wait 1ms
    c <- s tcp fin ack win 512 tsval 20010 tsecr 10010 wait 1ms
    c -> s tcp ack win 512 tsval 10012 tsecr 20010
}

compile {
    tcp_full_lifecycle(app_client, api_server)
}
```

### Example B: ECN Congestion Signaling, Urgent Pointer, Zero-Window & `RST` Abort
```frameassembly
host sender_v6   { ip 2001:db8:40::10 }
host receiver_v6 { ip 2001:db8:40::20 }

flow tcp_edge_cases(a, b) {
    a -> b tcp syn ece cwr srcport 58000 dstport 9000 ecn 2 wait 1ms
    a <- b tcp syn ack ece ecn 2 wait 1ms
    a -> b tcp psh ack ecn 3 payload "CONGESTED_BURST" wait 1ms
    a <- b tcp ack ece window 16384 ecn 2 wait 1ms
    a -> b tcp psh ack cwr window 32768 ecn 2 payload "CWND_REDUCED" wait 1ms
    a -> b tcp psh ack urg urgent 1 payload "!" wait 1ms
    a <- b tcp ack window 0 wait 5ms
    a -> b tcp rst ack window 0
}

compile {
    tcp_edge_cases(sender_v6, receiver_v6)
}
```

---

## 2. User Datagram Protocol (`UDP` — RFC 768)

Provides connectionless datagram framing with automatic port reversal across `<-` arrows and automatic multicast MAC derivation when targeting multicast IPs.
* **Modifiers:** `SRCPORT <u16>`, `DSTPORT <u16>`, `TRANSPORT UDP` (for dual-transport L7 protocols), `PAYLOAD "<str>"`, `HEXPAYLOAD "<hex>"`.

```frameassembly
host worker_a   { ip 10.88.1.10 }
host worker_b   { ip 10.88.1.20 }
host feed_mcast { ip 239.192.10.1 }

flow udp_unicast_and_mcast(a, b, mcast) {
    a -> b vlan 88 pcp 3 dscp 26 udp srcport 51001 dstport 4791 payload "RDMA_WRITE_QP_101" wait 200us
    a <- b vlan 88 pcp 3 dscp 26 udp payload "RDMA_ACK_PSN_101" wait 500us
    a -> mcast dscp 34 udp srcport 30001 dstport 15500 hexpayload "01020304deadbeef"
}

compile {
    udp_unicast_and_mcast(worker_a, worker_b, feed_mcast)
}
```

---

## 3. Stream Control Transmission Protocol (`SCTP` — RFC 9260)

Used across 5G Core (`NGAP` port `38412`), 4G LTE (`S1AP` port `36412`, `Diameter` port `3868`), Telecom SS7 SIGTRAN (`M3UA` port `2905`), and WebRTC DataChannels (`5000`).

| Modifier | Syntax | Description & Common Values |
| :--- | :--- | :--- |
| **Chunk Type** | `CHUNK <TYPE>` | `INIT`, `INIT_ACK`, `COOKIE_ECHO`, `COOKIE_ACK`, `DATA`, `SACK`, `HEARTBEAT`, `HEARTBEAT_ACK`, `SHUTDOWN`, `ABORT` |
| **Verification Tag**| `VTAG <u32>` | 32-bit association tag (`0` on `INIT`, peer tag thereafter) |
| **Stream & Seq** | `STREAM <u16>`, `SSN <u16>`, `TSN <u32>` (`SEQ <u32>`) | Stream ID, Stream Sequence Number, and Transmission Sequence Number |
| **Payload Proto ID**| `PPID <u32>` | `60` = 5G NGAP, `18` = S1AP, `27` = X2AP, `3` = M3UA, `46` = Diameter, `50` = WebRTC DCEP, `51` = WebRTC String |

```frameassembly
host gnb_n2 { ip 10.50.2.10 }
host amf_n2 { ip 10.50.2.1 }

flow sctp_5g_ngap_session(gnb, amf) {
    gnb -> amf dscp 46 sctp chunk init vtag 0 srcport 38412 dstport 38412 wait 1ms
    gnb <- amf dscp 46 sctp chunk init_ack vtag 3841201 wait 1ms
    gnb -> amf dscp 46 sctp chunk cookie_echo vtag 3841201 payload "STATE_COOKIE_5G" wait 1ms
    gnb <- amf dscp 46 sctp chunk cookie_ack vtag 3841201 wait 1ms
    gnb -> amf dscp 46 sctp chunk data vtag 3841201 seq 100 stream 0 ssn 0 ppid 60 payload "NGAP_NG_SETUP_REQ" wait 2ms
    gnb <- amf dscp 46 sctp chunk sack vtag 3841201 seq 100 wait 5ms
    gnb -> amf dscp 46 sctp chunk heartbeat vtag 3841201 payload "PATH_PRIMARY" wait 2ms
    gnb <- amf dscp 46 sctp chunk heartbeat_ack vtag 3841201 payload "PATH_PRIMARY" wait 2ms
    gnb -> amf dscp 46 sctp chunk shutdown vtag 3841201 seq 100
}

compile {
    sctp_5g_ngap_session(gnb_n2, amf_n2)
}
```