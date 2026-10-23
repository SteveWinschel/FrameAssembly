# FrameAssembly
[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**FrameAssembly** is a domain-specific language (DSL) and optimizing compiler that compiles human-readable, declarative network packet specifications into deterministic, wire-valid `.pcap` / `.pcapng` packet captures. Engineered for network technicians, security engineers, protocol researchers, firewall/IDS validation, and AI synthetic traffic generation, FrameAssembly eliminates the complexity of binary packet crafting with zero-keyword RFC-compliant defaults and intuitive Wireshark-aligned syntax.

---

## Unified `<layer>/<protocol>` Architecture

FrameAssembly v1.0.0 enforces a unified `<layer>/<protocol>` architecture across both compiler implementation modules (`src/`) and example captures (`examples/`):

```text
frameassembly/
├── src/
│   ├── lexer/                     # Zero-copy Logos tokenizer (mod.rs, tests.rs)
│   ├── ast/                       # Abstract Syntax Tree definitions
│   │   ├── mod.rs                 # Re-exports, Program, HostDef, FlowDef, ProtocolSpec
│   │   ├── l2/                    # Layer 2 protocol AST specs (arp, vlan, qinq, mpls, etc.)
│   │   ├── l3/                    # Layer 3 protocol AST specs (icmp, ndp, gre, ospf, bgp, etc.)
│   │   ├── l4/                    # Layer 4 transport AST specs (tcp, udp, sctp)
│   │   └── l7/                    # Layer 7 protocol AST specs (snmp, dns, http, modbus, etc.)
│   ├── parser/                    # Winnow parser combinators
│   │   ├── mod.rs                 # Combinators, validation, and parse_program
│   │   ├── tests.rs               # Parser unit tests
│   │   ├── l2/                    # Layer 2 protocol parsers
│   │   ├── l3/                    # Layer 3 protocol parsers
│   │   ├── l4/                    # Layer 4 transport parsers
│   │   └── l7/                    # Layer 7 application parsers
│   ├── builders/                  # Zero-heap packet builders and payload encoders
│   │   ├── mod.rs                 # Layer re-exports and backwards-compatible aliases
│   │   ├── l2/                    # Layer 2 wire builders
│   │   ├── l3/                    # Layer 3 tunnel and routing builders
│   │   ├── l4/                    # Layer 4 transport builders
│   │   └── l7/                    # Layer 7 infra, app, OT, and snmp/ builders
│   ├── backend/                   # 4-tuple state tracking, timing, and PCAP emission
│   ├── packet.rs                  # Etherparse network packet encapsulation
│   ├── pcap.rs                    # Nanosecond-precision PCAPNG writer (pcap-file)
│   └── main.rs                    # Command-line binary interface
└── examples/
    ├── l2/                        # Layer 2 scenarios (<proto>/<proto>_<scenario>.fasm)
    ├── l3/                        # Layer 3 scenarios (icmp, ndp, gre, ipsec, ospf, bgp, etc.)
    ├── l4/                        # Layer 4 scenarios (tcp, udp, sctp)
    ├── l7/                        # Layer 7 scenarios (dns, http, tls, modbus, etc.)
    │   └── snmp/                  # SNMP scenarios (snmpv1/, snmpv2c/, snmpv3/)
    └── topologies/                # Cross-cutting dual-stack, QoS, and multi-tier topologies
```

---

## Key Features

- **81 Native Network Protocols:** Complete, zero-dependency packet crafting across Layer 2, Layer 3, Layer 4, and Layer 7 protocols with smart RFC-compliant wire defaults and field overrides.
- **Unified `<layer>/<protocol>` Organization:** Perfect structural symmetry between compiler AST/parser/builders and the `examples/` corpus.
- **Dual-Stack IPv4 & IPv6 Polymorphism:** Write network flows once; compile them identically over IPv4 or IPv6 endpoints. Automatic RFC 2464 (`33:33:xx:xx:xx:xx`) and RFC 1112 (`01:00:5e:xx:xx:xx`) multicast MAC derivation.
- **Comprehensive L2–L4 Modifiers:** Full control over 802.1Q VLAN, 802.1ad QinQ, MPLS labels, IPv4/IPv6 TTL/Hop Limit, DSCP, ECN, 20-bit Flow Labels, fragmentation flags (DF, MF, FragOffset), TCP options (MSS, WSCALE, SACK, Timestamps), and SCTP chunks.
- **Stateful 4-Tuple Port & Sequence Progression:** Automatic port binding and swapping across directional arrows (`->` and `<-`), accurate TCP sequence/acknowledgment tracking, and loopback (`127.0.0.1`, `::1`) connection handling.
- **Cryptographic SNMPv3 Engine:** Complete RFC 3414 / RFC 3826 / RFC 7860 USM implementation supporting HMAC-MD5, HMAC-SHA1, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, DES-CBC, and AES-128-CFB encryption.
- **Deterministic Nanosecond Timing:** High-fidelity timestamp serialization using `pcap-file 2.0` with configurable `WAIT` durations (`ns`, `us`, `ms`, `s`, `m`).
- **Rich Source-Spanned Diagnostics:** Contextual error diagnostics powered by `miette 7.6` and zero-copy tokenization via `logos 0.14`.

---

## Getting Started

### Prerequisites
Install Rust and Cargo using [rustup.rs](https://rustup.rs/).

### Installation

**From Cargo:**
```bash
cargo install frameassembly
```

**From Source Repository:**
```bash
git clone https://github.com/stevewinschel/frameassembly.git
cd frameassembly
cargo build --release
```

### Command-Line Usage

Compile a `.fasm` specification into a wire-valid `.pcap` capture:

```bash
# Default output to output.pcap
frameassembly scenario.fasm

# Explicit output path with -o / --output
frameassembly scenario.fasm -o capture.pcap
frameassembly scenario.fasm --output /path/to/traffic.pcap
```

### Editor Support (VS Code & Antigravity IDE)

A dedicated VS Code extension providing full syntax highlighting for all 81 protocols, sub-keywords, modifiers, durations, IPv6, and OIDs is available in `frameassembly-vscode/`:

```bash
code --install-extension frameassembly-vscode/frameassembly-vscode-1.0.1.vsix
```

---

## Language Syntax Guide

### 1. Host Declarations
Hosts define network endpoints with IP and optional MAC addresses. Unspecified MAC addresses are automatically derived from the IP address:

```frameassembly
// IPv4 Host with explicit MAC
HOST web_server { IP 192.168.1.100 MAC 00:11:22:33:44:55 }

// IPv6 Host with auto-derived unicast MAC
HOST ipv6_client { IP 2001:db8::10 }

// Multicast Host (auto-derives 33:33:00:00:00:01 per RFC 2464)
HOST all_nodes_mcast { IP ff02::1 }

// IPv4 Multicast Host (auto-derives 01:00:5e:00:00:fb per RFC 1112)
HOST mdns_mcast { IP 224.0.0.251 }
```

### 2. Flow Declarations & Directionality
Flows define parameterized communication sequences between endpoints:

```frameassembly
FLOW tcp_handshake(client, server) {
    client -> server TCP SYN WIN 65535
    client <- server TCP SYN ACK WIN 65535
    client -> server TCP ACK
}
```

- `A -> B`: `A` is the transmitter (source), `B` is the receiver (destination).
- `A <- B`: `B` is the transmitter (source), `A` is the receiver (destination).
- **Two-Stage Port Inheritance:** If subsequent statements omit `SRCPORT` or `DSTPORT`, ports are automatically remembered and swapped across reversed arrows.

### 3. Layer 2–L4 Frame Modifiers

| Category | Modifiers | Description |
|---|---|---|
| **Layer 2** | `SRCMAC <mac>`, `DSTMAC <mac>` | Override source or destination Ethernet address |
| | `ETHERTYPE <u16>` | Override Ethernet Type field (e.g. `0x8100`, `0x8847`) |
| | `VLAN <1..4094> [PCP <0..7>] [DEI <0..1>]` | IEEE 802.1Q Virtual LAN tagging |
| | `QINQ <1..4094> [INNER_VLAN <1..4094>]` | IEEE 802.1ad Provider Bridging dual VLAN tags |
| | `MPLS <label> [EXP <0..7>] [BOS <0..1>] [MPLS_TTL <u8>]` | Multiprotocol Label Switching shim header |
| **Layer 3** | `TTL <0..255>` | Time-To-Live (IPv4) or Hop Limit (IPv6) |
| | `DSCP <0..63>` | Differentiated Services Code Point (QoS) |
| | `ECN <0..3>` | Explicit Congestion Notification bits |
| | `FLOWLABEL <0..1048575>` | 20-bit IPv6 Flow Label (ignored on IPv4) |
| | `IPID <u16>`, `DF`, `MF`, `FRAGOFFSET <u16>` | IPv4 identification and fragmentation flags |
| **Layer 4** | `SRCPORT <u16>`, `DSTPORT <u16>` | Source and destination transport port numbers |
| | `TRANSPORT TCP \| UDP` | Explicit transport override for dual-mode protocols |
| | `SEQ <u32>`, `ACKNUM <u32>`, `WIN <u16>` | TCP sequence number, ack number, and window size |
| | `MSS <u16>`, `WSCALE <u8>`, `SACK_PERM` | TCP Maximum Segment Size, Window Scale, SACK options |
| | `TSVAL <u32>`, `TSECR <u32>`, `URGENT <u16>` | TCP Timestamps and urgent pointer |
| **Payload** | `PAYLOAD "<string>"` | Text payload with escape sequences (`\r`, `\n`, `\t`, `\xHH`) |
| | `HEXPAYLOAD "<hex>"` | Arbitrary hexadecimal byte payload (e.g. `"deadbeef"`) |
| **Timing** | `WAIT <duration>` | Inter-frame step delay (`ns`, `us`, `ms`, `s`, `m`) |

### 4. Compilation & Execution Loops

The `COMPILE` block executes declared flows, supporting multi-host parameter passing and loops:

```frameassembly
COMPILE {
    LOOP 10 {
        tcp_handshake(client_v4, server_v4)
        tcp_handshake(client_v6, server_v6)
    }
}
```

---

## Canonical RFC Wire Defaults Table

Every protocol in FrameAssembly can be instantiated with **zero mandatory sub-keywords**, emitting RFC-compliant default wire headers:

| Protocol | Layer | Transport | Default Port | Default Wire Behavior |
|---|---|---|---|---|
| `ARP` | L2 | Ethernet (0x0806) | N/A | Request, Hardware 1 (Ethernet), Protocol 0x0800 (IPv4), hardware len 6, protocol len 4. |
| `VLAN` | L2 | Ethernet (0x8100) | N/A | IEEE 802.1Q tag, default VLAN ID 100, PCP 0, DEI 0. |
| `QINQ` | L2 | Ethernet (0x88A8) | N/A | IEEE 802.1ad outer tag (VLAN 100) + 802.1Q inner tag (VLAN 200). |
| `LLDP` | L2 | Ethernet (0x88CC) | N/A | Multicast `01:80:c2:00:00:0e`, Chassis ID & Port ID TLVs, TTL 120s, End TLV. |
| `STP` | L2 | LLC/SNAP (0x4242) | N/A | Multicast `01:80:c2:00:00:00`, Configuration BPDU, Root ID, Bridge ID, Cost 0. |
| `LACP` | L2 | Ethernet (0x8809) | N/A | Multicast `01:80:c2:00:00:02`, Actor Info & Partner Info TLVs, Collector TLV. |
| `EAPOL` | L2 | Ethernet (0x888E) | N/A | IEEE 802.1X Version 1, Type 1 (EAP-Packet), Identity request/response. |
| `MPLS` | L2 | Ethernet (0x8847) | N/A | Label 16, EXP 0, BOS 1, TTL 64 unicast shim header. |
| `ICMP` | L3 | IP proto 1 / 58 | N/A | Echo Request (Type 8 for IPv4, Type 128 for IPv6), ID 1, Seq 1. |
| `NDP` | L3 | IPv6 ICMPv6 (58) | N/A | Neighbor Solicitation (Type 135) to Solicited-Node Multicast (`ff02::1:ffxx:xxxx`). |
| `IGMP` | L3 | IPv4 proto 2 | N/A | Membership Query to `224.0.0.1` (All Hosts), Max Resp Time 10.0s. |
| `MLD` | L3 | IPv6 ICMPv6 (58) | N/A | Multicast Listener Query (Type 130) to `ff02::1`, Router Alert option. |
| `GRE` | L3 | IP proto 47 | N/A | GRE Version 0, Protocol Type 0x0800 (IPv4) / 0x86DD (IPv6). |
| `VXLAN` | L3 | UDP | 4789 | Flags 0x08 (I flag), 24-bit VNI 1000, 8-byte encapsulation header. |
| `GENEVE` | L3 | UDP | 6081 | Version 0, 24-bit VNI 1000, Protocol Type 0x6558 (Ethernet). |
| `IPSEC` / `ESP` | L3 | IP proto 50 | N/A | SPI 0x1000, Sequence 1, default ESP header. |
| `AH` | L3 | IP proto 51 | N/A | SPI 0x1000, Sequence 1, 96-bit ICV header. |
| `IKEV2` | L3 | UDP | 500 | SA_INIT exchange (Type 34), Initiator SPI random, Responder SPI 0. |
| `WIREGUARD` | L3 | UDP | 51820 | Handshake Initiation message (Type 1), Sender index 1. |
| `OSPF` | L3 | IP proto 89 | N/A | OSPFv2 (IPv4) or OSPFv3 (IPv6) Hello packet, Area 0.0.0.0, to `224.0.0.5`/`ff02::5`. |
| `BGP` | L3 | TCP | 179 | BGP-4 16-byte marker, OPEN message, ASN 65001, Hold Time 180s. |
| `RIP` | L3 | UDP | 520 | RIPv2 Response (Command 2), Version 2, Route AFI 2 (IP), Metric 1. |
| `VRRP` | L3 | IP proto 112 | N/A | VRRPv2/v3 Advertisement, VRID 1, Priority 100 to `224.0.0.18`/`ff02::12`. |
| `HSRP` | L3 | UDP | 1985 | Cisco HSRP Hello, Opcode 0, State Active, Group 1 to `224.0.0.2`. |
| `PIM` | L3 | IP proto 103 | N/A | PIM-SM Hello message, DR Priority 1 to `224.0.0.13`/`ff02::d`. |
| `BFD` | L3 | UDP | 3784 | Single-hop Control packet, State Up, Detect Mult 3, Min TX/RX 1000ms. |
| `OPENFLOW` | L3 | TCP | 6653 | OpenFlow 1.3 Hello / Features Request (Version 0x04), XID 1. |
| `TCP` | L4 | IP proto 6 | 80 | Sequence numbers auto-incremented, ACK numbers tracked across reverse arrows. |
| `UDP` | L4 | IP proto 17 | 80 | Stateless UDP datagram with computed RFC 768 checksum. |
| `SCTP` | L4 | IP proto 132 | 80 | Verification Tag 0, DATA chunk, TSN 1, Stream 0, CRC32c checksum. |
| `SNMP1` | L7 | UDP | 162 / 161 | Community `"public"`, sysUpTime 0, Trap PDU, RFC 1157 BER encoding. |
| `SNMP2` | L7 | UDP | 162 / 161 | Community `"public"`, sysUpTime 0, Trap PDU, RFC 3416 BER encoding. |
| `SNMP3` | L7 | UDP | 161 / 162 | USM security model, RFC 3414 / 3826 / 7860 auth & priv engine. |
| `DNS` / `MDNS` | L7 | UDP | 53 / 5353 | Standard Query, TXID 0x1234, QNAME `"example.com"`, QTYPE A / AAAA. |
| `DHCP` | L7 | UDP | 67 / 68 | DHCPDISCOVER (IPv4) or Solicit (IPv6 UDP 546/547) with client MAC. |
| `NTP` | L7 | UDP | 123 | Mode 3 (Client), Version 4, Stratum 0, Poll 4. |
| `PTP` | L7 | UDP | 319 / 320 | IEEE 1588-2008 Version 2 Sync message, Domain 0. |
| `RADIUS` | L7 | UDP | 1812 / 1813 | Access-Request (Code 1), Identifier 1, NAS-IP default to host. |
| `TACACS` | L7 | TCP | 49 | TACACS+ Authentication Start, Session ID 0x12345678. |
| `SYSLOG` | L7 | UDP | 514 | RFC 5424 PRI `<14>` (Facility 1 User, Severity 6 Info), APP `"frameassembly"`. |
| `NETFLOW` | L7 | UDP | 2055 | NetFlow v5/v9 Flow Record export packet. |
| `IPFIX` | L7 | UDP | 4739 | IPFIX Template & Data Record packet. |
| `SFLOW` | L7 | UDP | 6343 | sFlow v5 Flow Sample Datagram. |
| `TFTP` | L7 | UDP | 69 | Read Request (RRQ), Filename `"file.bin"`, Mode `"octet"`. |
| `FTP` | L7 | TCP | 21 | Greeting banner `"220 FTP Server Ready\r\n"` or `USER anonymous`. |
| `SSH` | L7 | TCP | 22 | Identification banner `"SSH-2.0-FrameAssembly_1.0\r\n"`. |
| `TELNET` | L7 | TCP | 23 | IAC WILL/DO negotiation bytes (`\xff\xfb...`). |
| `HTTP` | L7 | TCP | 80 | `GET / HTTP/1.1\r\nHost: <host>\r\n\r\n`. |
| `HTTP2` | L7 | TCP | 443 | 24-byte client connection preface (`PRI * HTTP/2.0...`) + SETTINGS frame. |
| `GRPC` | L7 | TCP | 50051 | HTTP/2 POST with `content-type: application/grpc`. |
| `WEBSOCKET`| L7 | TCP | 80 | HTTP Upgrade handshake or masked client text/binary frame. |
| `TLS` | L7 | TCP | 443 | TLS 1.3 ClientHello with SNI and Supported Versions extensions. |
| `QUIC` | L7 | UDP | 443 | QUIC Initial packet with TLS 1.3 ClientHello payload. |
| `STUN` | L7 | UDP | 3478 | Binding Request, RFC 8489 Magic Cookie `0x2112A442`. |
| `SIP` | L7 | UDP / TCP | 5060 | `INVITE sip:bob@domain SIP/2.0\r\n...`. |
| `RTP` | L7 | UDP | 5004 | RTP Version 2, Payload Type 0 (PCMU), Seq 1, Timestamp 0. |
| `RTSP` | L7 | TCP | 554 | `DESCRIBE rtsp://server/media RTSP/1.0\r\n...`. |
| `SMTP` | L7 | TCP | 25 | `EHLO mail.example.com\r\n`. |
| `IMAP` | L7 | TCP | 143 | `A001 CAPABILITY\r\n`. |
| `POP3` | L7 | TCP | 110 | `+OK POP3 server ready\r\n` or `USER user\r\n`. |
| `KERBEROS` | L7 | UDP / TCP | 88 | Kerberos AS-REQ for krbtgt ticket. |
| `LDAP` | L7 | TCP | 389 | LDAP BindRequest (Simple) message. |
| `SMB` | L7 | TCP | 445 | SMB2 Negotiate Protocol Request. |
| `NFS` | L7 | TCP | 2049 | ONC RPC NULL / GETATTR compound call. |
| `REDIS` | L7 | TCP | 6379 | RESP command `*1\r\n$4\r\nPING\r\n`. |
| `MEMCACHED`| L7 | TCP | 11211 | Text command `version\r\n` or Binary GET packet. |
| `MYSQL` | L7 | TCP | 3306 | Initial Handshake Packet v10 or COM_QUERY. |
| `POSTGRES` | L7 | TCP | 5432 | SSLRequest / StartupMessage v3.0. |
| `MQTT` | L7 | TCP | 1883 | MQTT v3.1.1 CONNECT packet, Clean Session. |
| `COAP` | L7 | UDP | 5683 | Confirmable (CON) GET, Code 0.01, Msg ID 1. |
| `AMQP` | L7 | TCP | 5672 | 8-byte protocol header `'AMQP\x00\x00\x09\x01'`. |
| `SSDP` | L7 | UDP | 1900 | Multicast `M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n...`. |
| `WHOIS` | L7 | TCP | 43 | Query string `"example.com\r\n"`. |
| `MODBUS` | L7 | TCP | 502 | MBAP header + Function 3 (Read Holding Registers). |
| `BACNET` | L7 | UDP | 47808 | BVLC 0x81 + APDU Unconfirmed WHO-IS. |
| `DNP3` | L7 | TCP / UDP | 20000 | DNP3 0x0564 Data Link Header + Function 1 (Read). |
| `S7COMM` | L7 | TCP | 102 | TPKT + ISO-on-TCP COTP Connection Request + S7 Setup Communication. |
| `ETHERNETIP`| L7 | TCP / UDP | 44818 | Encapsulation Command 0x0065 (Register Session). |
| `OPCUA` | L7 | TCP | 4840 | Hello message `HEL` (Chunk 'F') with endpoint URL. |

---

## Exhaustive Protocol & Sub-Keyword Reference (All 81 Protocols)

### 1. Layer 2 Protocols (8 Protocols)

- [examples/l2/arp/](examples/l2/arp/) — **`ARP` (Address Resolution Protocol - RFC 826):**
  - Sub-keywords: `REQUEST`, `REPLY`, `GRATUITOUS` / `GARP`, `SPA <ip>`, `THA <mac>`, `TPA <ip>`, `SENDERMAC <mac>`, `TARGETMAC <mac>`, `SENDERIP <ip>`, `TARGETIP <ip>`.
  - Wire behavior: EtherType 0x0806, Hardware Type 1 (Ethernet), Protocol Type 0x0800 (IPv4). Defaults to `REQUEST` asking for target IP.
- [examples/l2/vlan/](examples/l2/vlan/) — **`VLAN` (IEEE 802.1Q Virtual Bridged LANs):**
  - Sub-keywords: `VLAN <1..4094>`, `PCP <0..7>`, `DEI <0..1>`.
  - Wire behavior: Inserts 4-byte 802.1Q tag (EtherType 0x8100) before inner payload. Defaults to VLAN 100, PCP 0, DEI 0.
- [examples/l2/qinq/](examples/l2/qinq/) — **`QINQ` (IEEE 802.1ad Provider Bridging):**
  - Sub-keywords: `QINQ <1..4094>`, `INNER_VLAN <1..4094>`, `PCP <0..7>`, `DEI <0..1>`.
  - Wire behavior: Dual-tagged stack with 0x88A8 outer service tag and 0x8100 inner customer tag.
- [examples/l2/lldp/](examples/l2/lldp/) — **`LLDP` (IEEE 802.1AB Link Layer Discovery Protocol):**
  - Sub-keywords: `CHASSIS_ID "<str>"`, `PORT_ID "<str>"`, `TTL <u16>`, `SYSNAME "<str>"`, `SYSDESC "<str>"`.
  - Wire behavior: EtherType 0x88CC to multicast `01:80:c2:00:00:0e`. Emits Chassis ID, Port ID, TTL (default 120s), and End TLVs.
- [examples/l2/stp/](examples/l2/stp/) — **`STP` (IEEE 802.1D Spanning Tree / 802.1w RSTP):**
  - Sub-keywords: `ROOT_ID "<str>"`, `BRIDGE_ID "<str>"`, `COST <u32>`, `PORT_ID <u16>`, `MAX_AGE <u16>`, `HELLO_TIME <u16>`, `FORWARD_DELAY <u16>`, `RSTP`, `FLAGS <u8>`.
  - Wire behavior: Emitted over LLC/SNAP to `01:80:c2:00:00:00`. Emits Configuration or RSTP BPDU.
- [examples/l2/lacp/](examples/l2/lacp/) — **`LACP` (IEEE 802.3ad Link Aggregation Control):**
  - Sub-keywords: `ACTOR_SYS "<mac>"`, `ACTOR_KEY <u16>`, `ACTOR_PORT <u16>`, `PARTNER_SYS "<mac>"`, `PARTNER_KEY <u16>`, `PARTNER_PORT <u16>`, `ACTOR_STATE <u8>`, `PARTNER_STATE <u8>`.
  - Wire behavior: Slow Protocols (EtherType 0x8809, Subtype 1) to `01:80:c2:00:00:02`.
- [examples/l2/eapol/](examples/l2/eapol/) — **`EAPOL` (IEEE 802.1X Port-Based Network Access Control):**
  - Sub-keywords: `VERSION <u8>`, `TYPE <u8>`, `START`, `LOGOFF`, `KEY`, `EAP_PACKET`, `EAP_CODE <u8>`, `EAP_ID <u8>`, `EAP_METHOD <u8>`, `IDENTITY "<str>"`.
  - Wire behavior: EtherType 0x888E. Defaults to EAP-Packet with EAP-Request/Response Identity.
- [examples/l2/mpls/](examples/l2/mpls/) — **`MPLS` (RFC 3031 / 3032 Multi-Protocol Label Switching):**
  - Sub-keywords: `LABEL <u32>`, `EXP <0..7>`, `TC <0..7>`, `BOS <0..1>`, `MPLS_TTL <u8>`.
  - Wire behavior: EtherType 0x8847. Emits 32-bit label stack entry (default Label 16, BOS 1, TTL 64).

### 2. Layer 3 Routing, Tunneling & Security Protocols (20 Protocols)

- [examples/l3/icmp/](examples/l3/icmp/) — **`ICMP` (Internet Control Message Protocol - RFC 792 / RFC 4443):**
  - Sub-keywords: `ECHO_REQUEST`, `ECHO_REPLY`, `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`, `CODE <u8>`, `ID <u16>`, `SEQ <u16>`, `GATEWAY <ip>`.
  - Wire behavior: Polymorphic dual-stack (IPv4 protocol 1 or IPv6 protocol 58). Defaults to Echo Request (ID 1, Seq 1).
- [examples/l3/ndp/](examples/l3/ndp/) — **`NDP` (IPv6 Neighbor Discovery - RFC 4861):**
  - Sub-keywords: `ROUTER_SOLICIT`, `ROUTER_ADVERT`, `NEIGHBOR_SOLICIT`, `NEIGHBOR_ADVERT`, `TARGET <ipv6>`, `SLLA <mac>`, `TLLA <mac>`, `ROUTER_LIFETIME <u16>`.
  - Wire behavior: ICMPv6 Type 135 Neighbor Solicitation to Solicited-Node Multicast (`ff02::1:ffxx:xxxx`), Hop Limit 255.
- [examples/l3/igmp/](examples/l3/igmp/) — **`IGMP` (Internet Group Management Protocol - RFC 2236 / RFC 3376):**
  - Sub-keywords: `QUERY`, `REPORT`, `LEAVE`, `V1`, `V2`, `V3`, `GROUP <ipv4>`, `MAX_RESP <u8>`.
  - Wire behavior: IPv4 protocol 2. Defaults to Membership Query to all-systems multicast `224.0.0.1`.
- [examples/l3/mld/](examples/l3/mld/) — **`MLD` (Multicast Listener Discovery for IPv6 - RFC 2710 / RFC 3810):**
  - Sub-keywords: `QUERY`, `REPORT`, `DONE`, `V1`, `V2`, `MULTICAST_ADDR <ipv6>`, `MAX_RESP_DELAY <u16>`.
  - Wire behavior: ICMPv6 Type 130 Listener Query to `ff02::1` with Router Alert hop-by-hop option.
- [examples/l3/gre/](examples/l3/gre/) — **`GRE` (Generic Routing Encapsulation - RFC 2784 / RFC 2890):**
  - Sub-keywords: `CHECKSUM`, `GRE_KEY <u32>`, `GRE_SEQ <u32>`, `GRE_PROTO <u16>`.
  - Wire behavior: IP protocol 47. Encapsulates inner protocol payload (default EtherType 0x0800 or 0x86DD).
- [examples/l3/vxlan/](examples/l3/vxlan/) — **`VXLAN` (Virtual eXtensible Local Area Network - RFC 7348):**
  - Sub-keywords: `VNI <u32>` / `VNID <u32>`, `SRCPORT <u16>`, `DSTPORT <u16>`.
  - Wire behavior: UDP port 4789. Emits 8-byte VXLAN header with 24-bit VNI (default 1000) and inner Ethernet frame.
- [examples/l3/geneve/](examples/l3/geneve/) — **`GENEVE` (Generic Network Virtualization Encapsulation - RFC 8926):**
  - Sub-keywords: `VNI <u32>`, `PROTOCOL_TYPE <u16>`, `OPT_CLASS <u16>`, `OPT_TYPE <u8>`.
  - Wire behavior: UDP port 6081. Emits GENEVE header with 24-bit VNI and EtherType 0x6558.
- [examples/l3/ipsec/](examples/l3/ipsec/) — **`IPSEC` (IP Security Architecture - RFC 4301):**
  - Sub-keywords: `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`.
  - Wire behavior: IP protocol 50 (ESP wrapper). SPI default 0x1000, sequence 1.
- [examples/l3/esp/](examples/l3/esp/) — **`ESP` (Encapsulating Security Payload - RFC 4303):**
  - Sub-keywords: `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
  - Wire behavior: IP protocol 50. Encapsulates encrypted payload with SPI and sequence counter.
- [examples/l3/ah/](examples/l3/ah/) — **`AH` (IP Authentication Header - RFC 4302):**
  - Sub-keywords: `SPI <u32>`, `SEQ <u32>`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
  - Wire behavior: IP protocol 51. Emits SPI, sequence counter, and 96-bit ICV authentication tag.
- [examples/l3/ikev2/](examples/l3/ikev2/) — **`IKEV2` (Internet Key Exchange Protocol Version 2 - RFC 7296):**
  - Sub-keywords: `INITIATOR_SPI "<hex>"`, `RESPONDER_SPI "<hex>"`, `EXCHANGE <u8>`, `SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL`, `MSGID <u32>`, `NEXT_PAYLOAD <u8>`.
  - Wire behavior: UDP port 500. Defaults to IKE_SA_INIT (Exchange Type 34).
- [examples/l3/wireguard/](examples/l3/wireguard/) — **`WIREGUARD` (WireGuard VPN Protocol):**
  - Sub-keywords: `INITIATION`, `COOKIE`, `DATA`, `SENDER <u32>`, `RECEIVER <u32>`, `COUNTER <u64>`.
  - Wire behavior: UDP port 51820. Defaults to Type 1 Handshake Initiation message.
- [examples/l3/ospf/](examples/l3/ospf/) — **`OSPF` (Open Shortest Path First - RFC 2328 / RFC 5340):**
  - Sub-keywords: `HELLO`, `DBD`, `LSR`, `LSU`, `LSACK`, `ROUTER_ID <ip>`, `AREA_ID <ip>`, `HELLO_INTERVAL <u16>`, `DEAD_INTERVAL <u32>`, `PRIORITY <u8>`.
  - Wire behavior: IP protocol 89. Emits OSPFv2 (IPv4) or OSPFv3 (IPv6) Hello packet to `224.0.0.5` / `ff02::5`.
- [examples/l3/bgp/](examples/l3/bgp/) — **`BGP` (Border Gateway Protocol 4 - RFC 4271 / RFC 2545):**
  - Sub-keywords: `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ASN <u32>`, `HOLDTIME <u16>`, `BGPID <ip>`, `PREFIX "<cidr>"`, `NLRI "<cidr>"`, `NEXTHOP <ip>`.
  - Wire behavior: TCP port 179. Defaults to BGP OPEN message with ASN 65001 and Hold Time 180s.
- [examples/l3/rip/](examples/l3/rip/) — **`RIP` (Routing Information Protocol - RFC 2453 / RFC 2080):**
  - Sub-keywords: `REQUEST`, `REPLY`, `COMMAND <u8>`, `VERSION <u8>`, `METRIC <u32>`, `TAG <u16>`, `PREFIX "<cidr>"`.
  - Wire behavior: UDP port 520 (RIPv2) or 521 (RIPng). Emits Route Table Response.
- [examples/l3/vrrp/](examples/l3/vrrp/) — **`VRRP` (Virtual Router Redundancy Protocol - RFC 5798):**
  - Sub-keywords: `VRID <u8>`, `PRIORITY <u8>`, `ADV_INT <u8>`, `VIP <ip>`, `VERSION <u8>`.
  - Wire behavior: IP protocol 112 to `224.0.0.18` / `ff02::12`. Defaults to VRID 1, Priority 100.
- [examples/l3/hsrp/](examples/l3/hsrp/) — **`HSRP` (Cisco Hot Standby Router Protocol - RFC 2281):**
  - Sub-keywords: `GROUP <u8>`, `PRIORITY <u8>`, `HELLOTIME <u8>`, `STATE <u8>`, `VIP <ip>`.
  - Wire behavior: UDP port 1985 to `224.0.0.2`. Defaults to Hello message, State Active, Group 1.
- [examples/l3/pim/](examples/l3/pim/) — **`PIM` (Protocol Independent Multicast - RFC 7761):**
  - Sub-keywords: `HELLO`, `JOIN_PRUNE`, `REGISTER`, `DR_PRIORITY <u32>`, `HOLDTIME <u16>`, `SOURCE <ip>`, `GROUP <ip>`, `RP <ip>`.
  - Wire behavior: IP protocol 103 to `224.0.0.13` / `ff02::d`. Defaults to Hello message.
- [examples/l3/bfd/](examples/l3/bfd/) — **`BFD` (Bidirectional Forwarding Detection - RFC 5880 / RFC 5881):**
  - Sub-keywords: `STATE <u8>`, `DIAG <u8>`, `MY_DISC <u32>`, `YOUR_DISC <u32>`, `MIN_TX <u32>`, `MIN_RX <u32>`, `MULT <u8>`.
  - Wire behavior: UDP port 3784. Single-hop control packet, State Up, Detect Mult 3, Min TX/RX 1s.
- [examples/l3/openflow/](examples/l3/openflow/) — **`OPENFLOW` (OpenFlow Switch Protocol 1.3):**
  - Sub-keywords: `HELLO`, `FEATURES_REQ`, `FEATURES_REPLY`, `PACKET_IN`, `PACKET_OUT`, `FLOW_MOD`, `ECHO_REQ`, `XID <u32>`, `DPID <u64>`, `TABLE_ID <u8>`.
  - Wire behavior: TCP port 6653. OpenFlow Version 1.3 (0x04) OFPT_HELLO, XID 1.

### 3. Layer 4 Transport Protocols (3 Protocols)

- [examples/l4/tcp/](examples/l4/tcp/) — **`TCP` (Transmission Control Protocol - RFC 793 / RFC 7323):**
  - Sub-keywords: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`, `SRCPORT <u16>`, `DSTPORT <u16>`, `SEQ <u32>`, `ACKNUM <u32>`, `WIN <u16>`, `WINDOW <u16>`, `MSS <u16>`, `WSCALE <u8>`, `SACK_PERM`, `TSVAL <u32>`, `TSECR <u32>`, `URGENT <u16>`.
  - Wire behavior: IP protocol 6, default destination port 80. Automatic 4-tuple tracking, port inheritance, and sequence number progression across requests and replies.
- [examples/l4/udp/](examples/l4/udp/) — **`UDP` (User Datagram Protocol - RFC 768):**
  - Sub-keywords: `SRCPORT <u16>`, `DSTPORT <u16>`.
  - Wire behavior: IP protocol 17, default destination port 80. Stateless transport header with automatic length and RFC 768 checksum calculation.
- [examples/l4/sctp/](examples/l4/sctp/) — **`SCTP` (Stream Control Transmission Protocol - RFC 4960):**
  - Sub-keywords: `VTAG <u32>`, `CHECKSUM <u32>`, `CHUNK <type>`, `INIT`, `INIT_ACK`, `SACK`, `HEARTBEAT`, `HEARTBEAT_ACK`, `ABORT`, `SHUTDOWN`, `COOKIE_ECHO`, `COOKIE_ACK`, `TSN <u32>`, `STREAM <u16>`, `SSN <u16>`, `PPID <u32>`.
  - Wire behavior: IP protocol 132, default destination port 80. Common header with Verification Tag and DATA chunk, verified with CRC32c checksum.

### 4. SNMP Protocols (3 Protocols)

- [examples/l7/snmp/snmpv1/](examples/l7/snmp/snmpv1/) — **`SNMP1` (Simple Network Management Protocol v1 - RFC 1157):**
  - Sub-keywords: `TRAP`, `GET`, `SET`, `RESPONSE`, `GETNEXT`, `COMMUNITY "<str>"`, `OID <oid>`, `SYSUPTIME <u32>`, `ENTERPRISE <oid>`, `AGENTIP <ipv4>`, `GENTRAP <0..6>`, `SPECTRAP <u32>`, `VARBIND`.
  - Wire behavior: UDP port 162 (Trap) / 161 (Get/Set). Emits RFC 1157 SMIv1 ASN.1 BER encoded messages.
- [examples/l7/snmp/snmpv2c/](examples/l7/snmp/snmpv2c/) — **`SNMP2` (Simple Network Management Protocol v2c - RFC 3416):**
  - Sub-keywords: `TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `COMMUNITY "<str>"`, `OID <oid>`, `SYSUPTIME <u32>`, `REQID <u32>`, `NONREPEATERS <u32>`, `MAXREPETITIONS <u32>`, `VARBIND`.
  - Wire behavior: UDP port 162 / 161. Emits RFC 3416 SMIv2 BER encoded PDUs with 64-bit counter support.
- [examples/l7/snmp/snmpv3/](examples/l7/snmp/snmpv3/) — **`SNMP3` (Simple Network Management Protocol v3 - RFC 3414):**
  - Sub-keywords: `TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `REPORT`, `USER "<str>"`, `ENGINEID "<hex>"`, `ENGINEBOOTS <u32>`, `ENGINETIME <u32>`, `CONTEXTNAME "<str>"`, `AUTH <MD5|SHA|SHA256|SHA384|SHA512> "<pass>"`, `PRIV <DES|AES> "<pass>"`, `VARBIND`.
  - Wire behavior: UDP port 161/162. Complete User-Based Security Model (USM) with authentication (MD5, SHA-1, SHA-256, SHA-384, SHA-512) and privacy encryption (DES-CBC, AES-128-CFB).
  - Variable Bindings: `VARBIND <oid> <TYPE> <value>`:
    - `NULLVAL` / `NULL`: Null ASN.1 value
    - `STRING "<text>"`: OctetString value
    - `INT <signed_i32>`: Signed 32-bit Integer (supports negative numbers, e.g. `-15`)
    - `TIMETICKS <u32>`: Hundredths of a second
    - `IPVAL <ip>`: 4-byte IPv4 or 16-byte IPv6 address per RFC 4001
    - `OIDVAL <oid>`: ASN.1 Object Identifier
    - `COUNTER32 <u32>`: Unsigned 32-bit counter
    - `GAUGE32 <u32>`: Unsigned 32-bit gauge
    - `COUNTER64 <u64>`: Unsigned 64-bit high-capacity counter

### 5. Layer 7 Network Management & Telemetry Protocols (11 Protocols)

- [examples/l7/dns/](examples/l7/dns/) — **`DNS` (Domain Name System - RFC 1035):**
  - Sub-keywords: `TXID <u16>`, `QNAME "<name>"`, `QTYPE <u16>`, `RDATA "<str>"`, `RCODE <u8>`, `ANS_TTL <u32>`.
  - Wire behavior: UDP port 53. Standard query or answer (Type 1 A, Type 28 AAAA, etc.).
- [examples/l7/mdns/](examples/l7/mdns/) — **`MDNS` (Multicast DNS - RFC 6762):**
  - Sub-keywords: Same as DNS, plus UDP port 5353 and multicast destination `224.0.0.251` / `ff02::fb`.
- [examples/l7/dhcp/](examples/l7/dhcp/) — **`DHCP` (Dynamic Host Configuration Protocol - RFC 2131 / RFC 8415):**
  - Sub-keywords: `DISCOVER`, `OFFER`, `REQUEST`, `RELEASE`, `SOLICIT`, `ADVERTISE`, `TXID <u32>`, `CIADDR <ip>`, `YIADDR <ip>`, `SIADDR <ip>`, `CHADDR <mac>`, `HOSTNAME "<str>"`, `DNS_SERVER <ip>`, `ROUTER <ip>`, `SUBNET_MASK <ip>`, `LEASE_TIME <u32>`.
  - Wire behavior: UDP port 67/68 (IPv4 BOOTP) or UDP port 546/547 (DHCPv6).
- [examples/l7/ntp/](examples/l7/ntp/) — **`NTP` (Network Time Protocol - RFC 5905):**
  - Sub-keywords: `LI <0..3>`, `VN <0..7>`, `MODE <0..7>`, `STRATUM <u8>`, `POLL <u8>`, `PRECISION <i8>`, `REFID "<str>"`, `TX_TIMESTAMP <u64>`.
  - Wire behavior: UDP port 123. Defaults to Version 4, Mode 3 (Client), Stratum 0, Poll 4.
- [examples/l7/ptp/](examples/l7/ptp/) — **`PTP` (Precision Time Protocol - IEEE 1588-2008):**
  - Sub-keywords: `MSG_TYPE <u8>`, `SYNC`, `DELAY_REQ`, `FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE`, `VERSION <u8>`, `DOMAIN <u8>`, `SEQ_ID <u16>`, `CLOCK_ID "<mac>"`.
  - Wire behavior: UDP port 319 (Event) / 320 (General). Defaults to Sync message, Domain 0.
- [examples/l7/radius/](examples/l7/radius/) — **`RADIUS` (Remote Authentication Dial-In User Service - RFC 2865):**
  - Sub-keywords: `CODE <u8>`, `ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCESS_REJECT`, `ACCESS_CHALLENGE`, `ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE`, `ID <u8>`, `USER "<str>"`, `NAS_IP <ip>`, `SERVICE_TYPE <u32>`, `FRAMED_IP <ip>`.
  - Wire behavior: UDP port 1812 (Auth) / 1813 (Acct). Defaults to Access-Request.
- [examples/l7/tacacs/](examples/l7/tacacs/) — **`TACACS` (TACACS+ Terminal Access Controller - RFC 8907):**
  - Sub-keywords: `AUTHEN`, `AUTHOR`, `ACCT`, `SESSION_ID <u32>`, `USER "<str>"`.
  - Wire behavior: TCP port 49. Defaults to Authentication Start, Session ID 0x12345678.
- [examples/l7/syslog/](examples/l7/syslog/) — **`SYSLOG` (The Syslog Protocol - RFC 5424):**
  - Sub-keywords: `PRI <u16>`, `FACILITY <u8>`, `SEVERITY <u8>`, `HOSTNAME "<str>"`, `APP "<str>"`, `PROCID "<str>"`, `MSGID "<str>"`, `MSG "<text>"`.
  - Wire behavior: UDP port 514. Defaults to PRI `<14>` (User.Info), App `"frameassembly"`.
- [examples/l7/netflow/](examples/l7/netflow/) — **`NETFLOW` (Cisco NetFlow Flow Export):**
  - Sub-keywords: `VERSION <u16>`, `UPTIME <u32>`, `SRCIP <ip>`, `DSTIP <ip>`, `NEXTHOP <ip>`, `SRCPORT <u16>`, `DSTPORT <u16>`, `PACKETS <u32>`, `OCTETS <u32>`, `PROTO <u8>`, `TOS <u8>`.
  - Wire behavior: UDP port 2055. Defaults to NetFlow v5 export packet.
- [examples/l7/ipfix/](examples/l7/ipfix/) — **`IPFIX` (IP Flow Information Export - RFC 7011):**
  - Sub-keywords: `DOMAIN_ID <u32>`, `SRCIP <ip>`, `DSTIP <ip>`, `PACKETS <u64>`, `OCTETS <u64>`, `PROTO <u8>`.
  - Wire behavior: UDP port 4739. Emits RFC 7011 Flow Data Record.
- [examples/l7/sflow/](examples/l7/sflow/) — **`SFLOW` (sFlow Traffic Monitoring - RFC 3176):**
  - Sub-keywords: `VERSION <u32>`, `AGENT_IP <ip>`, `SUB_AGENT_ID <u32>`, `SEQ_NUM <u32>`, `UPTIME <u32>`, `SAMPLES <u32>`.
  - Wire behavior: UDP port 6343. Emits sFlow Version 5 Flow Sample datagram.

### 6. Layer 7 Web, App, Storage, Mail & Messaging Protocols (30 Protocols)

- [examples/l7/tftp/](examples/l7/tftp/) — **`TFTP` (Trivial File Transfer Protocol - RFC 1350):** UDP port 69 (`RRQ`, `WRQ`, `FILENAME "<str>"`, `MODE "<str>"`, `BLOCK <u16>`, `ERRCODE <u16>`, `ERRMSG "<str>"`).
- [examples/l7/ftp/](examples/l7/ftp/) — **`FTP` (File Transfer Protocol - RFC 959):** TCP port 21 (`CMD "<str>"`, `ARG "<str>"`, `BANNER "<str>"`, `USER "<str>"`).
- [examples/l7/ssh/](examples/l7/ssh/) — **`SSH` (Secure Shell Protocol - RFC 4253):** TCP port 22 (`BANNER "<str>"`, `KEXINIT`, `NEWKEYS`, `MSG_CODE <u8>`).
- [examples/l7/telnet/](examples/l7/telnet/) — **`TELNET` (Telnet Protocol - RFC 854):** TCP port 23 (`WILL`, `WONT`, `DO`, `DONT`, `OPTION <u8>`, `CMD <u8>`).
- [examples/l7/http/](examples/l7/http/) — **`HTTP` (Hypertext Transfer Protocol 1.1 - RFC 7230):** TCP port 80 (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `URI "<str>"`, `HOST_HDR "<str>"`, `USER_AGENT "<str>"`, `CONTENT_TYPE "<str>"`, `STATUS <u16>`, `REASON "<str>"`, `HEADER "<k>" "<v>"`, `BODY "<str>"`).
- [examples/l7/http2/](examples/l7/http2/) — **`HTTP2` (Hypertext Transfer Protocol Version 2 - RFC 7540):** TCP port 443 (`PREFACE`, `SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`, `PING`, `GOAWAY`, `STREAM_ID <u32>`).
- [examples/l7/grpc/](examples/l7/grpc/) — **`GRPC` (gRPC over HTTP/2):** TCP port 50051 (`SERVICE "<str>"`, `METHOD "<str>"`, `GRPC_STATUS <u32>`, `PAYLOAD "<str>"`).
- [examples/l7/websocket/](examples/l7/websocket/) — **`WEBSOCKET` (The WebSocket Protocol - RFC 6455):** TCP port 80 (`OPCODE <u8>`, `TEXT`, `BINARY`, `PING`, `PONG`, `CLOSE`, `FIN_BIT <0..1>`, `MASK_KEY <u32>`, `PAYLOAD "<str>"`).
- [examples/l7/tls/](examples/l7/tls/) — **`TLS` (Transport Layer Security 1.3 - RFC 8446):** TCP port 443 (`CLIENT_HELLO`, `SERVER_HELLO`, `CERTIFICATE`, `FINISHED`, `APP_DATA`, `ALERT`, `RECORD_VERSION <u16>`, `HANDSHAKE_VERSION <u16>`, `SNI "<str>"`, `CIPHERSUITE <u16>`, `ALPN "<str>"`).
- [examples/l7/quic/](examples/l7/quic/) — **`QUIC` (QUIC Transport Protocol - RFC 9000):** UDP port 443 (`INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`, `SHORT`, `VERSION <u32>`, `DCID "<hex>"`, `SCID "<hex>"`, `TOKEN "<hex>"`, `PKT_NUM <u32>`, `PAYLOAD "<str>"`).
- [examples/l7/stun/](examples/l7/stun/) — **`STUN` (Session Traversal Utilities for NAT - RFC 8489):** UDP port 3478 (`BINDING_REQUEST`, `BINDING_RESPONSE`, `BINDING_ERROR`, `TXID "<hex>"`, `XOR_MAPPED_ADDR <ip> <port>`, `SOFTWARE "<str>"`).
- [examples/l7/sip/](examples/l7/sip/) — **`SIP` (Session Initiation Protocol - RFC 3261):** UDP/TCP port 5060 (`INVITE`, `ACK`, `BYE`, `CANCEL`, `REGISTER`, `OPTIONS`, `URI "<str>"`, `FROM "<str>"`, `TO "<str>"`, `CALL_ID "<str>"`, `CSEQ <u32>`, `VIA "<str>"`, `CONTACT "<str>"`).
- [examples/l7/rtp/](examples/l7/rtp/) — **`RTP` (Real-Time Transport Protocol - RFC 3550):** UDP port 5004 (`PT <u8>`, `SEQ <u16>`, `TIMESTAMP <u32>`, `SSRC <u32>`, `MARKER <0..1>`, `PAYLOAD "<str>"`).
- [examples/l7/rtsp/](examples/l7/rtsp/) — **`RTSP` (Real Time Streaming Protocol - RFC 2326):** TCP port 554 (`DESCRIBE`, `SETUP`, `PLAY`, `TEARDOWN`, `OPTIONS`, `URI "<str>"`, `CSEQ <u32>`, `SESSION "<str>"`, `TRANSPORT_HDR "<str>"`).
- [examples/l7/smtp/](examples/l7/smtp/) — **`SMTP` (Simple Mail Transfer Protocol - RFC 5321):** TCP port 25 (`EHLO "<domain>"`, `HELO "<domain>"`, `MAIL_FROM "<addr>"`, `RCPT_TO "<addr>"`, `DATA`, `QUIT`, `STATUS <u16>`, `MSG "<str>"`).
- [examples/l7/imap/](examples/l7/imap/) — **`IMAP` (Internet Message Access Protocol - RFC 3501):** TCP port 143 (`TAG "<str>"`, `CMD "<str>"`, `PARAM "<str>"`, `OK`, `ERR`).
- [examples/l7/pop3/](examples/l7/pop3/) — **`POP3` (Post Office Protocol Version 3 - RFC 1939):** TCP port 110 (`CMD "<str>"`, `ARG "<str>"`, `OK`, `ERR`, `USER "<str>"`).
- [examples/l7/kerberos/](examples/l7/kerberos/) — **`KERBEROS` (Kerberos Network Authentication - RFC 4120):** UDP/TCP port 88 (`AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`, `KRB_ERROR`, `REALM "<str>"`, `CNAME "<str>"`, `SNAME "<str>"`, `ETYPE <u32>`).
- [examples/l7/ldap/](examples/l7/ldap/) — **`LDAP` (Lightweight Directory Access Protocol - RFC 4511):** TCP port 389 (`MSGID <u32>`, `BIND_REQ`, `BIND_RES`, `SEARCH_REQ`, `SEARCH_ENTRY`, `SEARCH_DONE`, `UNBIND_REQ`, `VERSION <u8>`, `USER "<str>"`, `BASE_DN "<str>"`, `FILTER "<str>"`, `RESULT_CODE <u32>`).
- [examples/l7/smb/](examples/l7/smb/) — **`SMB` (Server Message Block 2/3 - MS-SMB2):** TCP port 445 (`NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`, `TREE_DISCONNECT`, `SESSION_ID <u64>`, `TREE_ID <u32>`, `SHARE "<str>"`, `STATUS <u32>`).
- [examples/l7/nfs/](examples/l7/nfs/) — **`NFS` (Network File System v3/v4 - RFC 1813 / RFC 7530):** TCP port 2049 (`VERS <u32>`, `PROC <u32>`, `PATH "<str>"`, `COMPOUND`, `STATUS <u32>`).
- [examples/l7/redis/](examples/l7/redis/) — **`REDIS` (Redis Serialization Protocol RESP):** TCP port 6379 (`CMD "<str>"`, `ARGS "<str>"`, `REPLY_TYPE "<str>"`, `VALUE "<str>"`).
- [examples/l7/memcached/](examples/l7/memcached/) — **`MEMCACHED` (Memcached Text/Binary Protocol):** TCP port 11211 (`CMD "<str>"`, `KEY "<str>"`, `VALUE "<str>"`, `FLAGS <u32>`, `EXPTIME <u32>`, `OPAQUE <u32>`, `CAS <u64>`).
- [examples/l7/mysql/](examples/l7/mysql/) — **`MYSQL` (MySQL Client/Server Protocol):** TCP port 3306 (`GREETING`, `LOGIN`, `SQL "<query>"`, `OK`, `ERR`, `EOF`, `SERVER_VERSION "<str>"`, `USER "<str>"`, `DB "<str>"`).
- [examples/l7/postgres/](examples/l7/postgres/) — **`POSTGRES` (PostgreSQL Frontend/Backend Protocol 3.0):** TCP port 5432 (`STARTUP`, `SQL "<query>"`, `READY_FOR_QUERY`, `COMMAND_COMPLETE`, `ERROR_RESPONSE`, `AUTH_OK`, `USER "<str>"`, `DB "<str>"`).
- [examples/l7/mqtt/](examples/l7/mqtt/) — **`MQTT` (Message Queuing Telemetry Transport 3.1.1/5.0):** TCP port 1883 (`CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`, `SUBSCRIBE`, `SUBACK`, `PINGREQ`, `PINGRESP`, `DISCONNECT`, `CLIENT_ID "<str>"`, `TOPIC "<str>"`, `QOS <0..2>`, `RETAIN <0..1>`, `PKT_ID <u16>`, `PAYLOAD "<str>"`).
- [examples/l7/coap/](examples/l7/coap/) — **`COAP` (Constrained Application Protocol - RFC 7252):** UDP port 5683 (`CON`, `NON`, `ACK`, `RST`, `CODE <u8>`, `GET`, `POST`, `PUT`, `DELETE`, `MSGID <u16>`, `TOKEN "<hex>"`, `URI_PATH "<str>"`, `CONTENT_FORMAT <u16>`).
- [examples/l7/amqp/](examples/l7/amqp/) — **`AMQP` (Advanced Message Queuing Protocol 0-9-1 / 1.0):** TCP port 5672 (`PROTOCOL_HEADER`, `CONNECTION_START`, `CHANNEL_OPEN`, `BASIC_PUBLISH`, `BASIC_DELIVER`, `CHANNEL <u16>`, `ROUTING_KEY "<str>"`).
- [examples/l7/ssdp/](examples/l7/ssdp/) — **`SSDP` (Simple Service Discovery Protocol - UPnP):** UDP port 1900 to `239.255.255.250` (`MSEARCH`, `NOTIFY`, `MAN "<str>"`, `MX <u8>`, `ST "<str>"`, `NT "<str>"`, `NTS "<str>"`, `USN "<str>"`, `LOCATION "<str>"`).
- [examples/l7/whois/](examples/l7/whois/) — **`WHOIS` (WHOIS Protocol - RFC 3912):** TCP port 43 (`QUERY "<domain>"`, `REGISTRAR "<str>"`).

### 7. Layer 7 Industrial & Operational Technology (SCADA/OT) Protocols (6 Protocols)

- [examples/l7/modbus/](examples/l7/modbus/) — **`MODBUS` (Modbus TCP Industrial Automation Protocol):**
  - Sub-keywords: `PROTO_ID <u16>`, `UNITID <u8>`, `FUNC <u8>`, `READ_COILS`, `READ_DISCRETE_INPUTS`, `READ_HOLDING_REGISTERS`, `READ_INPUT_REGISTERS`, `WRITE_SINGLE_COIL`, `WRITE_SINGLE_REGISTER`, `WRITE_MULTIPLE_REGISTERS`, `ADDR <u16>`, `COUNT <u16>`, `DATA "<hex>"`, `IS_RESPONSE`.
  - Wire behavior: TCP port 502. Emits 7-byte MBAP header and Modbus PDU. Defaults to Read Holding Registers (Func 3).
- [examples/l7/bacnet/](examples/l7/bacnet/) — **`BACNET` (Building Automation and Control Networks - ANSI/ASHRAE 135):**
  - Sub-keywords: `WHO_IS`, `I_AM`, `READ_PROPERTY`, `WRITE_PROPERTY`, `INVOKE_ID <u8>`, `OBJECT_TYPE <u16>`, `OBJECT_INSTANCE <u32>`, `PROPERTY_ID <u32>`.
  - Wire behavior: UDP port 47808 (BACnet/IP BVLC Type 0x81). Defaults to BVLC Original-Broadcast with Unconfirmed Who-Is request.
- [examples/l7/dnp3/](examples/l7/dnp3/) — **`DNP3` (Distributed Network Protocol for Utilities - IEEE 1815):**
  - Sub-keywords: `FUNC <u8>`, `CONFIRM`, `READ`, `WRITE`, `SELECT`, `OPERATE`, `DIRECT_OPERATE`, `UNSOLICITED_RESPONSE`, `VARIATION <u8>`, `CRC <u16>`, `SRC <u16>`, `DST <u16>`.
  - Wire behavior: TCP/UDP port 20000. Emits DNP3 0x0564 sync byte frame, Data Link header with CRC, and Transport/Application layers.
- [examples/l7/s7comm/](examples/l7/s7comm/) — **`S7COMM` (Siemens S7 Industrial PLC Communication):**
  - Sub-keywords: `ROSCTR <u8>`, `PDU_REF <u16>`, `SETUP_COMM`, `READ_VAR`, `WRITE_VAR`, `PLC_CONTROL`, `AREA <u8>`, `DB_NUM <u16>`, `OFFSET <u32>`, `COUNT <u16>`.
  - Wire behavior: TCP port 102. Encapsulates TPKT (RFC 1006) + ISO COTP Connection Request + S7 Setup Communication PDU.
- [examples/l7/ethernetip/](examples/l7/ethernetip/) — **`ETHERNETIP` (EtherNet/IP & Common Industrial Protocol CIP):**
  - Sub-keywords: `LIST_SERVICES`, `LIST_IDENTITY`, `LIST_INTERFACES`, `REGISTER_SESSION`, `UNREGISTER_SESSION`, `SEND_RR_DATA`, `SEND_UNIT_DATA`, `SESSION_HANDLE <u32>`, `STATUS <u32>`, `CONTEXT "<hex>"`, `CIP_SERVICE <u8>`, `CIP_CLASS <u16>`, `CIP_INSTANCE <u16>`, `CIP_ATTR <u16>`, `DATA "<hex>"`.
  - Wire behavior: TCP/UDP port 44818. Emits 24-byte Encapsulation header with Register Session (0x0065) or Send RR Data.
- [examples/l7/opcua/](examples/l7/opcua/) — **`OPCUA` (OPC Unified Architecture - IEC 62541):**
  - Sub-keywords: `CHUNK_TYPE "<c>"`, `SECURE_CHANNEL_ID <u32>`, `TOKEN_ID <u32>`, `SEQ_NUM <u32>`, `ENDPOINT_URL "<str>"`, `NODE_ID "<str>"`, `PAYLOAD "<str>"`.
  - Wire behavior: TCP port 4840. Emits Hello message (`HEL` chunk 'F') with client buffer parameters and Endpoint URL.

---

## Examples Corpus Directory Index

The `examples/` directory contains an exhaustive suite of validated `.fasm` scripts:

- **Layer 2 Data-Link (`examples/l2/`):**
  - [`examples/l2/arp/`](examples/l2/arp/) — ARP request, reply, gratuitous ARP (GARP)
  - [`examples/l2/vlan/`](examples/l2/vlan/) — 802.1Q single-tagged traffic with PCP/DEI priorities
  - [`examples/l2/qinq/`](examples/l2/qinq/) — 802.1ad dual-tagged QinQ service provider tunnels
  - [`examples/l2/lldp/`](examples/l2/lldp/) — LLDP chassis, port, system description discovery
  - [`examples/l2/stp/`](examples/l2/stp/) — STP configuration and RSTP rapid topology change BPDUs
  - [`examples/l2/lacp/`](examples/l2/lacp/) — LACP actor and partner bundle negotiation
  - [`examples/l2/eapol/`](examples/l2/eapol/) — 802.1X EAPOL-Start, Identity, and key exchange
  - [`examples/l2/mpls/`](examples/l2/mpls/) — MPLS single and multi-label shim encapsulation
- **Layer 3 Routing & Tunneling (`examples/l3/`):**
  - [`examples/l3/icmp/`](examples/l3/icmp/) — Dual-stack ICMPv4/ICMPv6 echo and error flows
  - [`examples/l3/ndp/`](examples/l3/ndp/) — IPv6 Router and Neighbor Solicitations & Advertisements
  - [`examples/l3/igmp/`](examples/l3/igmp/) — IGMPv2/v3 membership queries and host reports
  - [`examples/l3/mld/`](examples/l3/mld/) — MLDv1/v2 IPv6 multicast listener discovery
  - [`examples/l3/gre/`](examples/l3/gre/) — GRE point-to-point tunnels with checksums and keys
  - [`examples/l3/vxlan/`](examples/l3/vxlan/) — VXLAN overlay encapsulation across VNI boundaries
  - [`examples/l3/geneve/`](examples/l3/geneve/) — GENEVE virtualization with variable TLV options
  - [`examples/l3/ipsec/`](examples/l3/ipsec/) / [`examples/l3/esp/`](examples/l3/esp/) / [`examples/l3/ah/`](examples/l3/ah/) — IPsec security associations
  - [`examples/l3/ikev2/`](examples/l3/ikev2/) — IKEv2 SA_INIT and CHILD_SA negotiations
  - [`examples/l3/wireguard/`](examples/l3/wireguard/) — WireGuard handshake initiation and transport
  - [`examples/l3/ospf/`](examples/l3/ospf/) — OSPFv2/v3 adjacency establishment and DBD exchange
  - [`examples/l3/bgp/`](examples/l3/bgp/) — BGP-4 OPEN, UPDATE, and KEEPALIVE peering
  - [`examples/l3/rip/`](examples/l3/rip/) — RIPv2 and RIPng metric advertisement
  - [`examples/l3/vrrp/`](examples/l3/vrrp/) / [`examples/l3/hsrp/`](examples/l3/hsrp/) — First-hop gateway redundancy failover
  - [`examples/l3/pim/`](examples/l3/pim/) — PIM-SM multicast router hello and join/prune trees
  - [`examples/l3/bfd/`](examples/l3/bfd/) — High-frequency sub-second link failure detection
  - [`examples/l3/openflow/`](examples/l3/openflow/) — SDN controller flow table modification
- **Layer 4 Transports (`examples/l4/`):**
  - [`examples/l4/tcp/`](examples/l4/tcp/) — 3-way handshakes, options, window scaling, teardowns
  - [`examples/l4/udp/`](examples/l4/udp/) — High-speed UDP streaming and empty probe probes
  - [`examples/l4/sctp/`](examples/l4/sctp/) — SCTP 4-way association, data chunks, and multi-homing
- **Layer 7 SNMP (`examples/l7/snmp/`):**
  - [`examples/l7/snmp/snmpv1/`](examples/l7/snmp/snmpv1/) — SNMPv1 traps, coldStart, warmStart, linkUp/Down
  - [`examples/l7/snmp/snmpv2c/`](examples/l7/snmp/snmpv2c/) — GET, GETNEXT, GETBULK walks and 64-bit varbinds
  - [`examples/l7/snmp/snmpv3/`](examples/l7/snmp/snmpv3/) — USM authentication (MD5/SHA/SHA-2) and privacy (DES/AES)
- **Layer 7 Telemetry, Web & Industrial (`examples/l7/`):**
  - Telemetry & Infra: [`dns/`](examples/l7/dns/), [`mdns/`](examples/l7/mdns/), [`dhcp/`](examples/l7/dhcp/), [`ntp/`](examples/l7/ntp/), [`ptp/`](examples/l7/ptp/), [`radius/`](examples/l7/radius/), [`tacacs/`](examples/l7/tacacs/), [`syslog/`](examples/l7/syslog/), [`netflow/`](examples/l7/netflow/), [`ipfix/`](examples/l7/ipfix/), [`sflow/`](examples/l7/sflow/)
  - Web & App: [`http/`](examples/l7/http/), [`http2/`](examples/l7/http2/), [`grpc/`](examples/l7/grpc/), [`websocket/`](examples/l7/websocket/), [`tls/`](examples/l7/tls/), [`quic/`](examples/l7/quic/), [`stun/`](examples/l7/stun/), [`sip/`](examples/l7/sip/), [`rtp/`](examples/l7/rtp/), [`rtsp/`](examples/l7/rtsp/), [`smtp/`](examples/l7/smtp/), [`imap/`](examples/l7/imap/), [`pop3/`](examples/l7/pop3/), [`kerberos/`](examples/l7/kerberos/), [`ldap/`](examples/l7/ldap/), [`smb/`](examples/l7/smb/), [`nfs/`](examples/l7/nfs/), [`redis/`](examples/l7/redis/), [`memcached/`](examples/l7/memcached/), [`mysql/`](examples/l7/mysql/), [`postgres/`](examples/l7/postgres/), [`mqtt/`](examples/l7/mqtt/), [`coap/`](examples/l7/coap/), [`amqp/`](examples/l7/amqp/), [`ssdp/`](examples/l7/ssdp/), [`whois/`](examples/l7/whois/), [`tftp/`](examples/l7/tftp/), [`ftp/`](examples/l7/ftp/), [`ssh/`](examples/l7/ssh/), [`telnet/`](examples/l7/telnet/)
  - SCADA & OT: [`modbus/`](examples/l7/modbus/), [`bacnet/`](examples/l7/bacnet/), [`dnp3/`](examples/l7/dnp3/), [`s7comm/`](examples/l7/s7comm/), [`ethernetip/`](examples/l7/ethernetip/), [`opcua/`](examples/l7/opcua/)
- **Cross-Cutting Topologies (`examples/topologies/`):**
  - [`examples/topologies/`](examples/topologies/) — Spine-leaf enterprise topologies, DMZ firewall alerts, DNS amplification defense, VoIP QoS prioritization, Kubernetes service mesh simulations, and grand omnibus showcases.

---

## Complete Realistic Example

```frameassembly
// PROMPT: Dual-stack HTTP and DNS monitoring scenario with QoS tagging.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, PSH, PAYLOAD, UDP, DSTPORT, DSCP, FLOWLABEL, COMPILE

HOST client_v4 { IP 192.168.1.50 }
HOST server_v4 { IP 192.168.1.1 }

HOST client_v6 { IP 2001:db8::50 }
HOST server_v6 { IP 2001:db8::1 }

FLOW web_request(client, server) {
    client -> server TCP SYN WIN 65535 DSCP 46
    client <- server TCP SYN ACK WIN 65535 DSCP 46
    client -> server TCP ACK DSCP 46
    client -> server TCP PSH ACK PAYLOAD "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
}

FLOW dns_lookup(client, resolver) {
    client -> resolver UDP DSTPORT 53 FLOWLABEL 1000 PAYLOAD "DNS_QUERY_EXAMPLE"
    client <- resolver UDP FLOWLABEL 1000 PAYLOAD "DNS_RESPONSE_EXAMPLE"
}

COMPILE {
    // Run IPv4 web session
    web_request(client_v4, server_v4)
    // Run IPv6 web session using the same polymorphic flow!
    web_request(client_v6, server_v6)
    // Run IPv6 DNS query
    dns_lookup(client_v6, server_v6)
}
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
