# FrameAssembly (`frameassembly`)

[![Crates.io](https://img.shields.io/crates/v/frameassembly.svg)](https://crates.io/crates/frameassembly)
[![Docs.rs](https://docs.rs/frameassembly/badge.svg)](https://docs.rs/frameassembly)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B%20(Edition%202024)-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[**30-Second Quickstart**](#30-second-quickstart) • [**Why FrameAssembly?**](#why-frameassembly) • [**Language Syntax Guide**](#language-syntax-guide) • [**Rust Library API**](#rust-library-api-quickstart) • [**All 81 Protocols**](#canonical-rfc-wire-defaults-table) • [**Examples Corpus (`2,611`)**](#examples-corpus-directory-index) • [**Architecture & Docs**](#technical-documentation--compiler-architecture)

**FrameAssembly** (`frameassembly` v1.2.1) is a declarative network packet crafting Domain-Specific Language (DSL) and optimizing Rust compiler that compiles human-readable `.fasm` traffic specifications into deterministic, nanosecond-accurate `.pcap` and `.pcapng` packet captures across **81 native Layer 2 through Layer 7 protocols**. Built as a fast, rootless **Scapy and `text2pcap` alternative in Rust**, FrameAssembly generates reproducible packet captures for **Wireshark / `tshark` dissector testing**, **Suricata / Zeek / Snort IDS rule validation**, **firewall & DPI verification**, **industrial SCADA/OT security testing**, and **deterministic CI/CD packet capture fixtures**—with zero root privileges, raw sockets, or manual byte-offset math.

---

## 30-Second Quickstart

### 1. Install `frameassembly`

**One-Line Cross-Platform Bootstrap (`install.sh` — Zero Repo Clone Required):**
Installs missing system prerequisites (`curl`, `ca-certificates`, C linker), ensures Rust `>= 1.85` via [rustup.rs](https://rustup.rs/), installs `frameassembly` from Crates.io, and installs the VS Code / Antigravity `.fasm` syntax extension if `code` or `agy` is on `PATH`:

```bash
curl -fsSL https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/install.sh | sh
```

**Or install directly via Cargo (Rust `>= 1.85`):**

```bash
cargo install frameassembly
```

### 2. Write a Declarative Packet Specification (`demo.fasm`)

Every protocol in FrameAssembly works out-of-the-box with smart RFC wire defaults, while allowing explicit overrides for ports, flags, headers, and nanosecond delays:

```frameassembly
// PROMPT: Three-way TCP handshake followed by an HTTP/1.1 GET request and 200 OK response
// TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, SRCPORT, DSTPORT, WIN, MSS, WAIT, ACK, HTTP, GET, URI, HOST_HDR, STATUS, REASON, BODY, COMPILE

// INSTRUCTION: Declare the client and web server IPv4 endpoints
HOST client { IP 10.0.0.10 MAC 00:11:22:33:44:55 }
HOST server { IP 10.0.0.80 MAC aa:bb:cc:dd:ee:ff }

// INSTRUCTION: Define a stateful TCP 3-way handshake and HTTP/1.1 transaction
FLOW web_session(c, s) {
    c -> s TCP SYN SRCPORT 51234 DSTPORT 80 WIN 65535 MSS 1460 WAIT 1ms
    c <- s TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
    c -> s TCP ACK WAIT 1ms
    c -> s HTTP GET URI "/index.html" HOST_HDR "example.com" WAIT 5ms
    c <- s HTTP STATUS 200 REASON "OK" BODY "<h1>Hello</h1>" WAIT 2ms
}

// INSTRUCTION: Compile the flow into the output PCAPNG capture
COMPILE {
    web_session(client, server)
}
```

### 3. Compile to `.pcap` & Inspect with `tshark` / Wireshark

```console
$ frameassembly demo.fasm -o output.pcap
Successfully parsed 2 hosts, 1 flows
Starting PCAP compilation...
Successfully generated output.pcap

$ tshark -r output.pcap
    1 0.000000000    10.0.0.10 → 10.0.0.80    TCP 58 51234 → 80 [SYN] Seq=0 Win=65535 Len=0 MSS=1460
    2 0.001000000    10.0.0.80 → 10.0.0.10    TCP 58 80 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460
    3 0.002000000    10.0.0.10 → 10.0.0.80    TCP 54 51234 → 80 [ACK] Seq=1 Ack=1 Win=65535 Len=0
    4 0.003000000    10.0.0.10 → 10.0.0.80    HTTP 97 GET /index.html HTTP/1.1
    5 0.008000000    10.0.0.80 → 10.0.0.10    HTTP 126 HTTP/1.1 200 OK  (text/html)
```

Notice what the compiler handled automatically:
- **Bidirectional Port Inheritance**: `51234 -> 80` on `c -> s` automatically reversed to `80 -> 51234` on `c <- s` without retyping `SRCPORT` or `DSTPORT`.
- **Stateful 4-Tuple TCP `SEQ`/`ACK` Tracking**: The `HTTP GET` and `200 OK` frames automatically inherited the established TCP connection (`51234 <-> 80`), emitted `PSH, ACK` segments, and advanced `Seq` and `Ack` counters by exact payload byte lengths.
- **RFC Checksums & Nanosecond Timestamps**: All IPv4 header checksums, TCP pseudo-header checksums, Ethernet framing, and PCAPNG nanosecond `WAIT` offsets (`0.001s`, `0.002s`, `0.003s`, `0.008s`) were synthesized deterministically.

---

## Why FrameAssembly?

| Capability | FrameAssembly (`.fasm`) | Python Scapy | `text2pcap` / Raw Hex | Live Generators (`pktgen` / `tcpreplay`) |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Interface** | Declarative `.fasm` DSL + Rust Library & CLI | Imperative Python scripts | Manual hex dumps | Live NIC / kernel socket injection |
| **Root / `CAP_NET_RAW` Required?** | **Never** (pure userspace compiler) | Often required for sniffing/sending | No | **Yes** (requires root & NICs) |
| **Stateful 4-Tuple TCP `SEQ`/`ACK`?** | **Automatic** across raw `TCP` & L7 flows | Manual (`seq`/`ack` math per packet) | Manual hex editing | Hardware/template dependent |
| **Dual-Stack IPv4 / IPv6 Reuse?** | **Polymorphic** (1 `FLOW` runs on IPv4 & IPv6) | Separate `IP()` vs `IPv6()` scripts | Complete hex rewrite | Separate templates |
| **Native Protocol Coverage** | **81 L2–L7 protocols** with 0-keyword defaults | Broad, but verbose layer stacking | None (user encodes bytes) | Limited to pre-captured PCAPs |
| **SNMPv3 USM Crypto (RFC 3414/7860)** | **Built-in** (`MD5`/`SHA`/`SHA-2` + `DES`/`AES`) | Complex external crypto setup | Impossible by hand | Static replay only |
| **Bit-Exact CI Determinism** | **100% deterministic** (nanosecond PCAPNG) | Ephemeral ports/timestamps vary | Deterministic but brittle | Kernel jitter & NIC offload variance |

### Key Features

- **81 Native Network Protocols:** Complete, zero-dependency packet crafting across Layer 2, Layer 3, Layer 4, and Layer 7 protocols with smart RFC-compliant wire defaults and field overrides.
- **Polymorphic Dual-Stack IPv4 & IPv6 Flows:** Write a `FLOW` once and invoke it over IPv4 or IPv6 host pairs in `COMPILE`. Automatic RFC 2464 (`33:33:xx:xx:xx:xx`) and RFC 1112 (`01:00:5e:xx:xx:xx`) multicast MAC derivation.
- **Comprehensive L2–L4 Modifiers:** Full control over 802.1Q `VLAN`, 802.1ad `QINQ`, `MPLS` label stacks, IPv4/IPv6 `TTL`, `DSCP`, `ECN`, 20-bit `FLOWLABEL`, IPv4 fragmentation (`IPID`, `DF`, `MF`, `FRAGOFFSET`), TCP options (`MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`), and `SCTP` multi-chunk bundling.
- **Cryptographic SNMPv3 USM Engine:** Complete RFC 3414 / RFC 3826 / RFC 7860 implementation supporting `MD5`, `SHA`, `SHA256`, `SHA384`, `SHA512` authentication and `DES` / `AES` privacy encryption across all 9 SMI `VARBIND` types.
- **AI & Constrained Decoding Ready:** Ships with 5-way synchronized formal grammars ([`grammar.ebnf`](grammar.ebnf), [`frameassembly.gbnf`](frameassembly.gbnf), [`frameassembly.lark`](frameassembly.lark), TextMate), [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt), and **`2,611` verified `.fasm` scenarios**.

---

## Language Syntax Guide

### 1. Host, Flow & Compile Declarations
FrameAssembly (`.fasm`) syntax is completely **case-insensitive** across all keywords, protocols, modifiers, time units, and identifiers (`host` or `HOST`, `tcp` or `TCP`). A program consists of `host` endpoint definitions, parameterized `flow` blocks (`->` and `<-`), and a `compile` block supporting polymorphic dual-stack invocation and `loop` bursts:

```frameassembly
// PROMPT: Dual-stack TCP 3-way handshake and mDNS multicast query demonstrating HOST, FLOW, and COMPILE LOOP syntax.
// TOKENS: HOST, IP, MAC, FLOW, ->, <-, TCP, SYN, ACK, WIN, MDNS, QUERY, QNAME, QTYPE, WAIT, COMPILE, LOOP

// INSTRUCTION: Define IPv4 and IPv6 unicast and multicast endpoints.
host client_v4  { ip 192.168.1.50 }
host server_v4  { ip 192.168.1.100 mac 00:11:22:33:44:55 }
host client_v6  { ip 2001:db8::10 }
host server_v6  { ip 2001:db8::100 }
host mdns_mcast { ip 224.0.0.251 }

// INSTRUCTION: Define a polymorphic TCP 3-way handshake flow reusable across IPv4 and IPv6.
flow tcp_handshake(client, server) {
    client -> server tcp syn win 65535
    client <- server tcp syn ack win 65535 wait 1ms
    client -> server tcp ack wait 1ms
}

// INSTRUCTION: Define an mDNS multicast service discovery flow.
flow mdns_probe(host, mcast) {
    host -> mcast mdns query qname "_http._tcp.local" qtype "PTR" wait 2ms
}

// INSTRUCTION: Compile 2 dual-stack TCP handshake iterations followed by an mDNS multicast probe.
compile {
    loop 2 {
        tcp_handshake(client_v4, server_v4)
        tcp_handshake(client_v6, server_v6)
    }
    mdns_probe(client_v4, mdns_mcast)
}
```

- `A -> B`: `A` is the transmitter (source), `B` is the receiver (destination).
- `A <- B`: `B` is the transmitter (source), `A` is the receiver (destination).
- **Two-Stage Port Inheritance:** If subsequent statements omit `SRCPORT` or `DSTPORT`, ports are automatically remembered and swapped across reversed arrows.

### 2. Layer 2–L4 Frame Modifiers

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

---

## Rust Library API Quickstart

Embed `frameassembly` directly inside Rust unit and integration test suites to synthesize wire-valid Ethernet frames (`Vec<(Vec<u8>, u64)>`) in memory or write `.pcap` files to disk:

```rust
use frameassembly::parser::parse_program;
use frameassembly::backend::{compile_program, generate_pcap};

let fasm = r#"
    HOST sensor { IP 192.168.10.5 MAC 00:1a:2b:3c:4d:5e }
    HOST plc    { IP 192.168.10.20 MAC 00:1a:2b:3c:4d:5f }

    FLOW modbus_poll(c, s) {
        c -> s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS ADDR 100 COUNT 4 WAIT 5ms
        c <- s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS IS_RESPONSE VALUE 42 WAIT 5ms
    }

    COMPILE { modbus_poll(sensor, plc) }
"#;

let program = parse_program(fasm).expect("valid .fasm specification");
let frames = compile_program(&program).expect("wire synthesis succeeds");
assert_eq!(frames.len(), 2);
assert_eq!(frames[1].1, 5_000_000); // 5ms in nanoseconds
```

### CLI & Editor Options

```bash
# Default output to output.pcap, or specify -o / --output
frameassembly demo.fasm -o output.pcap

# Install only the VS Code / Antigravity .vsix syntax extension without cloning:
curl -fsSLo /tmp/frameassembly.vsix https://raw.githubusercontent.com/SteveWinschel/FrameAssembly/main/frameassembly-vscode/frameassembly-vscode-1.2.1.vsix && code --install-extension /tmp/frameassembly.vsix && rm -f /tmp/frameassembly.vsix
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

- [examples/l2/arp/](examples/l2/arp/) — **`ARP` (RFC 826):** `REQUEST`, `REPLY`, `GRATUITOUS` / `GARP`, `SHA <mac>`, `SPA <ip>`, `THA <mac>`, `TPA <ip>`, `SENDERMAC <mac>`, `TARGETMAC <mac>`, `SENDERIP <ip>`, `TARGETIP <ip>`.
- [examples/l2/vlan/](examples/l2/vlan/) — **`VLAN` (IEEE 802.1Q):** `VLAN <1..4094>`, `PCP <0..7>`, `DEI <0..1>`.
- [examples/l2/qinq/](examples/l2/qinq/) — **`QINQ` (IEEE 802.1ad Provider Bridging):** `QINQ <1..4094>`, `INNER_VLAN <1..4094>`, `PCP <0..7>`, `DEI <0..1>`.
- [examples/l2/lldp/](examples/l2/lldp/) — **`LLDP` (IEEE 802.1AB):** `CHASSIS_ID "<str>"`, `PORT_ID "<str>"`, `TTL <u16>`, `SYSNAME "<str>"`, `SYSDESC "<str>"`.
- [examples/l2/stp/](examples/l2/stp/) — **`STP` (IEEE 802.1D / 802.1w RSTP):** `ROOTID "<str>"` / `ROOT_ID "<str>"`, `BRIDGEID "<str>"` / `BRIDGE_ID "<str>"`, `COST <u32>`, `PORT_ID <u16>`, `MAX_AGE <u16>`, `HELLO_TIME <u16>`, `FORWARD_DELAY <u16>`, `RSTP`, `FLAGS <u8>`.
- [examples/l2/lacp/](examples/l2/lacp/) — **`LACP` (IEEE 802.3ad):** `ACTOR_SYS "<mac>"`, `ACTOR_KEY <u16>`, `ACTOR_PORT <u16>`, `PARTNER_SYS "<mac>"`, `PARTNER_KEY <u16>`, `PARTNER_PORT <u16>`, `ACTOR_STATE <u8>`, `PARTNER_STATE <u8>`.
- [examples/l2/eapol/](examples/l2/eapol/) — **`EAPOL` (IEEE 802.1X NAC):** `VERSION <u8>`, `TYPE <START|LOGOFF|KEY|EAP_PACKET>`, `EAP_CODE <u8>`, `EAP_ID <u8>`, `EAP_METHOD <u8>`, `IDENTITY "<str>"`.
- [examples/l2/mpls/](examples/l2/mpls/) — **`MPLS` (RFC 3032):** `LABEL <u32>`, `EXP <0..7>`, `TC <0..7>`, `BOS <0..1>`, `MPLS_TTL <u8>`.

### 2. Layer 3 Routing, Tunneling & Security Protocols (20 Protocols)

- [examples/l3/icmp/](examples/l3/icmp/) — **`ICMP` (RFC 792 / RFC 4443 Dual-Stack):** `ECHO_REQUEST`, `ECHO_REPLY`, `DEST_UNREACH`, `TIME_EXCEEDED`, `REDIRECT`, `CODE <u8>`, `ID <u16>`, `SEQ <u16>`, `GATEWAY <ip>`.
- [examples/l3/ndp/](examples/l3/ndp/) — **`NDP` (RFC 4861 IPv6 Neighbor Discovery):** `ROUTER_SOLICIT`, `ROUTER_ADVERT`, `NEIGHBOR_SOLICIT`, `NEIGHBOR_ADVERT`, `TARGET <ipv6>`, `SLLA <mac>`, `TLLA <mac>`, `ROUTER_LIFETIME <u16>`.
- [examples/l3/igmp/](examples/l3/igmp/) — **`IGMP` (RFC 2236 / RFC 3376):** `QUERY`, `REPORT`, `LEAVE`, `V1`, `V2`, `V3`, `VERSION <1..3>`, `GROUP <ipv4>`, `MAX_RESP <u8>`.
- [examples/l3/mld/](examples/l3/mld/) — **`MLD` (RFC 2710 / RFC 3810 IPv6 Multicast):** `QUERY`, `REPORT`, `DONE`, `V1`, `V2`, `MULTICAST_ADDR <ipv6>`, `MAX_RESP_DELAY <u16>`.
- [examples/l3/gre/](examples/l3/gre/) — **`GRE` (RFC 2784 / RFC 2890):** `CHECKSUM`, `GRE_KEY <u32>`, `GRE_SEQ <u32>`, `SEQ <u32>`, `GRE_PROTO <u16>`.
- [examples/l3/vxlan/](examples/l3/vxlan/) — **`VXLAN` (RFC 7348):** `VNI <u32>` / `VNID <u32>`, `SRCPORT <u16>`, `DSTPORT <u16>`.
- [examples/l3/geneve/](examples/l3/geneve/) — **`GENEVE` (RFC 8926):** `VNI <u32>` / `VNID <u32>`, `PROTOCOL_TYPE <u16>`, `OPT_CLASS <u16>`, `OPT_TYPE <u8>`.
- [examples/l3/ipsec/](examples/l3/ipsec/) — **`IPSEC` (RFC 4301):** `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
- [examples/l3/esp/](examples/l3/esp/) — **`ESP` (RFC 4303):** `SPI <u32>`, `SEQ <u32>`, `IV "<hex>"`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
- [examples/l3/ah/](examples/l3/ah/) — **`AH` (RFC 4302):** `SPI <u32>`, `SEQ <u32>`, `ICV "<hex>"`, `NEXT_HEADER <u8>`.
- [examples/l3/ikev2/](examples/l3/ikev2/) — **`IKEV2` (RFC 7296):** `INITIATOR_SPI <u64>`, `RESPONDER_SPI <u64>`, `EXCHANGE <u8>`, `SA_INIT`, `CREATE_CHILD_SA`, `INFORMATIONAL`, `MSGID <u32>`, `NEXT_PAYLOAD <u8>`.
- [examples/l3/wireguard/](examples/l3/wireguard/) — **`WIREGUARD` (WireGuard VPN):** `TYPE <INITIATION|RESPONSE|COOKIE|DATA>`, `SENDER <u32>`, `RECEIVER <u32>`, `COUNTER <u64>`.
- [examples/l3/ospf/](examples/l3/ospf/) — **`OSPF` (RFC 2328 OSPFv2 / RFC 5340 OSPFv3):** `HELLO`, `DBD`, `LSR`, `LSU`, `LSACK`, `ROUTER_ID <ip>`, `AREA_ID <u32>`, `HELLO_INTERVAL <u16>`, `DEAD_INTERVAL <u32>`, `PRIORITY <u8>`.
- [examples/l3/bgp/](examples/l3/bgp/) — **`BGP` (RFC 4271 / RFC 2545 BGP-4):** `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ASN <u32>`, `HOLDTIME <u16>`, `BGPID <ip>`, `PREFIX "<cidr>"`, `NEXTHOP <ip>`.
- [examples/l3/rip/](examples/l3/rip/) — **`RIP` (RFC 2453 RIPv2 / RFC 2080 RIPng):** `REQUEST`, `REPLY`, `COMMAND <u8>`, `VERSION <u8>`, `METRIC <u32>`, `TAG <u16>`, `PREFIX <ip>`, `NEXTHOP <ip>`.
- [examples/l3/vrrp/](examples/l3/vrrp/) — **`VRRP` (RFC 5798 VRRPv3 / RFC 3768 VRRPv2):** `VERSION <2|3>`, `VRID <u8>`, `PRIORITY <u8>`, `ADV_INT <u16>`, `VIP <ip>`.
- [examples/l3/hsrp/](examples/l3/hsrp/) — **`HSRP` (RFC 2281):** `GROUP <u8>`, `PRIORITY <u8>`, `HELLOTIME <u8>`, `HOLDTIME <u16>`, `STATE <u8>`, `VIP <ip>`.
- [examples/l3/pim/](examples/l3/pim/) — **`PIM` (RFC 7761 PIM-SM):** `HELLO`, `JOIN_PRUNE`, `REGISTER`, `DR_PRIORITY <u32>`, `HOLDTIME <u16>`, `SOURCE <ip>`, `GROUP <ip>`, `RP <ip>`.
- [examples/l3/bfd/](examples/l3/bfd/) — **`BFD` (RFC 5880 / RFC 5881):** `STATE <u8>`, `DIAG <u8>`, `MY_DISC <u32>`, `YOUR_DISC <u32>`, `MIN_TX <u32>`, `MIN_RX <u32>`, `MULT <u8>`.
- [examples/l3/openflow/](examples/l3/openflow/) — **`OPENFLOW` (OpenFlow 1.3):** `HELLO`, `FEATURES_REQ`, `FEATURES_REPLY`, `PACKET_IN`, `PACKET_OUT`, `FLOW_MOD`, `ECHO_REQ`, `ECHO_REPLY`, `VERSION <u8>`, `XID <u32>`, `DPID <u64>`, `TABLE <u8>` / `TABLE_ID <u8>`, `PRIORITY <u16>`.

### 3. Layer 4 Transport Protocols (3 Protocols)

- [examples/l4/tcp/](examples/l4/tcp/) — **`TCP` (RFC 9293 / RFC 7323):** `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`, `SRCPORT <u16>`, `DSTPORT <u16>`, `SEQ <u32>`, `ACKNUM <u32>`, `WIN <u16>`, `WINDOW <u16>`, `MSS <u16>`, `WSCALE <u8>`, `SACK_PERM`, `TSVAL <u32>`, `TSECR <u32>`, `URGENT <u16>`.
- [examples/l4/udp/](examples/l4/udp/) — **`UDP` (RFC 768):** `SRCPORT <u16>`, `DSTPORT <u16>`.
- [examples/l4/sctp/](examples/l4/sctp/) — **`SCTP` (RFC 9260):** `VTAG <u32>`, `CHECKSUM <u32>`, `CHUNK <type>`, `INIT`, `INIT_ACK`, `SACK`, `HEARTBEAT`, `HEARTBEAT_ACK`, `ABORT`, `SHUTDOWN`, `COOKIE_ECHO`, `COOKIE_ACK`, `TSN <u32>`, `STREAM <u16>`, `SSN <u16>`, `PPID <u32>`.

### 4. SNMP Protocols (3 Protocols)

- [examples/l7/snmp/snmpv1/](examples/l7/snmp/snmpv1/) — **`SNMP1` (RFC 1157 SMIv1 BER):** `TRAP`, `GET`, `SET`, `RESPONSE`, `GETNEXT`, `COMMUNITY "<str>"`, `OID <oid>`, `SYSUPTIME <u32>`, `ENTERPRISE <oid>`, `AGENTIP <ipv4>`, `GENTRAP <0..6>`, `SPECTRAP <u32>`, `VARBIND`.
- [examples/l7/snmp/snmpv2c/](examples/l7/snmp/snmpv2c/) — **`SNMP2` (RFC 3416 SMIv2 BER):** `TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `COMMUNITY "<str>"`, `OID <oid>`, `SYSUPTIME <u32>`, `REQID <u32>`, `NONREPEATERS <u32>`, `MAXREPETITIONS <u32>`, `VARBIND`.
- [examples/l7/snmp/snmpv3/](examples/l7/snmp/snmpv3/) — **`SNMP3` (RFC 3414 / 3826 / 7860 USM):** `TRAP`, `INFORM`, `GET`, `GETNEXT`, `GETBULK`, `SET`, `RESPONSE`, `REPORT`, `USER "<str>"`, `ENGINEID "<hex>"`, `ENGINEBOOTS <u32>`, `ENGINETIME <u32>`, `CONTEXTNAME "<str>"`, `AUTH <MD5|SHA|SHA256|SHA384|SHA512> "<pass>"`, `PRIV <DES|AES> "<pass>"`, `VARBIND`.
  - **All 9 SMI `VARBIND <oid> <TYPE> <value>` Types:** `NULLVAL` / `NULL`, `STRING "<text>"`, `INT <signed_i32>`, `TIMETICKS <u32>`, `IPVAL <ip>`, `OIDVAL <oid>`, `COUNTER32 <u32>`, `GAUGE32 <u32>`, `COUNTER64 <u64>`.

### 5. Layer 7 Network Management & Telemetry Protocols (11 Protocols)

- [examples/l7/dns/](examples/l7/dns/) — **`DNS` (RFC 1035):** `TXID <u16>`, `QNAME "<name>"`, `QTYPE <u16>`, `RDATA "<str>"`, `RCODE <u8>`, `ANS_TTL <u32>`.
- [examples/l7/mdns/](examples/l7/mdns/) — **`MDNS` (RFC 6762):** `QUERY`, `RESPONSE`, `TXID <u16>`, `QNAME "<name>"`, `QTYPE <u16>`, `RDATA "<str>"`, `ANS_TTL <u32>`.
- [examples/l7/dhcp/](examples/l7/dhcp/) — **`DHCP` (RFC 2131 / RFC 8415 DHCPv6):** `DISCOVER`, `OFFER`, `REQUEST`, `RELEASE`, `SOLICIT`, `ADVERTISE`, `TXID <u32>`, `CIADDR <ip>`, `YIADDR <ip>`, `SIADDR <ip>`, `CHADDR <mac>`, `HOSTNAME "<str>"`, `DNS_SERVER <ip>`, `ROUTER <ip>`, `SUBNET_MASK <ip>`, `LEASE_TIME <u32>`.
- [examples/l7/ntp/](examples/l7/ntp/) — **`NTP` (RFC 5905):** `LI <0..3>`, `VN <0..7>`, `MODE <0..7>`, `STRATUM <u8>`, `POLL <u8>`, `PRECISION <i8>`, `REFID "<str>"`, `TX_TIMESTAMP <u64>`.
- [examples/l7/ptp/](examples/l7/ptp/) — **`PTP` (IEEE 1588-2008):** `MSG_TYPE <u8>`, `SYNC`, `DELAY_REQ`, `FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE`, `VERSION <u8>`, `DOMAIN <u8>`, `SEQ_ID <u16>`, `CLOCK_ID "<mac>"`.
- [examples/l7/radius/](examples/l7/radius/) — **`RADIUS` (RFC 2865):** `CODE <u8>`, `ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCESS_REJECT`, `ACCESS_CHALLENGE`, `ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE`, `ID <u8>`, `USER "<str>"`, `NAS_IP <ip>`, `SERVICE_TYPE <u32>`, `FRAMED_IP <ip>`.
- [examples/l7/tacacs/](examples/l7/tacacs/) — **`TACACS` (RFC 8907 TACACS+):** `AUTHEN`, `AUTHOR`, `ACCT`, `SESSION_ID <u32>`, `USER "<str>"`.
- [examples/l7/syslog/](examples/l7/syslog/) — **`SYSLOG` (RFC 5424):** `PRI <u16>`, `FACILITY <u8>`, `SEVERITY <u8>`, `HOSTNAME "<str>"`, `APP "<str>"`, `PROCID "<str>"`, `MSGID "<str>"`, `MSG "<text>"`.
- [examples/l7/netflow/](examples/l7/netflow/) — **`NETFLOW` (Cisco NetFlow v5/v9):** `VERSION <u16>`, `UPTIME <u32>`, `SRCIP <ip>`, `DSTIP <ip>`, `NEXTHOP <ip>`, `SRCPORT <u16>`, `DSTPORT <u16>`, `PACKETS <u32>`, `OCTETS <u32>`, `PROTO <u8>`, `TOS <u8>`.
- [examples/l7/ipfix/](examples/l7/ipfix/) — **`IPFIX` (RFC 7011):** `DOMAIN_ID <u32>`, `SRCIP <ip>`, `DSTIP <ip>`, `PACKETS <u64>`, `OCTETS <u64>`, `PROTO <u8>`.
- [examples/l7/sflow/](examples/l7/sflow/) — **`SFLOW` (RFC 3176):** `VERSION <u32>`, `AGENT_IP <ip>`, `SUB_AGENT_ID <u32>`, `SEQ_NUM <u32>`, `UPTIME <u32>`, `SAMPLES <u32>`.

### 6. Layer 7 Web, App, Storage, Mail & Messaging Protocols (30 Protocols)

- [examples/l7/tftp/](examples/l7/tftp/) — **`TFTP` (RFC 1350):** `RRQ`, `WRQ`, `FILENAME "<str>"`, `MODE "<str>"`, `BLOCK <u16>`, `ERRCODE <u16>`, `ERRMSG "<str>"`.
- [examples/l7/ftp/](examples/l7/ftp/) — **`FTP` (RFC 959):** `CMD "<str>"`, `ARG "<str>"`, `BANNER "<str>"`, `USER "<str>"`.
- [examples/l7/ssh/](examples/l7/ssh/) — **`SSH` (RFC 4253):** `BANNER "<str>"`, `KEXINIT`, `NEWKEYS`, `MSG_CODE <u8>`.
- [examples/l7/telnet/](examples/l7/telnet/) — **`TELNET` (RFC 854):** `WILL`, `WONT`, `DO`, `DONT`, `OPTION <u8>`, `CMD <u8>`.
- [examples/l7/http/](examples/l7/http/) — **`HTTP` (RFC 7230 HTTP/1.1):** `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `URI "<str>"`, `HOST_HDR "<str>"`, `USER_AGENT "<str>"`, `CONTENT_TYPE "<str>"`, `STATUS <u16>`, `REASON "<str>"`, `HEADER "<k>" "<v>"`, `BODY "<str>"`.
- [examples/l7/http2/](examples/l7/http2/) — **`HTTP2` (RFC 7540):** `PREFACE`, `SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`, `PING`, `GOAWAY`, `STREAM_ID <u32>`.
- [examples/l7/grpc/](examples/l7/grpc/) — **`GRPC` (gRPC over HTTP/2):** `SERVICE "<str>"`, `METHOD "<str>"`, `GRPC_STATUS <u32>`, `PAYLOAD "<str>"`.
- [examples/l7/websocket/](examples/l7/websocket/) — **`WEBSOCKET` (RFC 6455):** `OPCODE <u8>`, `TEXT`, `BINARY`, `PING`, `PONG`, `CLOSE`, `FIN_BIT <0..1>`, `MASK_KEY <u32>`, `PAYLOAD "<str>"`.
- [examples/l7/tls/](examples/l7/tls/) — **`TLS` (RFC 8446 TLS 1.3):** `CLIENT_HELLO`, `SERVER_HELLO`, `CERTIFICATE`, `FINISHED`, `APP_DATA`, `ALERT`, `RECORD_VERSION <u16>`, `HANDSHAKE_VERSION <u16>`, `SNI "<str>"`, `CIPHERSUITE <u16>`, `ALPN "<str>"`.
- [examples/l7/quic/](examples/l7/quic/) — **`QUIC` (RFC 9000):** `INITIAL`, `ZERO_RTT`, `HANDSHAKE`, `RETRY`, `SHORT`, `VERSION <u32>`, `DCID "<hex>"`, `SCID "<hex>"`, `TOKEN "<hex>"`, `PKT_NUM <u32>`, `PAYLOAD "<str>"`.
- [examples/l7/stun/](examples/l7/stun/) — **`STUN` (RFC 8489):** `BINDING_REQUEST`, `BINDING_RESPONSE`, `BINDING_ERROR`, `TXID "<hex>"`, `XOR_MAPPED_ADDR <ip> <port>`, `SOFTWARE "<str>"`.
- [examples/l7/sip/](examples/l7/sip/) — **`SIP` (RFC 3261):** `INVITE`, `ACK`, `BYE`, `CANCEL`, `REGISTER`, `OPTIONS`, `URI "<str>"`, `FROM "<str>"`, `TO "<str>"`, `CALL_ID "<str>"`, `CSEQ <u32>`, `VIA "<str>"`, `CONTACT "<str>"`.
- [examples/l7/rtp/](examples/l7/rtp/) — **`RTP` (RFC 3550):** `PT <u8>`, `SEQ <u16>`, `TIMESTAMP <u32>`, `SSRC <u32>`, `MARKER <0..1>`, `PAYLOAD "<str>"`.
- [examples/l7/rtsp/](examples/l7/rtsp/) — **`RTSP` (RFC 2326):** `DESCRIBE`, `SETUP`, `PLAY`, `TEARDOWN`, `OPTIONS`, `URI "<str>"`, `CSEQ <u32>`, `SESSION "<str>"`, `TRANSPORT_HDR "<str>"`.
- [examples/l7/smtp/](examples/l7/smtp/) — **`SMTP` (RFC 5321):** `EHLO "<domain>"`, `HELO "<domain>"`, `MAIL_FROM "<addr>"`, `RCPT_TO "<addr>"`, `DATA`, `QUIT`, `STATUS <u16>`, `MSG "<str>"`.
- [examples/l7/imap/](examples/l7/imap/) — **`IMAP` (RFC 3501):** `TAG "<str>"`, `CMD "<str>"`, `PARAM "<str>"`, `OK`, `ERR`.
- [examples/l7/pop3/](examples/l7/pop3/) — **`POP3` (RFC 1939):** `CMD "<str>"`, `ARG "<str>"`, `OK`, `ERR`, `USER "<str>"`.
- [examples/l7/kerberos/](examples/l7/kerberos/) — **`KERBEROS` (RFC 4120):** `AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`, `KRB_ERROR`, `REALM "<str>"`, `CNAME "<str>"`, `SNAME "<str>"`, `ETYPE <u32>`.
- [examples/l7/ldap/](examples/l7/ldap/) — **`LDAP` (RFC 4511):** `MSGID <u32>`, `BIND_REQ`, `BIND_RES`, `SEARCH_REQ`, `SEARCH_ENTRY`, `SEARCH_DONE`, `UNBIND_REQ`, `VERSION <u8>`, `USER "<str>"`, `BASE_DN "<str>"`, `FILTER "<str>"`, `RESULT_CODE <u32>`.
- [examples/l7/smb/](examples/l7/smb/) — **`SMB` (MS-SMB2/3):** `NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`, `TREE_DISCONNECT`, `SESSION_ID <u64>`, `TREE_ID <u32>`, `SHARE "<str>"`, `STATUS <u32>`.
- [examples/l7/nfs/](examples/l7/nfs/) — **`NFS` (RFC 1813 / RFC 7530):** `VERS <u32>`, `PROC <u32>`, `PATH "<str>"`, `COMPOUND`, `STATUS <u32>`.
- [examples/l7/redis/](examples/l7/redis/) — **`REDIS` (RESP Protocol):** `CMD "<str>"`, `ARGS "<str>"`, `REPLY_TYPE "<str>"`, `VALUE "<str>"`.
- [examples/l7/memcached/](examples/l7/memcached/) — **`MEMCACHED`:** `CMD "<str>"`, `KEY "<str>"`, `VALUE "<str>"`, `FLAGS <u32>`, `EXPTIME <u32>`, `OPAQUE <u32>`, `CAS <u64>`.
- [examples/l7/mysql/](examples/l7/mysql/) — **`MYSQL`:** `GREETING`, `LOGIN`, `SQL "<query>"`, `OK`, `ERR`, `EOF`, `SERVER_VERSION "<str>"`, `USER "<str>"`, `DB "<str>"`.
- [examples/l7/postgres/](examples/l7/postgres/) — **`POSTGRES` (v3.0):** `STARTUP`, `SQL "<query>"`, `READY_FOR_QUERY`, `COMMAND_COMPLETE`, `ERROR_RESPONSE`, `AUTH_OK`, `USER "<str>"`, `DB "<str>"`.
- [examples/l7/mqtt/](examples/l7/mqtt/) — **`MQTT` (v3.1.1 / v5.0):** `CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`, `SUBSCRIBE`, `SUBACK`, `PINGREQ`, `PINGRESP`, `DISCONNECT`, `CLIENT_ID "<str>"`, `TOPIC "<str>"`, `QOS <0..2>`, `RETAIN <0..1>`, `PKT_ID <u16>`, `PAYLOAD "<str>"`.
- [examples/l7/coap/](examples/l7/coap/) — **`COAP` (RFC 7252):** `CON`, `NON`, `ACK`, `RST`, `CODE <u8>`, `GET`, `POST`, `PUT`, `DELETE`, `MSGID <u16>`, `TOKEN "<hex>"`, `URI_PATH "<str>"`, `CONTENT_FORMAT <u16>`.
- [examples/l7/amqp/](examples/l7/amqp/) — **`AMQP` (0-9-1 / 1.0):** `PROTOCOL_HEADER`, `CONNECTION_START`, `CHANNEL_OPEN`, `BASIC_PUBLISH`, `BASIC_DELIVER`, `CHANNEL <u16>`, `ROUTING_KEY "<str>"`.
- [examples/l7/ssdp/](examples/l7/ssdp/) — **`SSDP` (UPnP Discovery):** `MSEARCH`, `NOTIFY`, `MAN "<str>"`, `MX <u8>`, `ST "<str>"`, `NT "<str>"`, `NTS "<str>"`, `USN "<str>"`, `LOCATION "<str>"`.
- [examples/l7/whois/](examples/l7/whois/) — **`WHOIS` (RFC 3912):** `QUERY "<domain>"`, `REGISTRAR "<str>"`.

### 7. Layer 7 Industrial & Operational Technology (SCADA/OT) Protocols (6 Protocols)

- [examples/l7/modbus/](examples/l7/modbus/) — **`MODBUS` (Modbus TCP):** `PROTO_ID <u16>`, `UNITID <u8>`, `FUNC <u8>`, `READ_COILS`, `READ_DISCRETE_INPUTS`, `READ_HOLDING_REGISTERS`, `READ_INPUT_REGISTERS`, `WRITE_SINGLE_COIL`, `WRITE_SINGLE_REGISTER`, `WRITE_MULTIPLE_REGISTERS`, `ADDR <u16>`, `COUNT <u16>`, `DATA "<hex>"`, `IS_RESPONSE`, `TXID <u16>`, `VALUE <u16>`.
- [examples/l7/bacnet/](examples/l7/bacnet/) — **`BACNET` (ASHRAE 135 BACnet/IP):** `WHO_IS`, `I_AM`, `READ_PROPERTY`, `WRITE_PROPERTY`, `INVOKE_ID <u8>`, `OBJECT_TYPE <u16>`, `OBJECT_INSTANCE <u32>`, `PROPERTY_ID <u32>`.
- [examples/l7/dnp3/](examples/l7/dnp3/) — **`DNP3` (IEEE 1815):** `FUNC <u8>`, `CONFIRM`, `READ`, `WRITE`, `SELECT`, `OPERATE`, `DIRECT_OPERATE`, `UNSOLICITED_RESPONSE`, `VARIATION <u8>`, `CRC <u16>`, `SRC <u16>`, `DST <u16>`.
- [examples/l7/s7comm/](examples/l7/s7comm/) — **`S7COMM` (Siemens S7 PLC):** `ROSCTR <u8>`, `PDU_REF <u16>`, `SETUP_COMM`, `READ_VAR`, `WRITE_VAR`, `PLC_CONTROL`, `AREA <u8>`, `DB_NUM <u16>`, `OFFSET <u32>`, `COUNT <u16>`.
- [examples/l7/ethernetip/](examples/l7/ethernetip/) — **`ETHERNETIP` (ODVA EtherNet/IP & CIP):** `LIST_SERVICES`, `LIST_IDENTITY`, `LIST_INTERFACES`, `REGISTER_SESSION`, `UNREGISTER_SESSION`, `SEND_RR_DATA`, `SEND_UNIT_DATA`, `SESSION_HANDLE <u32>`, `STATUS <u32>`, `CONTEXT "<hex>"`, `CIP_SERVICE <u8>`, `CIP_CLASS <u16>`, `CIP_INSTANCE <u16>`, `CIP_ATTR <u16>`, `DATA "<hex>"`.
- [examples/l7/opcua/](examples/l7/opcua/) — **`OPCUA` (IEC 62541):** `CHUNK_TYPE "<c>"`, `SECURE_CHANNEL_ID <u32>`, `TOKEN_ID <u32>`, `SEQ_NUM <u32>`, `ENDPOINT_URL "<str>"`, `NODE_ID "<str>"`, `PAYLOAD "<str>"`.

---

## Examples Corpus Directory Index

The `examples/` directory contains an exhaustive verified corpus of **`2,611` `.fasm` scenarios** across all 82 dedicated directories:

- **Layer 2 Data-Link (`examples/l2/` — `248` examples):** `arp/`, `vlan/`, `qinq/`, `lldp/`, `stp/`, `lacp/`, `eapol/`, `mpls/`.
- **Layer 3 Routing & Tunneling (`examples/l3/` — `620` examples):** `icmp/`, `ndp/`, `igmp/`, `mld/`, `gre/`, `vxlan/`, `geneve/`, `ipsec/`, `esp/`, `ah/`, `ikev2/`, `wireguard/`, `ospf/`, `bgp/`, `rip/`, `vrrp/`, `hsrp/`, `pim/`, `bfd/`, `openflow/`.
- **Layer 4 Transports (`examples/l4/` — `95` examples):** `tcp/`, `udp/`, `sctp/`.
- **Layer 7 Telemetry, Web & Industrial (`examples/l7/` — `1,544` examples):**
  - Telemetry & Infra: `dns/`, `mdns/`, `dhcp/`, `ntp/`, `ptp/`, `radius/`, `tacacs/`, `syslog/`, `netflow/`, `ipfix/`, `sflow/`.
  - Web & App: `http/`, `http2/`, `grpc/`, `websocket/`, `tls/`, `quic/`, `stun/`, `sip/`, `rtp/`, `rtsp/`, `smtp/`, `imap/`, `pop3/`, `kerberos/`, `ldap/`, `smb/`, `nfs/`, `redis/`, `memcached/`, `mysql/`, `postgres/`, `mqtt/`, `coap/`, `amqp/`, `ssdp/`, `whois/`, `tftp/`, `ftp/`, `ssh/`, `telnet/`.
  - SCADA & OT: `modbus/`, `bacnet/`, `dnp3/`, `s7comm/`, `ethernetip/`, `opcua/`.
  - SNMP (`examples/l7/snmp/`): `snmpv1/`, `snmpv2c/`, `snmpv3/`.
- **Cross-Cutting Topologies (`examples/topologies/` — `104` examples):** Spine-leaf EVPN-VXLAN fabric, campus 802.1X NAC, DMZ firewall alerts, VoIP QoS, 5G SBA core, IEC 62443 substations, Kubernetes dual-stack service mesh, and SD-WAN failover.

---

## Technical Documentation & Compiler Architecture

FrameAssembly v1.2.1 enforces a unified `<layer>/<protocol>` architecture across both compiler implementation modules (`src/`) and verified example captures (`examples/`):

```text
frameassembly/
├── src/
│   ├── lexer/          # Zero-copy Logos tokenizer (mod.rs, tests.rs)
│   ├── ast/            # Abstract Syntax Tree definitions (mod.rs, l2/, l3/, l4/, l7/)
│   ├── parser/         # Winnow token-slice parser combinators & semantic validator
│   ├── builders/       # Zero-heap RFC wire builders (l2/, l3/, l4/, l7/, l7/snmp/)
│   ├── backend/        # Stateful 4-tuple tracking, timing, and PCAP emission
│   ├── packet.rs       # Native Ethernet/VLAN/QinQ/MPLS/IPv4/IPv6/L4 framing
│   ├── pcap.rs         # Nanosecond-precision PCAPNG writer (pcap-file)
│   └── main.rs         # Command-line binary interface
├── docs/               # 11 chunked (< 50 KB) architecture & protocol guides
└── examples/           # 2,611 verified .fasm scenarios (l2/, l3/, l4/, l7/, topologies/)
```

Comprehensive deep-dive architecture, RFC wire default mappings, and instruction-tuning guides are available in `docs/` (`< 50 KB` per file):

- [`docs/architecture_and_grammar.md`](docs/architecture_and_grammar.md) — Compiler pipeline, `HOST`/`FLOW`/`COMPILE` syntax, L2–L4 modifiers, dual-stack polymorphism, and formal grammar specification.
- [`docs/l2_protocols.md`](docs/l2_protocols.md) — All 8 Layer 2 protocols (`ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`).
- [`docs/l3_protocols.md`](docs/l3_protocols.md) — All 20 Layer 3 control, tunneling, VPN, and routing protocols (`ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`).
- [`docs/l4_transports.md`](docs/l4_transports.md) — Layer 4 transports (`TCP`, `UDP`, `SCTP`), 4-tuple state tracking, RFC 7323 options, and SCTP multi-chunk signaling.
- [`docs/l7_snmp.md`](docs/l7_snmp.md) — `SNMP1`, `SNMP2`, and `SNMP3` USM cryptographic authentication (`MD5`/`SHA`/`SHA256`/`SHA384`/`SHA512`), encryption (`DES`/`AES`), and all 9 SMI `VARBIND` types.
- [`docs/l7_infra_and_telemetry.md`](docs/l7_infra_and_telemetry.md) — Infrastructure, time, AAA, and flow telemetry (`DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`).
- [`docs/l7_web_and_cloud.md`](docs/l7_web_and_cloud.md) — Web, cloud-native, TLS/QUIC, VoIP, and remote access (`HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `STUN`, `SIP`, `RTP`, `RTSP`, `SSDP`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`).
- [`docs/l7_mail_auth_storage_db.md`](docs/l7_mail_auth_storage_db.md) — Mail, directory, storage, databases, caches, and message brokers (`SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`).
- [`docs/l7_industrial_ot.md`](docs/l7_industrial_ot.md) — Industrial Control Systems (ICS) & SCADA/OT (`MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`).
- [`docs/topologies_and_dual_stack.md`](docs/topologies_and_dual_stack.md) — Multi-tier enterprise, EVPN-VXLAN data center, Zero-Trust 802.1X NAC, Kubernetes dual-stack, and IEC 62443 substation topologies.
- [`docs/qa_synthesis_guide.md`](docs/qa_synthesis_guide.md) — Natural-language Prompt-to-`.fasm` instruction-tuning Q&A pairs and constrained decoding guide.

Formal Grammars, AI Discovery & Metadata Specifications:
- [`grammar.ebnf`](grammar.ebnf) — ISO/IEC 14977 formal context-free EBNF grammar.
- [`frameassembly.gbnf`](frameassembly.gbnf) — `llama.cpp` GBNF grammar for constrained decoding (`--grammar-file frameassembly.gbnf`).
- [`frameassembly.lark`](frameassembly.lark) — Earley/LALR Lark grammar for `vLLM`, `Outlines`, `Guidance`, `XGrammar`, and `llguidance`.
- [`AGENTS.md`](AGENTS.md), [`CLAUDE.md`](CLAUDE.md) & [`.github/copilot-instructions.md`](.github/copilot-instructions.md) — AI coding agent onboarding and syntax guardrails.
- [`llms.txt`](llms.txt), [`llms-full.txt`](llms-full.txt) & [`context7.json`](context7.json) — Curated LLM index, full context bundle, and Context7 MCP configuration.
- [`CITATION.cff`](CITATION.cff) & [`codemeta.json`](codemeta.json) — CFF 1.2.0 and CodeMeta 2.0 software citation metadata.

---

## Complete Realistic Example

```frameassembly
// PROMPT: Dual-stack HTTP and DNS monitoring scenario with QoS tagging.
// TOKENS: HOST, IP, FLOW, ->, <-, TCP, SYN, ACK, PSH, PAYLOAD, UDP, DSTPORT, DSCP, FLOWLABEL, COMPILE

host client_v4 { ip 192.168.1.50 }
host server_v4 { ip 192.168.1.1 }

host client_v6 { ip 2001:db8::50 }
host server_v6 { ip 2001:db8::1 }

flow web_request(client, server) {
    client -> server tcp syn win 65535 dscp 46
    client <- server tcp syn ack win 65535 dscp 46
    client -> server tcp ack dscp 46
    client -> server tcp psh ack payload "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
}

flow dns_lookup(client, resolver) {
    client -> resolver udp dstport 53 flowlabel 1000 payload "DNS_QUERY_EXAMPLE"
    client <- resolver udp flowlabel 1000 payload "DNS_RESPONSE_EXAMPLE"
}

compile {
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
