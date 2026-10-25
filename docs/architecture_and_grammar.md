# FrameAssembly Architecture, Compiler Pipeline & Formal Grammar Reference

FrameAssembly (`frameassembly`) is an optimizing domain-specific language (DSL) and zero-copy network packet compiler written in Rust (Edition 2024). It compiles declarative, human-readable, and LLM-friendly network traffic specifications (`.fasm`) into deterministic, wire-valid classic PCAP (`.pcap`) and PCAPNG packet captures across **81 protocols spanning OSI Layers 2 through 7**.

This canonical reference details the six-stage compiler pipeline, lexical and syntactic design, formal constrained-decoding grammars ([`grammar.ebnf`](../grammar.ebnf), [`frameassembly.gbnf`](../frameassembly.gbnf), and [`frameassembly.lark`](../frameassembly.lark)), stateful 4-tuple tracking, dual-stack IPv4/IPv6 polymorphism, universal cross-layer modifiers, and source-mapped diagnostic reporting.

---

## 1. Canonical Documentation Index

| Guide | OSI Layer & Scope | Covered Protocols & Subsystems |
| :--- | :--- | :--- |
| [`architecture_and_grammar.md`](architecture_and_grammar.md) | Compiler & Grammar | 6-stage pipeline, AST, EBNF/GBNF/Lark grammars, 4-tuple tracking, universal modifiers |
| [`l2_protocols.md`](l2_protocols.md) | Layer 2 (Data Link) | `ARP`, `VLAN` (802.1Q), `QINQ` (802.1ad), `LLDP` (802.1AB), `STP`/`RSTP` (802.1D/w), `LACP` (802.3ad), `EAPOL` (802.1X), `MPLS` (RFC 3032) |
| [`l3_protocols.md`](l3_protocols.md) | Layer 3 (Network, Routing & Tunnels) | IPv4, IPv6, `ICMP`, `ICMPv6`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW` |
| [`l4_transports.md`](l4_transports.md) | Layer 4 (Transport) | `TCP` (RFC 9293 stateful SEQ/ACK/Window/Flags), `UDP` (RFC 768), `SCTP` (RFC 9260 multi-chunk Verification Tag & CRC32c) |
| [`l7_snmp.md`](l7_snmp.md) | Layer 7 (Network Management) | `SNMP1` (RFC 1157), `SNMP2` (RFC 3416 v2c), `SNMP3` (RFC 3414 USM HMAC-MD5/SHA/SHA-2 & DES/AES-128 CFB + ASN.1 BER `VARBIND`) |
| [`l7_infra_and_telemetry.md`](l7_infra_and_telemetry.md) | Layer 7 (Infrastructure & Telemetry) | `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS` |
| [`l7_web_and_cloud.md`](l7_web_and_cloud.md) | Layer 7 (Web, Cloud, VoIP & IoT) | `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `STUN`, `SIP`, `RTP`, `RTSP`, `MQTT`, `COAP`, `AMQP`, `SSDP` |
| [`l7_mail_auth_storage_db.md`](l7_mail_auth_storage_db.md) | Layer 7 (Mail, Identity, Storage & DB) | `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES` |
| [`l7_industrial_ot.md`](l7_industrial_ot.md) | Layer 7 (Industrial OT / ICS / SCADA) | `MODBUS`, `BACNET`, `DNP3` (IEEE 1815 CRC-16), `S7COMM` (TPKT/COTP/ROSCTR), `ETHERNETIP` (CIP), `OPCUA` |
| [`topologies_and_dual_stack.md`](topologies_and_dual_stack.md) | Full-Stack Topologies | Multi-tier enterprise, 5G core, Clos/EVPN fabrics, Zero-Trust 802.1X, SASE, Purdue ICS, dual-stack polymorphism |
| [`qa_synthesis_guide.md`](qa_synthesis_guide.md) | AI / LLM Training & Q&A | Pre-training headers (`PROMPT`, `TOKENS`, `INSTRUCTION`), FIM boundaries, constrained decoding, Q&A exemplars |

---

## 2. Six-Stage Compiler Pipeline Architecture

The FrameAssembly compiler processes `.fasm` source files through a deterministic, six-stage feed-forward compilation pipeline designed for sub-millisecond compilation latency and zero heap waste:

```text
 ┌────────────────┐     ┌────────────────┐     ┌─────────────────────┐
 │  .fasm Source  │ ──> │  Logos Lexer   │ ──> │  Winnow TokenSlice  │
 │  Text Buffer   │     │  (Zero-Copy)   │     │  Parser Combinators │
 └────────────────┘     └────────────────┘     └─────────────────────┘
                                                          │
                                                          ▼
 ┌────────────────┐     ┌────────────────┐     ┌─────────────────────┐
 │ .pcap / PCAPNG │ <── │  4-Tuple State │ <── │  Semantic Validator │
 │ Serialization  │ <── │ & Wire Builders│ <── │ & AST Representation│
 └────────────────┘     └────────────────┘     └─────────────────────┘
```

### Stage 1: Zero-Copy Lexical Analysis (`src/lexer/mod.rs`)
- Powered by `logos 0.14`, the lexer scans the UTF-8 source buffer without allocating strings on the heap.
- Every `SpannedToken<'a>` carries a `Token<'a>` borrowing slices directly from the input buffer alongside a `logos::Span` (`Range<usize>`) recording exact byte offsets.
- Recognizes all 81 protocol keywords, 280+ protocol-specific modifier keywords, hexadecimal/decimal integer literals (`u8`, `u16`, `u32`, `u64`), IPv4 and IPv6 literals, IEEE 802 MAC addresses, ASN.1 Object Identifiers (`OidStr`), duration literals (`ns`, `us`, `ms`, `s`, `m`), and directional operators (`->`, `<-`).

### Stage 2: Two-Phase Token-Slice Combinator Parsing (`src/parser/mod.rs`)
- Implemented with `winnow 1.0` operating over a custom `TokenSlice<'i, 'a>` stream (`Stream<'i, 'a>`).
- Decoupling lexical scanning from syntactic combinators eliminates character-level backtracking, strips comments and whitespace in $O(N)$ time, and preserves exact byte spans for error reporting.
- Modular layer parsers (`src/parser/l2/`, `src/parser/l3/`, `src/parser/l4/`, `src/parser/l7/`) parse unordered modifier lists on each frame statement into strongly-typed `ParsedField<'a>` nodes.

### Stage 3: Semantic Validation (`src/parser/mod.rs`)
Before any byte is lowered to wire format, the semantic validator enforces strict invariants across the Abstract Syntax Tree (`Program<'a>`):
1. **Host Scope & Uniqueness**: Every `HOST` identifier must be unique and define a valid IPv4 or IPv6 address. Every host argument passed in `COMPILE` must refer to a declared `HOST`.
2. **Flow Scope & Parameter Arity**: Every flow invoked in `COMPILE` or `LOOP` must be declared and receive the exact number of host parameters specified in its signature.
3. **Dual-Stack IP Family Homogeneity**: Within any frame statement (`a -> b` or `a <- b`), the concrete hosts bound to `a` and `b` must share the same IP family (both IPv4 or both IPv6). Mixing IPv4 and IPv6 endpoints in a single frame statement triggers a compile-time `SemanticError` with source-mapped spans pointing to the conflicting host declarations.
4. **Modifier Uniqueness & Exclusivity**: Duplicate modifiers within a single frame statement (such as specifying `DSTPORT` twice or two protocols in one statement) are rejected with a diagnostic span.
5. **Positive Loop Bounds**: `LOOP <count> { ... }` blocks require `count >= 1`.

### Stage 4: Zero-Heap Protocol Wire Builders (`src/builders/`)
- Each of the 81 protocols has a dedicated wire builder under `src/builders/{l2,l3,l4,l7}/` that serializes RFC-compliant headers and payloads directly into a pre-allocated frame buffer.
- Missing optional fields automatically receive RFC-compliant defaults (e.g., IPv4 `TTL 64`, `NDP`/`VRRP`/IPv6 `ARP` `TTL 255`, TCP `WINDOW 65535`, DNS port `53`, HTTP port `80`, TLS port `443`, Modbus port `502`, 42-byte inner Ethernet+IPv4+UDP frames when `VXLAN`/`GENEVE` payloads are empty, and ITU-T X.690 ASN.1 OID arc validation in `SNMP`).
- Built-in checksum engines compute RFC 1071 16-bit one's complement checksums (IPv4 header, ICMPv4, TCP with IPv4/IPv6 pseudo-header, UDP with IPv4/IPv6 pseudo-header, GRE RFC 2784, IGMP, VRRPv2 RFC 3768), RFC 5798 VRRPv3 IPv4/IPv6 pseudo-header checksums, RFC 4443 checksums (ICMPv6, NDP, MLDv2), RFC 9260 CRC32c (SCTP), and IEEE 1815 CRC-16 (DNP3).

### Stage 5: Stateful 4-Tuple Engine (`src/backend/mod.rs`)
- Tracks bidirectional connection state keyed by canonical 4-tuple (`Endpoint A`, `Endpoint B`, `Port A`, `Port B`, `Protocol`).
- Automatically reverses source and destination ports on return arrows (`<-`), tracks TCP `SEQ` and `ACKNUM` progression across `SYN`, `FIN`, and payload bytes, and derives RFC 1112 (`01:00:5e:xx:xx:xx`) or RFC 2464 (`33:33:xx:xx:xx:xx`) multicast MAC addresses when multicast hosts omit an explicit `MAC`.

### Stage 6: Nanosecond PCAP Serialization (`src/pcap.rs`)
- Serializes finalized Ethernet frames into standard Libpcap (`.pcap`) format via `pcap-file 2.0`.
- Accumulates frame `WAIT` durations (`ns`, `us`, `ms`, `s`, `m`) into monotonically increasing 64-bit nanosecond timestamps for deterministic replay in Wireshark, `tshark`, Suricata, Zeek, and `tcpreplay`.

---

## 3. Core DSL Syntax & Top-Level Declarations

Every `.fasm` program comprises three top-level constructs: `HOST` declarations, `FLOW` declarations, and a `COMPILE` orchestration block.

### 3.1 `HOST` Declarations
A `HOST` block binds a symbolic identifier to an IPv4 or IPv6 address and an optional 48-bit IEEE 802 MAC address. Always use `IP <address>` and `MAC <mac>` without colons or equals signs after the keywords:

```frameassembly
// PROMPT: Demonstrate canonical IPv4, IPv6, and multicast HOST declarations with a baseline flow.
// TOKENS: HOST, IP, MAC, FLOW, UDP, DSTPORT, PAYLOAD, COMPILE

// INSTRUCTION: Declare an IPv4 client with an explicit IEEE 802 MAC address.
HOST edge_client_v4 {
    IP 192.168.10.25
    MAC 00:1a:2b:3c:4d:5e
}

// INSTRUCTION: Declare an IPv4 server with an explicit MAC address.
HOST edge_server_v4 {
    IP 192.168.10.1
    MAC 00:1a:2b:3c:4d:01
}

// INSTRUCTION: Declare an IPv6 client and server with auto-derived MAC addresses.
HOST edge_client_v6 {
    IP 2001:db8:10::25
    MAC 00:1a:2b:3c:60:25
}

// INSTRUCTION: Declare the IPv6 server endpoint.
HOST edge_server_v6 {
    IP 2001:db8:10::1
    MAC 00:1a:2b:3c:60:01
}

// INSTRUCTION: Define a polymorphic UDP echo flow reusable across IPv4 and IPv6 pairs.
FLOW udp_echo_exchange(client, server) {
    client -> server UDP SRCPORT 54000 DSTPORT 9000 PAYLOAD "ECHO_PING_FRAME" WAIT 1ms
    client <- server UDP SRCPORT 9000 DSTPORT 54000 PAYLOAD "ECHO_PONG_FRAME" WAIT 1ms
}

// INSTRUCTION: Compile the flow for both IPv4 and IPv6 host pairs.
COMPILE {
    udp_echo_exchange(edge_client_v4, edge_server_v4)
    udp_echo_exchange(edge_client_v6, edge_server_v6)
}
```

### 3.2 `FLOW` Declarations & Directional Operators (`->` and `<-`)
A `FLOW` declaration defines a parameterized sequence of frame statements:
- `FLOW <name>(<param1>, <param2>, ...) { ... }`
- Inside a flow, `lhs -> rhs <PROTOCOL> [modifiers...]` transmits a frame from `lhs` (source) to `rhs` (destination).
- Conversely, `lhs <- rhs <PROTOCOL> [modifiers...]` transmits a frame from `rhs` (source) to `lhs` (destination), keeping visual alignment with sequence diagrams while automatically swapping tracked L4 ports.

```frameassembly
// PROMPT: Illustrate bidirectional arrow semantics and automatic TCP sequence and port tracking.
// TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, ACK, PSH, FIN, SRCPORT, DSTPORT, WIN, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare the initiating workstation host.
HOST workstation {
    IP 10.10.1.50
    MAC 00:50:56:a1:01:50
}

// INSTRUCTION: Declare the internal application gateway host.
HOST app_gateway {
    IP 10.10.1.10
    MAC 00:50:56:a1:01:10
}

// INSTRUCTION: Define a complete TCP lifecycle using -> and <- arrows with stateful SEQ/ACK tracking.
FLOW stateful_tcp_session(c, s) {
    c -> s TCP SYN SRCPORT 51234 DSTPORT 8080 SEQ 1000 WIN 65535 WAIT 1ms
    c <- s TCP SYN ACK SEQ 5000 ACKNUM 1001 WIN 65535 WAIT 1ms
    c -> s TCP ACK SEQ 1001 ACKNUM 5001 WIN 65535 WAIT 1ms
    c -> s TCP PSH ACK SEQ 1001 ACKNUM 5001 PAYLOAD "POST /v1/events HTTP/1.1\r\nHost: app.internal\r\n\r\n" WAIT 2ms
    c <- s TCP PSH ACK SEQ 5001 ACKNUM 1049 PAYLOAD "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n" WAIT 2ms
    c -> s TCP FIN ACK SEQ 1049 ACKNUM 5045 WAIT 1ms
    c <- s TCP FIN ACK SEQ 5045 ACKNUM 1050 WAIT 1ms
    c -> s TCP ACK SEQ 1050 ACKNUM 5046 WAIT 1ms
}

// INSTRUCTION: Compile the stateful TCP session.
COMPILE {
    stateful_tcp_session(workstation, app_gateway)
}
```

### 3.3 `COMPILE` and `LOOP` Orchestration
The `COMPILE` block instantiates flows with concrete `HOST` identifiers and supports deterministic `LOOP <count> { ... }` blocks for load testing, heartbeat bursts, and multi-stage traffic generation. Note that `LOOP` is only valid inside `COMPILE { ... }`, never inside `FLOW { ... }`.

```frameassembly
// PROMPT: Multi-flow orchestration and LOOP iteration inside the COMPILE block.
// TOKENS: HOST, IP, MAC, FLOW, ICMP, ECHO_REQUEST, ECHO_REPLY, ID, SEQ, UDP, DSTPORT, PAYLOAD, WAIT, COMPILE, LOOP

// INSTRUCTION: Declare the network monitoring probe host.
HOST net_probe {
    IP 172.16.50.10
    MAC 00:1b:63:84:45:10
}

// INSTRUCTION: Declare the core router loopback interface.
HOST core_router {
    IP 172.16.50.1
    MAC 00:1b:63:84:45:01
}

// INSTRUCTION: Define an ICMP reachability check flow.
FLOW icmp_reachability(probe, router) {
    probe -> router ICMP ECHO_REQUEST ID 901 SEQ 1 PAYLOAD "PREFLIGHT_PING" WAIT 2ms
    probe <- router ICMP ECHO_REPLY ID 901 SEQ 1 PAYLOAD "PREFLIGHT_PING" WAIT 2ms
}

// INSTRUCTION: Define a high-rate UDP jitter measurement burst flow.
FLOW udp_jitter_sample(probe, router) {
    probe -> router UDP SRCPORT 60000 DSTPORT 1967 PAYLOAD "IP_SLA_JITTER_SAMPLE_32B" WAIT 500us
    probe <- router UDP SRCPORT 1967 DSTPORT 60000 PAYLOAD "IP_SLA_JITTER_RETURN_32B" WAIT 500us
}

// INSTRUCTION: Execute the preflight check followed by 10 jitter measurement iterations.
COMPILE {
    icmp_reachability(net_probe, core_router)
    LOOP 10 {
        udp_jitter_sample(net_probe, core_router)
    }
}
```

---

## 4. Universal Cross-Layer Frame Modifiers

FrameAssembly supports attaching L2, L3, L4, timing, and payload modifiers to any frame statement so that upper-layer protocols can be encapsulated inside VLANs, QinQ service tags, MPLS label stacks, QoS DSCP/ECN markings, or IPv4 fragmentation headers:

| Layer | Modifier Syntax | Argument Type | Wire Effect & RFC Standard |
| :--- | :--- | :--- | :--- |
| **L2 Ethernet** | `SRCMAC <mac>` / `DSTMAC <mac>` | 48-bit MAC | Overrides Ethernet II source or destination MAC address (IEEE 802.3) |
| **L2 Ethernet** | `ETHERTYPE <u16>` | `u16` (`0..65535`) | Overrides outer Ethernet II EtherType field |
| **L2 802.1Q** | `VLAN <u16>` | `u16` (`0..4095`) | Inserts IEEE 802.1Q VLAN tag (`0x8100`) with 12-bit VID |
| **L2 802.1p** | `PCP <u8>` / `DEI <u8>` | `u8` (`0..7` / `0..1`) | Sets 3-bit Priority Code Point and 1-bit Drop Eligible Indicator |
| **L2 802.1ad** | `QINQ <u16> INNER_VLAN <u16>` | `u16`, `u16` | Inserts IEEE 802.1ad S-Tag (`0x88A8`) and inner C-Tag (`0x8100`) |
| **L2.5 MPLS** | `MPLS <u20>` or `LABEL <u20>` | `u32` (`0..1048575`) | Inserts MPLS shim header (`0x8847`, RFC 3032) |
| **L2.5 MPLS** | `EXP <u8>` / `BOS <u8>` / `MPLS_TTL <u8>` | `u8` | Sets MPLS Traffic Class (`0..7`), Bottom-of-Stack (`0..1`), and TTL (`0..255`) |
| **L3 IPv4/v6** | `TTL <u8>` | `u8` (`0..255`) | Sets IPv4 Time-to-Live (RFC 791) or IPv6 Hop Limit (RFC 8200) |
| **L3 QoS** | `DSCP <u8>` / `ECN <u8>` | `u8` (`0..63` / `0..3`) | Sets DiffServ Code Point (RFC 2474) and Explicit Congestion Notification (RFC 3168) |
| **L3 IPv4 Frag**| `IPID <u16>` / `DF` / `MF` / `FRAGOFFSET <u16>` | `u16` / flags | Sets IPv4 Identification, DF/MF flags, and 8-byte fragment offset |
| **L3 IPv6** | `FLOWLABEL <u20>` | `u32` (`0..1048575`) | Sets 20-bit IPv6 Flow Label for ECMP multipath hashing (RFC 6437) |
| **L4 Ports** | `SRCPORT <u16>` / `DSTPORT <u16>` | `u16` (`0..65535`) | Overrides TCP, UDP, or SCTP source and destination port numbers |
| **Payload** | `PAYLOAD "<string>"` | Quoted string | Appends UTF-8 / escaped byte payload (`\r`, `\n`, `\t`, `\xHH`) |
| **Payload** | `HEXPAYLOAD "<hex>"` | Quoted hex string | Appends raw binary octets decoded from hexadecimal string |
| **Timing** | `WAIT <n><ns\|us\|ms\|s\|m>` | Duration literal | Advances PCAP capture clock after emitting the frame |

### Example: Multi-Layer Encapsulation (QinQ + MPLS + DSCP + TLS)

```frameassembly
// PROMPT: Carrier metro Ethernet backhaul combining 802.1ad QinQ, MPLS label switching, DiffServ QoS, and TLS 1.3.
// TOKENS: HOST, IP, MAC, FLOW, QINQ, INNER_VLAN, PCP, MPLS, EXP, BOS, MPLS_TTL, DSCP, TTL, TLS, CLIENT_HELLO, SERVER_HELLO, CIPHERSUITE, SNI, ALPN, WAIT, COMPILE

// INSTRUCTION: Declare customer branch CPE gateway.
HOST branch_cpe {
    IP 10.220.1.10
    MAC 00:50:56:c0:01:10
}

// INSTRUCTION: Declare headquarters data center concentrator.
HOST hq_concentrator {
    IP 10.220.1.200
    MAC 00:50:56:c0:01:c8
}

// INSTRUCTION: Define a TLS 1.3 handshake encapsulated in QinQ S-VLAN 2000, C-VLAN 150, and MPLS Label 40960.
FLOW metro_backhaul_tls(cpe, hq) {
    cpe -> hq QINQ 2000 INNER_VLAN 150 PCP 6 MPLS 40960 EXP 6 BOS 1 MPLS_TTL 64 DSCP 46 TTL 64 TLS CLIENT_HELLO SNI "vault.hq.example.com" CIPHERSUITE 4866 ALPN "h2" WAIT 5ms
    cpe <- hq QINQ 2000 INNER_VLAN 150 PCP 6 MPLS 40960 EXP 6 BOS 1 MPLS_TTL 63 DSCP 46 TTL 63 TLS SERVER_HELLO CIPHERSUITE 4866 ALPN "h2" WAIT 5ms
}

// INSTRUCTION: Compile the multi-layer encapsulated flow.
COMPILE {
    metro_backhaul_tls(branch_cpe, hq_concentrator)
}
```

### Example: IPv4 Fragmentation & IPv6 Flow Label Multipath ECMP

```frameassembly
// PROMPT: Demonstrate IPv4 packet fragmentation modifiers and IPv6 20-bit Flow Label ECMP hashing.
// TOKENS: HOST, IP, MAC, FLOW, UDP, SRCPORT, DSTPORT, IPID, MF, FRAGOFFSET, DF, FLOWLABEL, DSCP, ECN, PAYLOAD, WAIT, COMPILE

// INSTRUCTION: Declare IPv4 storage endpoints for fragmented UDP payload transfer.
HOST nfs_client_v4 {
    IP 192.168.80.10
    MAC 00:0c:29:80:00:10
}

// INSTRUCTION: Declare the IPv4 storage server.
HOST nfs_server_v4 {
    IP 192.168.80.20
    MAC 00:0c:29:80:00:20
}

// INSTRUCTION: Declare IPv6 RoCEv2 compute nodes using Flow Labels for spine ECMP spreading.
HOST gpu_node_a {
    IP 2001:db8:fab:1::10
    MAC 00:0c:29:90:00:10
}

// INSTRUCTION: Declare the peer IPv6 GPU compute node.
HOST gpu_node_b {
    IP 2001:db8:fab:1::20
    MAC 00:0c:29:90:00:20
}

// INSTRUCTION: Define an IPv4 fragmented UDP flow followed by an unfragmentable DF response.
FLOW ipv4_fragmented_transfer(c, s) {
    c -> s UDP SRCPORT 41000 DSTPORT 2049 IPID 7788 MF FRAGOFFSET 0 PAYLOAD "FRAGMENT_ONE_1480B_BLOCK" WAIT 1ms
    c -> s UDP SRCPORT 41000 DSTPORT 2049 IPID 7788 FRAGOFFSET 185 PAYLOAD "FRAGMENT_TWO_TAIL_BLOCK" WAIT 1ms
    c <- s UDP SRCPORT 2049 DSTPORT 41000 IPID 7789 DF PAYLOAD "REASSEMBLED_ACK_OK" WAIT 1ms
}

// INSTRUCTION: Define an IPv6 ECMP flow spreading two subflows across distinct 20-bit Flow Labels.
FLOW ipv6_ecmp_subflows(a, b) {
    a -> b UDP SRCPORT 47910 DSTPORT 4791 FLOWLABEL 0x1a2b3 DSCP 26 ECN 2 PAYLOAD "RDMA_WRITE_QP_101" WAIT 500us
    a -> b UDP SRCPORT 47911 DSTPORT 4791 FLOWLABEL 0x9f8e7 DSCP 26 ECN 2 PAYLOAD "RDMA_WRITE_QP_102" WAIT 500us
}

// INSTRUCTION: Compile both the IPv4 fragmentation flow and IPv6 Flow Label ECMP flow.
COMPILE {
    ipv4_fragmented_transfer(nfs_client_v4, nfs_server_v4)
    ipv6_ecmp_subflows(gpu_node_a, gpu_node_b)
}
```

---

## 5. Formal Constrained-Decoding Grammars

To guarantee **zero syntax errors (`0%` hallucination rate)** when synthesizing `.fasm` programs with Large Language Models, FrameAssembly ships three synchronized formal grammar specifications in the repository root:

| Grammar File | Format | Target Inference Engines & Structured Output Frameworks |
| :--- | :--- | :--- |
| [`grammar.ebnf`](../grammar.ebnf) | ISO/IEC 14977 W3C EBNF | Formal specification reference, parser verification, custom grammar compilers |
| [`frameassembly.gbnf`](../frameassembly.gbnf) | GGML BNF (`.gbnf`) | `llama.cpp` (`--grammar-file frameassembly.gbnf`), `vLLM`, `KoboldCpp`, `TabbyAPI` |
| [`frameassembly.lark`](../frameassembly.lark) | Lark Earley / LALR(1) | `Outlines`, `Guidance`, `llguidance`, `XGrammar`, `SGLang`, `lm-format-enforcer`, Python `lark` |

### 5.1 Core Production Hierarchy
All three grammar files enforce the exact lexical and syntactic productions of the Rust compiler:
1. **`program`**: One or more `declaration` blocks (`host_decl` or `flow_decl`) followed by a `compile_block`.
2. **`host_decl`**: `"HOST" IDENTIFIER "{" host_attr+ "}"`, where `host_attr` is `"IP" (IPV4_ADDR | IPV6_ADDR)` or `"MAC" MAC_ADDR`.
3. **`flow_decl`**: `"FLOW" IDENTIFIER "(" param_list ")" "{" statement* "}"`, requiring at least one parameter identifier.
4. **`statement`**: `IDENTIFIER ("->" | "<-") IDENTIFIER modifier+`.
5. **`compile_block`**: `"COMPILE" "{" compile_stmt* "}"`, where `compile_stmt` is either `flow_call` (`IDENTIFIER "(" arg_list ")"`) or `loop_stmt` (`"LOOP" INT_LIT "{" flow_call* "}"`).

### 5.2 Complete 81-Protocol Keyword Inventory
Every protocol keyword recognized by `src/lexer/mod.rs` and `grammar.ebnf` / `frameassembly.gbnf` / `frameassembly.lark` is organized by OSI layer:

- **Layer 2 (8 Protocols)**: `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`
- **Layer 3 (20 Protocols)**: `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`
- **Layer 4 (3 Protocols)**: `TCP`, `UDP`, `SCTP`
- **Layer 7 Management (3 Protocols)**: `SNMP1`, `SNMP2`, `SNMP3`
- **Layer 7 Infrastructure & Telemetry (16 Protocols)**: `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`
- **Layer 7 Web, Cloud, Real-Time & IoT (14 Protocols)**: `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `STUN`, `SIP`, `RTP`, `RTSP`, `MQTT`, `COAP`, `AMQP`, `SSDP`
- **Layer 7 Mail, Auth, Storage & Databases (11 Protocols)**: `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`
- **Layer 7 Industrial OT / ICS / SCADA (6 Protocols)**: `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`

---

## 6. CLI Usage, Verification & Diagnostics

The `frameassembly` binary compiles any `.fasm` file into a binary `.pcap` capture:

```bash
# Build release compiler
cargo build --release

# Compile a single .fasm topology into a binary PCAP file
./target/release/frameassembly examples/topologies/complete_dsl_omnibus_reference.fasm -o omnibus.pcap

# Inspect generated frames with tshark or tcpdump
tshark -r omnibus.pcap -V
```

When a `.fasm` file violates lexical, syntactic, or semantic rules, `miette` renders a source-mapped diagnostic pointing to the exact line and column of the error, enabling automated LLM self-repair loops and rapid human debugging.
