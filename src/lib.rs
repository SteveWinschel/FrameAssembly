//! **FrameAssembly** (`frameassembly`) is a deterministic network packet crafting Domain-Specific Language (DSL) and optimizing Rust compiler that synthesizes nanosecond-accurate `.pcap` and `.pcapng` packet captures across 81 native Layer 2 through Layer 7 protocols.
//!
//! Designed for network protocol engineering, intrusion detection system (IDS/IPS) validation,
//! deep packet inspection (DPI) testing, firewall verification, and high-fidelity synthetic
//! network telemetry generation, FrameAssembly compiles declarative `.fasm` topology and flow
//! specifications directly into standards-compliant wire frames without requiring root privileges
//! or live network interfaces.
//!
//! ## Compiler Architecture
//!
//! 1. **Lexical Analysis ([`lexer`])**: Zero-copy [`logos`]-based tokenizer recognizing all 81
//!    protocols, L2–L7 field modifiers, nanosecond timing suffixes, MAC/IPv4/IPv6 literals, and OIDs.
//! 2. **Syntactic & Semantic Analysis ([`parser`])**: Two-phase [`winnow`] combinator parser and
//!    semantic validator enforcing single-address-family endpoint invariants, IEEE/RFC field ranges,
//!    and protocol-scoped modifier disambiguation with rich [`miette`] source spans.
//! 3. **Stateful Backend & Wire Emission ([`backend`], [`builders`], [`packet`], [`pcap`])**:
//!    Tracks two-stage port inheritance, canonical 4-tuple TCP sequence/acknowledgment progression,
//!    RFC 1112 / RFC 2464 multicast MAC derivation, RFC 1071 checksums, and SNMPv3 USM (MD5/SHA-1/SHA-2
//!    HMAC + DES/AES encryption) before emitting nanosecond-resolution PCAPNG Enhanced Packet Blocks.
//!
//! ## Supported Protocol Matrix (81 Protocols)
//!
//! | OSI Layer | Count | Supported Protocols |
//! | :--- | :---: | :--- |
//! | **Layer 2 (Data Link)** | 8 | `ARP`, `VLAN` (802.1Q), `QINQ` (802.1ad), `MPLS`, `LLDP`, `STP` / `RSTP`, `LACP`, `EAPOL` (802.1X) |
//! | **Layer 3 (Network, Tunnel, Routing)** | 19 | `ICMP` / `ICMPv6`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW` |
//! | **Layer 4 (Transport)** | 3 | `TCP`, `UDP`, `SCTP` |
//! | **Layer 7 (Infrastructure & Telemetry)** | 14 | `DNS`, `MDNS`, `DHCP` / `DHCPv6`, `NTP`, `PTP`, `SNMP1`, `SNMP2`, `SNMP3`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW` |
//! | **Layer 7 (Application, Web, VoIP, DB)** | 31 | `TFTP`, `FTP`, `SSH`, `TELNET`, `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `STUN`, `SIP`, `RTP`, `RTSP`, `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`, `SSDP`, `WHOIS` |
//! | **Layer 7 (Industrial SCADA / OT)** | 6 | `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA` |
//!
//! ## FrameAssembly DSL Syntax Example
//!
//! ```frameassembly
//! // PROMPT: Three-way TCP handshake followed by an HTTP GET request and 200 OK response
//! // TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, ACK, HTTP, GET, URI, HOST_HDR, STATUS, REASON, BODY, WAIT, ms, COMPILE
//!
//! // INSTRUCTION: Define the client and web server IPv4 endpoints
//! HOST client {
//!     IP 10.0.0.10
//!     MAC 00:11:22:33:44:55
//! }
//!
//! // INSTRUCTION: Define the target HTTP server endpoint
//! HOST web_server {
//!     IP 10.0.0.80
//!     MAC aa:bb:cc:dd:ee:ff
//! }
//!
//! // INSTRUCTION: Define the stateful TCP handshake and HTTP request/response flow
//! FLOW web_session(c, s) {
//!     c -> s TCP SYN SRCPORT 51234 DSTPORT 80 WIN 65535 MSS 1460 WAIT 1ms
//!     c <- s TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
//!     c -> s TCP ACK WAIT 1ms
//!     c -> s HTTP GET URI "/index.html" HOST_HDR "example.com" WAIT 5ms
//!     c <- s HTTP STATUS 200 REASON "OK" BODY "<h1>Hello</h1>" WAIT 2ms
//! }
//!
//! // INSTRUCTION: Compile the flow into the output capture
//! COMPILE {
//!     web_session(client, web_server)
//! }
//! ```
//!
//! ## Rust Library Quickstart
//!
//! Parse a `.fasm` program and compile it into raw wire frames and nanosecond timestamps in memory:
//!
//! ```rust
//! use frameassembly::parser::parse_program;
//! use frameassembly::backend::compile_program;
//!
//! let fasm_source = r#"
//!     HOST sensor { IP 192.168.10.5 MAC 00:1a:2b:3c:4d:5e }
//!     HOST plc    { IP 192.168.10.20 MAC 00:1a:2b:3c:4d:5f }
//!
//!     FLOW modbus_poll(c, s) {
//!         c -> s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS ADDR 100 COUNT 4 WAIT 5ms
//!         c <- s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS IS_RESPONSE VALUE 42 WAIT 5ms
//!     }
//!
//!     COMPILE {
//!         modbus_poll(sensor, plc)
//!     }
//! "#;
//!
//! let program = parse_program(fasm_source).expect("valid FrameAssembly program");
//! let packets = compile_program(&program).expect("successful packet synthesis");
//! assert_eq!(packets.len(), 2);
//! assert!(packets[0].0.len() > 54);
//! ```

extern crate alloc;

pub mod ast;
pub mod backend;
pub mod builders;
pub mod error;
pub mod lexer;
pub mod packet;
pub mod parser;
pub mod pcap;
/// SNMP packet builder (backwards compatibility alias).
pub use builders::snmp::builder as snmp_builder;
/// SNMPv3 Cryptography (backwards compatibility alias).
pub use builders::snmp::crypto as snmp_crypto;
