//! **FrameAssembly** (`frameassembly`) is a declarative Domain-Specific Language (DSL) and
//! optimizing Rust compiler that turns plain-text `.fasm` packet recipes into deterministic,
//! nanosecond-accurate `.pcap` and `.pcapng` packet captures across **81 native Layer 2 through
//! Layer 7 protocols**.
//!
//! Built first and foremost for **network engineers, firewall administrators, NOC/SOC analysts,
//! and QA teams who do not write code**, FrameAssembly synthesizes clean, bit-exact capture files
//! in user space with zero root privileges (`CAP_NET_RAW`), zero live sockets, and zero background
//! noise.
//!
//! ## Companion Workflow: FrameAssembly + Wireshark/`tshark` + `tcpreplay`
//!
//! FrameAssembly is a **companion** to your existing packet analysis and replay toolkit—never a
//! replacement for live wire injectors like `tcpreplay`:
//!
//! 1. **Synthesize (`frameassembly`)**: Compile a human-readable `.fasm` specification into a
//!    deterministic `.pcap` / `.pcapng` file with automatic RFC defaults, 4-tuple TCP `SEQ`/`ACK`
//!    progression, bidirectional port inheritance across `->` and `<-`, IPv4/IPv6 dual-stack flow
//!    reuse, and full SNMPv3 USM (`MD5`/`SHA-1`/`SHA-2` + `DES`/`AES`) cryptography.
//! 2. **Inspect (`wireshark` / `tshark`)**: Open the generated `.pcap` in Wireshark or validate
//!    protocol fields in CI pipelines with `tshark -r output.pcap -V`.
//! 3. **Replay (`tcpreplay`)**: Inject the synthesized `.pcap` onto physical or virtual network
//!    interfaces at wire speed using `tcpreplay -i eth0 output.pcap` to test hardware firewalls,
//!    IDS/IPS sensors (Suricata, Zeek, Snort), NMS trap receivers, and SCADA/OT appliances.
//!
//! ## Six-Stage Zero-Copy Compiler Pipeline
//!
//! 1. **Stage 1 — Zero-Copy Lexical Analysis ([`lexer`])**: [`logos`]-powered DFA scanner
//!    ([`lexer::lex`]) recognizing 640+ case-insensitive DSL keywords, all 81 protocols,
//!    nanosecond-to-minute time units (`ns`, `us`, `ms`, `s`, `m`), IPv4/IPv6/MAC literals, and
//!    ASN.1 OIDs without heap string allocations.
//! 2. **Stage 2 — Two-Phase Token-Slice Parsing ([`parser`], [`ast`])**: [`winnow`] combinator
//!    parser ([`parser::parse_program`]) operating over [`parser::Stream`] with protocol-scoped
//!    modifier dispatch so shared sub-keywords never shadow across protocol boundaries.
//! 3. **Stage 3 — Semantic Validation ([`parser::validate_semantics`], [`error`])**: Enforces
//!    case-insensitive symbol uniqueness, flow arity, homogeneous IPv4/IPv6 endpoint pairs, and
//!    IEEE/RFC field bounds with byte-accurate [`miette`] source spans ([`error::CompilerError`]).
//! 4. **Stage 4 — Zero-Heap Wire Builders, Checksums & Crypto ([`builders`], [`packet`])**:
//!    Encapsulates frames inner-outward (`L7 -> L4 -> L3 -> MPLS/QinQ/VLAN/Ethernet II`) with
//!    disjoint-slice RFC 1071 checksums ([`packet::internet_checksum`]), RFC 8200 UDP
//!    `0x0000 -> 0xFFFF` folding, RFC 9260 SCTP Castagnoli CRC32c, IEEE 1815 DNP3 CRC-16, and
//!    RFC 3414/3826/7860 SNMPv3 USM key localization (`Ku -> Kul`), `DES-CBC`/`AES-128-CFB`, and
//!    truncated HMAC signing.
//! 5. **Stage 5 — Stateful 4-Tuple & Bidirectional Port Engine ([`backend`])**: Tracks two-stage
//!    port inheritance across `->` and `<-`, shares canonical 4-tuple TCP sequence/acknowledgment
//!    state across raw `TCP` and L7 protocols, preserves dynamic builder ports/multicast targets,
//!    and derives RFC 1112 (`01:00:5e:xx:xx:xx`) and RFC 2464 (`33:33:xx:xx:xx:xx`) multicast MACs.
//! 6. **Stage 6 — Nanosecond PCAPNG Serialization ([`pcap`])**: Emits `SHB -> IDB -> EPB` blocks
//!    via [`pcap::PcapWriter`] with `LINKTYPE_ETHERNET` and `IfTsResol(9)` (`10^-9`s) resolution.
//!
//! ## Supported Protocol Matrix (81 Native Protocols)
//!
//! | OSI Layer | Count | Supported Protocols |
//! | :--- | :---: | :--- |
//! | **Layer 2 (Data Link & Switching)** | 8 | `ARP`, `VLAN` (802.1Q), `QINQ` (802.1ad), `MPLS`, `LLDP`, `STP` / `RSTP`, `LACP`, `EAPOL` (802.1X) |
//! | **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `ICMP` / `ICMPv6`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW` |
//! | **Layer 4 (Transport)** | 3 | `TCP`, `UDP`, `SCTP` |
//! | **Layer 7 (SNMP, Infra, Time, AAA, Telemetry)** | 14 | `SNMP1`, `SNMP2`, `SNMP3`, `DNS`, `MDNS`, `DHCP` / `DHCPv6`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, `SFLOW` |
//! | **Layer 7 (Web, Cloud, Security, VoIP, Access)** | 16 | `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, `SSDP` |
//! | **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP` |
//! | **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA` |
//!
//! ## Canonical Documentation Guides (`docs/`)
//!
//! * [Getting Started Guide](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/getting_started.md) — Step-by-step tutorial for non-programmers, defaults vs. overrides, automatic TCP `SEQ`/`ACK` & reply ports, and Wireshark/`tshark` + `tcpreplay` workflows.
//! * [Practical Use-Case Cookbook](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/use_cases.md) — Ready-to-run recipes for SNMPv1/v2c/v3 traps, firewall ACL verification, VLAN/QinQ/MPLS QoS tagging, IDS/IPS validation, and OT/SCADA testing.
//! * [Layer 2 Switching & Data-Link Protocols](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l2_protocols.md) — `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, and `MPLS`.
//! * [Layer 3 Control, Tunneling, VPN & Routing](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l3_protocols.md) — `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, and `OPENFLOW`.
//! * [Layer 4 Transports (`TCP`, `UDP`, `SCTP`)](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l4_transports.md) — 4-tuple state tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling.
//! * [Layer 7 SNMPv1, SNMPv2c & SNMPv3 USM](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l7_snmp.md) — USM authentication (`MD5`/`SHA`/`SHA256`/`SHA384`/`SHA512`), privacy (`DES`/`AES`), and all 9 SMI `VARBIND` types.
//! * [Layer 7 Infrastructure, Time, AAA & Telemetry](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l7_infra_and_telemetry.md) — `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `SYSLOG`, `NETFLOW`, `IPFIX`, and `SFLOW`.
//! * [Layer 7 Web, Cloud, Security, VoIP & Remote Access](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l7_web_and_cloud.md) — `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`, `TFTP`, `FTP`, `SSH`, `TELNET`, `WHOIS`, `SIP`, `RTP`, `RTSP`, `STUN`, and `SSDP`.
//! * [Layer 7 Mail, Auth, Storage, Databases & Brokers](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l7_mail_auth_storage_db.md) — `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`, `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, and `AMQP`.
//! * [Layer 7 Industrial Control Systems (ICS) & SCADA/OT](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/l7_industrial_ot.md) — `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, and `OPCUA`.
//! * [Multi-Host Topologies & Dual-Stack IPv4/IPv6 Reuse](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/topologies_and_dual_stack.md) — Enterprise WAN, EVPN-VXLAN data center, and Zero-Trust 802.1X NAC architectures.
//! * [For Nerds: Compiler Internals, Rust API & Formal Grammars](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/for_nerds.md) — Deep dive into the 6-stage zero-copy compiler, public Rust library API, EBNF/GBNF/Lark constrained decoding, and RLVR/SFT corpus design.
//!
//! ## FrameAssembly DSL Syntax Example
//!
//! ```frameassembly
//! // Define the client and HTTP server endpoints
//! HOST client {
//!     IP 10.0.0.10
//!     MAC 00:11:22:33:44:55
//! }
//!
//! HOST web_server {
//!     IP 10.0.0.80
//!     MAC aa:bb:cc:dd:ee:ff
//! }
//!
//! // TCP 3-way handshake followed by an HTTP GET request and 200 OK response
//! FLOW web_session(c, s) {
//!     c -> s TCP SYN SRCPORT 51234 DSTPORT 80 WIN 65535 MSS 1460 WAIT 1ms
//!     c <- s TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
//!     c -> s TCP ACK WAIT 1ms
//!     c -> s HTTP GET URI "/index.html" HOST_HDR "example.com" WAIT 5ms
//!     c <- s HTTP STATUS 200 REASON "OK" BODY "<h1>Hello</h1>" WAIT 2ms
//! }
//!
//! // Build the output capture
//! COMPILE {
//!     web_session(client, web_server)
//! }
//! ```
//!
//! ## Rust Library Quickstart
//!
//! Parse a `.fasm` program and synthesize raw Ethernet frames paired with nanosecond timestamps in memory:
//!
//! ```rust
//! use frameassembly::backend::compile_program;
//! use frameassembly::parser::parse_program;
//!
//! let fasm_source = r#"
//!     HOST sensor { IP 192.168.10.5  MAC 00:1a:2b:3c:4d:5e }
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
//! assert_eq!(packets[1].1 - packets[0].1, 5_000_000); // 5ms delta in nanoseconds
//! ```
//!
//! Inspect structured [`error::CompilerError`] diagnostics and byte-offset spans when validating
//! untrusted `.fasm` input:
//!
//! ```rust
//! use frameassembly::error::CompilerError;
//! use frameassembly::parser::parse_program;
//!
//! let invalid_fasm = r#"
//!     HOST v4_host { IP 10.0.0.1 }
//!     HOST v6_host { IP 2001:db8::1 }
//!     FLOW bad_ping(a, b) { a -> b ICMP ECHO_REQUEST }
//!     COMPILE { bad_ping(v4_host, v6_host) }
//! "#;
//!
//! let err = parse_program(invalid_fasm).expect_err("mixed address families must fail");
//! match err {
//!     CompilerError::SemanticError { message, span, .. } => {
//!         assert!(message.contains("Mixed IPv4 and IPv6 endpoints"));
//!         assert!(span.1 > 0);
//!     }
//!     other => panic!("unexpected error variant: {:?}", other),
//! }
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
