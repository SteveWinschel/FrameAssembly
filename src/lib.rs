//! **FrameAssembly** (`frameassembly` v1.4.3) is an offline, rootless PCAP generator & Packets-as-Code DSL and optimizing compiler that compiles declarative `.fasm` code into deterministic `.pcap` and `.pcapng` packet captures across **81 native Layer 2 through Layer 7 protocols**.
//!
//! * **Canonical Repository & CLI:** [github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly)
//! * **Crates.io Package:** [crates.io/crates/frameassembly](https://crates.io/crates/frameassembly)
//! * **API Documentation:** [docs.rs/frameassembly](https://docs.rs/frameassembly)
//! * **`.fasm` Format Specification (`text/vnd.frameassembly`):** [`docs/fasm-specification.md`](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md)
//!
//! Whether you are testing firewall ACLs, simulating SNMPv3 traps, validating Suricata/Zeek IDS
//! rules, or verifying VLAN/QinQ/MPLS QoS markings, generating custom network traffic manually is
//! tedious—requiring lab hardware, manual fault triggers, raw-socket privileges (`CAP_NET_RAW`),
//! or manual TCP `SEQ`/`ACK` math in `Scapy`. FrameAssembly solves this for **network engineers,
//! firewall administrators, NOC/SOC analysts, OT/SCADA integrators, and CI pipelines** with a few
//! lines of `.fasm` code and two CLI commands: compile bit-exact capture files offline in
//! unprivileged user space (no root, no live raw sockets, no `libpcap`) and replay or inspect with
//! **`tcpreplay`**, **Wireshark**, **`tshark`**, **Suricata**, or **Zeek**.
//!
//! ## Upstream Companion Workflow: FrameAssembly $\rightarrow$ Wireshark / `tshark` / `tcpreplay` / IDS
//!
//! FrameAssembly is the **upstream packet-crafting compiler** in your network testing and analysis
//! pipeline—never a competitor to packet analyzers or live wire injectors:
//!
//! 1. **Compile (`frameassembly` / `frameassembly show`)**: Turn a declarative `.fasm`
//!    ("Packets as Code") specification into a deterministic `.pcap` / `.pcapng` file with automatic
//!    RFC defaults, 4-tuple TCP `SEQ`/`ACK` progression, bidirectional port inheritance across
//!    `->` and `<-`, IPv4/IPv6 dual-stack flow reuse, and full SNMPv3 USM (`MD5`/`SHA-1`/`SHA-2` +
//!    `DES`/`AES`) cryptography—or preview the packet ladder in the terminal with
//!    `frameassembly show demo.fasm`.
//! 2. **Inspect & Dissect (`Wireshark` / `tshark`)**: Open the generated `.pcap` in Wireshark or
//!    assert protocol fields in automated CI pipelines with `tshark -r output.pcap -V`.
//! 3. **Replay & Validate (`tcpreplay` / `Suricata` / `Zeek`)**: Inject the synthesized `.pcap`
//!    onto physical or virtual network interfaces at wire speed using `tcpreplay -i eth0 output.pcap`
//!    to test hardware firewalls, IDS/IPS sensors (**Suricata**, **Zeek**, **Snort**), NMS trap
//!    receivers, and industrial SCADA/OT appliances.
//!
//! ## Packet-Crafting Generator Comparison (`FrameAssembly` vs. `Scapy`, `text2pcap`, `Ostinato`)
//!
//! | Capability | **FrameAssembly (`.fasm`)** | **Python + `Scapy`** | **`text2pcap` (Hex Dumps)** | **`Ostinato` (GUI / Streams)** |
//! | :--- | :--- | :--- | :--- | :--- |
//! | **Primary Interface** | Declarative `.fasm` code (`1 line = 1 frame`) | Imperative Python scripts & classes | Raw hexadecimal byte offsets | Desktop GUI & stream dialogs |
//! | **Target Audience** | Network/firewall engineers & CI pipelines | Python developers & researchers | Analysts editing hex dumps | Desktop lab engineers |
//! | **Rootless / Offline** | Offline user space (no `libpcap` or raw sockets) | Requires Python + root for wire send | Offline user space | Requires daemon / agent setup |
//! | **TCP `SEQ`/`ACK` & Ports** | Automatic 4-tuple `SEQ`/`ACK` & `<-` port swap | Manual per-packet sequence math | Manual hex recalculation | Manual per-stream configuration |
//! | **SNMPv3 `authPriv` USM** | Built-in RFC 3414/3826/7860 `SHA-2` + `AES`/`DES` | Manual ASN.1 BER & crypto code | Impractical by hand | Not built-in |
//! | **Version Control ("Packets as Code")** | Clean, diffable UTF-8 `.fasm` code | Code scripts coupled to Python env | Opaque hex blobs | Binary/protobuf stream files |
//!
//! ## Common Network Testing Scenarios
//!
//! ### 1. Generate Custom Network Traffic & Protocol Exchanges Without Raw Sockets
//!
//! Instead of setting up a Python environment for `Scapy`, requesting `CAP_NET_RAW` root privileges, or calculating hexadecimal byte offsets in `text2pcap`, write your hosts and packet lines in `.fasm` code and compile directly to `.pcap` in unprivileged user space:
//!
//! ```frameassembly
//! HOST client { IP 192.168.1.100 }
//! HOST server { IP 8.8.8.8 }
//! FLOW dns_resolve(c, s) {
//!     c -> s DNS QUERY TXID 0x1a2b QNAME "example.com" QTYPE "A"
//!     c <- s DNS RESPONSE TXID 0x1a2b QNAME "example.com" QTYPE "A" RDATA "93.184.216.34"
//! }
//! COMPILE { dns_resolve(client, server) }
//! ```
//!
//! ```console
//! $ frameassembly dns.fasm -o dns.pcap
//! ```
//!
//! ### 2. Simulate SNMPv1/v2c & Encrypted SNMPv3 `authPriv` Traps Without Touching Live Gear
//!
//! Simulating SNMP traps to verify Zabbix, SolarWinds, LibreNMS, PRTG, or `snmptrapd` alerting rules normally requires configuring agent credentials, loading MIB files, and manually triggering faults on a switch. FrameAssembly replaces that with a few lines of `.fasm` code (performing RFC 3414/3826/7860 USM key localization `Ku -> Kul`, HMAC signing, and `DES-CBC`/`AES-128-CFB` encryption automatically) and two CLI commands:
//!
//! ```frameassembly
//! HOST router { IP 10.151.0.1 }
//! HOST soc    { IP 10.151.0.250 }
//! FLOW snmpv3_trap(r, s) {
//!     r -> s SNMP3 TRAP USER "admin" ENGINEID "80001f8880510001" AUTH SHA256 "authpass123" PRIV AES "privpass123" OID 1.3.6.1.6.3.1.1.5.3
//! }
//! COMPILE { snmpv3_trap(router, soc) }
//! ```
//!
//! ```console
//! $ frameassembly trap.fasm -o trap.pcap && tcpreplay -i eth0 trap.pcap
//! ```
//!
//! ### 3. Test 802.1Q `VLAN` Trunks, 802.1ad `QinQ`, `MPLS` & `DSCP` QoS Queues
//!
//! Desktop OS network stacks and NIC drivers often strip 802.1Q VLAN tags and block raw-socket injection of carrier `QinQ` double tags or custom DiffServ markings. FrameAssembly writes inner and outer VLAN tags, MPLS label stacks, and `DSCP` priority bits directly into the `.pcap` file:
//!
//! ```frameassembly
//! HOST hub    { IP 10.99.1.1 }
//! HOST branch { IP 10.99.1.2 }
//! FLOW qinq_flow(h, b) {
//!     h -> b QINQ 850 INNER_VLAN 12 ICMP ECHO_REQUEST
//!     h <- b QINQ 850 INNER_VLAN 12 ICMP ECHO_REPLY
//! }
//! COMPILE { qinq_flow(hub, branch) }
//! ```
//!
//! ```console
//! $ frameassembly trunk.fasm -o trunk.pcap && tshark -r trunk.pcap -V
//! ```
//!
//! ### 4. Validate Firewall ACLs & Suricata / Zeek / Snort IDS Rules
//!
//! Stateful firewalls and IDS engines drop isolated packets that lack a valid 3-way TCP handshake or sequence progression. FrameAssembly tracks 4-tuple TCP `SEQ`/`ACK` progression and bidirectional port inheritance across `->` and `<-` automatically:
//!
//! ```frameassembly
//! HOST client { IP 192.168.1.10 }
//! HOST server { IP 192.168.1.80 }
//! FLOW ids_probe(c, s) {
//!     c -> s TCP SYN SRCPORT 49152 DSTPORT 80 WIN 65535 MSS 1460 WAIT 1ms
//!     c <- s TCP SYN ACK WIN 65535 MSS 1460 WAIT 1ms
//!     c -> s TCP ACK WAIT 1ms
//!     c -> s HTTP GET URI "/malicious-probe" HOST_HDR "target.local" WAIT 5ms
//!     c <- s HTTP STATUS 403 REASON "Forbidden" BODY "Blocked" WAIT 2ms
//! }
//! COMPILE { ids_probe(client, server) }
//! ```
//!
//! ```console
//! $ frameassembly ids_test.fasm -o ids_test.pcap && suricata -r ids_test.pcap
//! ```
//!
//! ### 5. Reproduce Customer Incidents & Sanitize Captures for Vendor TAC Tickets
//!
//! Instead of scrubbing production PCAPs and risking leaked internal IPs or customer payloads, write a clean `.fasm` reproducer containing only the relevant protocol exchange:
//!
//! ```frameassembly
//! HOST client { IP 10.0.0.10 }
//! HOST radius { IP 10.0.0.1 }
//! FLOW auth_lifecycle(c, r) {
//!     c -> r RADIUS ACCESS_REQUEST USER "alice" NAS_IP 10.0.0.10
//!     c <- r RADIUS ACCESS_ACCEPT
//! }
//! COMPILE { auth_lifecycle(client, radius) }
//! ```
//!
//! ```console
//! $ frameassembly tac_ticket.fasm -o sanitized.pcap
//! ```
//!
//! ### 6. Test Industrial OT / SCADA Firewalls Without a Live PLC
//!
//! Generate bit-accurate Modbus TCP, IEEE 1815 DNP3 (with automatic CRC-16), Siemens S7comm, BACnet/IP, EtherNet/IP, and OPC UA frames without physical PLCs or simulator VMs:
//!
//! ```frameassembly
//! HOST scada_master   { IP 10.200.1.10 }
//! HOST rtu_outstation { IP 10.200.1.50 }
//! FLOW dnp3_poll(m, o) {
//!     m -> o DNP3 FUNC "READ" SRC 10 DST 20 GROUP 1 VARIATION 2
//! }
//! COMPILE { dnp3_poll(scada_master, rtu_outstation) }
//! ```
//!
//! ```console
//! $ frameassembly ot_test.fasm -o ot_test.pcap && tshark -r ot_test.pcap -Y dnp3
//! ```
//!
//! ## `.fasm` File Extension & Media Type Disambiguation (`text/vnd.frameassembly`)
//!
//! `.fasm` is the permanent file extension for FrameAssembly network packet specifications
//! (IANA vendor media type `text/vnd.frameassembly`, specified in
//! [`docs/fasm-specification.md`](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md)).
//! FrameAssembly `.fasm` files (`HOST`, `FLOW`, `COMPILE`, `->`, `<-`, `//` comments) are completely
//! distinct from unregistered x86 Flat Assembler source files (`; ` comments, `format PE`/`ELF`, x86
//! mnemonics) and SymbiFlow/F4PGA FPGA bitstream assembly files (`#` comments, hardware tile bit paths).
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
//! * [Getting Started Guide](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/getting_started.md) — Step-by-step tutorial to writing `.fasm` code, defaults vs. overrides, automatic TCP `SEQ`/`ACK` & reply ports, and Wireshark/`tshark` + `tcpreplay` workflows.
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
//! * [`.fasm` File Format & Media Type Specification (`text/vnd.frameassembly`)](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md) — Normative RFC 6838 media type specification, UTF-8 encoding, lexical magic rules, `.fasm` extension disambiguation, and Wikidata/IANA mappings.
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
