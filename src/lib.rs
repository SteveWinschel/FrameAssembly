//! **FrameAssembly** (`frameassembly` v3.0.0) is an offline, rootless PCAP generator & Packets-as-Code DSL and optimizing compiler that compiles declarative `.frasm` code into deterministic `.pcap` and `.pcapng` packet captures—and decompiles `.pcap` / `.pcapng` captures back into canonical `.frasm` code—across **81 native Layer 2 through Layer 7 protocols**.
//!
//! * **Official Website & Browser Playground:** [frameassembly.ai.studio](https://frameassembly.ai.studio/) (compile `.frasm` <-> `.pcap`/`.pcapng` and inspect packets in the browser with zero install)
//! * **Canonical Repository & CLI:** [github.com/SteveWinschel/FrameAssembly](https://github.com/SteveWinschel/FrameAssembly)
//! * **Crates.io Package:** [crates.io/crates/frameassembly](https://crates.io/crates/frameassembly)
//! * **API Documentation:** [docs.rs/frameassembly](https://docs.rs/frameassembly)
//! * **`.frasm` Format Specification (`text/vnd.frameassembly`):** [`docs/12_frasm_specification.md`](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/12_frasm_specification.md)
//!
//! Whether you are testing firewall ACLs, simulating SNMPv3 traps, validating Suricata/Zeek IDS
//! rules, or verifying VLAN/QinQ/MPLS QoS markings, generating custom network traffic manually is
//! tedious—requiring lab hardware, manual fault triggers, raw-socket privileges (`CAP_NET_RAW`),
//! or manual TCP `SEQ`/`ACK` math in `Scapy`. FrameAssembly solves this for **network engineers,
//! firewall administrators, NOC/SOC analysts, OT/SCADA integrators, and CI pipelines** with a few
//! lines of `.frasm` code and two CLI commands: compile bit-exact capture files offline in
//! unprivileged user space (no root, no live raw sockets, no `libpcap`) and replay or inspect with
//! **`tcpreplay`**, **Wireshark**, **`tshark`**, **Suricata**, or **Zeek**.
//!
//! ## Upstream Companion Workflow: FrameAssembly $\rightarrow$ Wireshark / `tshark` / `tcpreplay` / IDS
//!
//! FrameAssembly is the **upstream packet-crafting compiler** in your network testing and analysis
//! pipeline—never a competitor to packet analyzers or live wire injectors:
//!
//! 1. **Compile, Inspect & Decompile (`frameassembly` / `frameassembly show` / `frameassembly reverse`)**: Turn a declarative `.frasm`
//!    ("Packets as Code") specification into a deterministic `.pcap` / `.pcapng` file with automatic
//!    RFC defaults, 4-tuple TCP `SEQ`/`ACK` progression, bidirectional port inheritance across
//!    `->` and `<-`, IPv4/IPv6 dual-stack flow reuse, and full SNMPv3 USM (`MD5`/`SHA-1`/`SHA-2` +
//!    `DES`/`AES`) cryptography (`frameassembly demo.frasm output.pcap`)—preview the packet
//!    ladder in the terminal with `frameassembly show demo.frasm`, or decompile an existing `.pcap` /
//!    `.pcapng` capture back into canonical `.frasm` code with `frameassembly reverse capture.pcap`.
//! 2. **Inspect & Dissect (`Wireshark` / `tshark`)**: Open the generated `.pcap` in Wireshark or
//!    assert protocol fields in automated CI pipelines with `tshark -r output.pcap -V`.
//! 3. **Replay & Validate (`tcpreplay` / `Suricata` / `Zeek`)**: Inject the synthesized `.pcap`
//!    onto physical or virtual network interfaces at wire speed using `tcpreplay -i eth0 output.pcap`
//!    to test hardware firewalls, IDS/IPS sensors (**Suricata**, **Zeek**, **Snort**), NMS trap
//!    receivers, and industrial SCADA/OT appliances.
//!
//! ## Packet-Crafting Generator Comparison (`FrameAssembly` vs. `Scapy`, `text2pcap`, `Ostinato`)
//!
//! | Capability | **FrameAssembly (`.frasm`)** | **Python + `Scapy`** | **`text2pcap` (Hex Dumps)** | **`Ostinato` (GUI / Streams)** |
//! | :--- | :--- | :--- | :--- | :--- |
//! | **Primary Interface** | Declarative `.frasm` code (`1 line = 1 frame`) | Imperative Python scripts & classes | Raw hexadecimal byte offsets | Desktop GUI & stream dialogs |
//! | **Target Audience** | Network/firewall engineers & CI pipelines | Python developers & researchers | Analysts editing hex dumps | Desktop lab engineers |
//! | **Rootless / Offline** | Offline user space (no `libpcap` or raw sockets) | Requires Python + root for wire send | Offline user space | Requires daemon / agent setup |
//! | **TCP `SEQ`/`ACK` & Ports** | Automatic 4-tuple `SEQ`/`ACK` & `<-` port swap | Manual per-packet sequence math | Manual hex recalculation | Manual per-stream configuration |
//! | **SNMPv3 `authPriv` USM** | Built-in RFC 3414/3826/7860 `SHA-2` + `AES`/`DES` | Manual ASN.1 BER & crypto code | Impractical by hand | Not built-in |
//! | **Version Control ("Packets as Code")** | Clean, diffable UTF-8 `.frasm` code | Code scripts coupled to Python env | Opaque hex blobs | Binary/protobuf stream files |
//!
//! ## Common Network Testing Scenarios
//!
//! ### 1. Generate Custom Network Traffic & Protocol Exchanges Without Raw Sockets
//!
//! Instead of setting up a Python environment for `Scapy`, requesting `CAP_NET_RAW` root privileges, or calculating hexadecimal byte offsets in `text2pcap`, write your hosts and packet lines in `.frasm` code and compile directly to `.pcap` in unprivileged user space:
//!
//! ```frameassembly
//! host client { ip 192.168.1.100 }
//! host server { ip 8.8.8.8 }
//! flow dns_resolve(c, s) {
//!     c -> s dns query txid 0x1a2b qname "example.com" qtype "A"
//!     c <- s dns response txid 0x1a2b qname "example.com" qtype "A" rdata "93.184.216.34"
//! }
//! compile { dns_resolve(client, server) }
//! ```
//!
//! ```console
//! $ frameassembly dns.frasm dns.pcap
//! ```
//!
//! ### 2. Simulate SNMPv1/v2c & Encrypted SNMPv3 `authPriv` Traps Without Touching Live Gear
//!
//! Simulating SNMP traps to verify Zabbix, SolarWinds, LibreNMS, PRTG, or `snmptrapd` alerting rules normally requires configuring agent credentials, loading MIB files, and manually triggering faults on a switch. FrameAssembly replaces that with a few lines of `.frasm` code (performing RFC 3414/3826/7860 USM key localization `Ku -> Kul`, HMAC signing, and `DES-CBC`/`AES-128-CFB` encryption automatically) and two CLI commands:
//!
//! ```frameassembly
//! host router { ip 10.151.0.1 }
//! host soc    { ip 10.151.0.250 }
//! flow snmpv3_trap(r, s) {
//!     r -> s snmp3 trap user "admin" engineid "80001f8880510001" auth sha256 "authpass123" priv aes "privpass123" oid 1.3.6.1.6.3.1.1.5.3
//! }
//! compile { snmpv3_trap(router, soc) }
//! ```
//!
//! ```console
//! $ frameassembly trap.frasm trap.pcap && tcpreplay -i eth0 trap.pcap
//! ```
//!
//! ### 3. Test 802.1Q `vlan` Trunks, 802.1ad `qinq`, `mpls` & `dscp` QoS Queues
//!
//! Desktop OS network stacks and NIC drivers often strip 802.1Q VLAN tags and block raw-socket injection of carrier `qinq` double tags or custom DiffServ markings. FrameAssembly writes inner and outer VLAN tags, MPLS label stacks, and `dscp` priority bits directly into the `.pcap` file:
//!
//! ```frameassembly
//! host hub    { ip 10.99.1.1 }
//! host branch { ip 10.99.1.2 }
//! flow qinq_flow(h, b) {
//!     h -> b qinq 850 innervlan 12 icmp echorequest
//!     h <- b qinq 850 innervlan 12 icmp echoreply
//! }
//! compile { qinq_flow(hub, branch) }
//! ```
//!
//! ```console
//! $ frameassembly trunk.frasm trunk.pcap && tshark -r trunk.pcap -V
//! ```
//!
//! ### 4. Validate Firewall ACLs & Suricata / Zeek / Snort IDS Rules
//!
//! Stateful firewalls and IDS engines drop isolated packets that lack a valid 3-way TCP handshake or sequence progression. FrameAssembly tracks 4-tuple TCP `SEQ`/`ACK` progression and bidirectional port inheritance across `->` and `<-` automatically:
//!
//! ```frameassembly
//! host client { ip 192.168.1.10 }
//! host server { ip 192.168.1.80 }
//! flow ids_probe(c, s) {
//!     c -> s tcp syn srcport 49152 dstport 80 win 65535 mss 1460 wait 1ms
//!     c <- s tcp syn ack win 65535 mss 1460 wait 1ms
//!     c -> s tcp ack wait 1ms
//!     c -> s http get uri "/malicious-probe" hosthdr "target.local" wait 5ms
//!     c <- s http status 403 reason "Forbidden" body "Blocked" wait 2ms
//! }
//! compile { ids_probe(client, server) }
//! ```
//!
//! ```console
//! $ frameassembly ids_test.frasm ids_test.pcap && suricata -r ids_test.pcap
//! ```
//!
//! ### 5. Reproduce Customer Incidents & Sanitize Captures for Vendor TAC Tickets
//!
//! Instead of scrubbing production PCAPs and risking leaked internal IPs or customer payloads, write a clean `.frasm` reproducer containing only the relevant protocol exchange:
//!
//! ```frameassembly
//! host client { ip 10.0.0.10 }
//! host radius { ip 10.0.0.1 }
//! flow auth_lifecycle(c, r) {
//!     c -> r radius accessrequest user "alice" nasip 10.0.0.10
//!     c <- r radius accessaccept
//! }
//! compile { auth_lifecycle(client, radius) }
//! ```
//!
//! ```console
//! $ frameassembly tac_ticket.frasm sanitized.pcap
//! ```
//!
//! ### 6. Test Industrial OT / SCADA Firewalls Without a Live PLC
//!
//! Generate bit-accurate Modbus TCP, IEEE 1815 DNP3 (with automatic CRC-16), Siemens S7comm, BACnet/IP, EtherNet/IP, and OPC UA frames without physical PLCs or simulator VMs:
//!
//! ```frameassembly
//! host scada_master   { ip 10.200.1.10 }
//! host rtu_outstation { ip 10.200.1.50 }
//! flow dnp3_poll(m, o) {
//!     m -> o dnp3 read src 10 dst 20 group 1 variation 2
//! }
//! compile { dnp3_poll(scada_master, rtu_outstation) }
//! ```
//!
//! ```console
//! $ frameassembly ot_test.frasm ot_test.pcap && tshark -r ot_test.pcap -Y dnp3
//! ```
//!
//! ## `.frasm` File Extension & Media Type Disambiguation (`text/vnd.frameassembly`)
//!
//! `.frasm` is the canonical file extension for FrameAssembly network packet specifications
//! (IANA vendor media type `text/vnd.frameassembly`, specified in
//! [`docs/12_frasm_specification.md`](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/12_frasm_specification.md)).
//! FrameAssembly `.frasm` files (`host`, `flow`, `compile`, `->`, `<-`, `//` comments) are completely
//! distinct from x86 Flat Assembler `.fasm` source files (`; ` comments, `format PE`/`ELF`, x86
//! mnemonics) and SymbiFlow/F4PGA FPGA `.fasm` bitstream assembly files (`#` comments, hardware tile bit paths).
//!
//! ## Six-Stage Zero-Copy Compiler Pipeline
//!
//! 1. **Stage 1 — Zero-Copy Lexical Analysis ([`lexer`])**: [`logos`]-powered DFA scanner
//!    ([`lexer::lex`]) recognizing 640+ strict-lowercase `[a-z0-9]+` DSL keywords, all 81 protocols,
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
//!    state across raw `tcp` and L7 protocols, preserves dynamic builder ports/multicast targets,
//!    and derives RFC 1112 (`01:00:5e:xx:xx:xx`) and RFC 2464 (`33:33:xx:xx:xx:xx`) multicast MACs.
//! 6. **Stage 6 — Nanosecond PCAPNG Serialization ([`pcap`]) & 5-Stage Reverse PCAP Decompiler ([`reverse`])**: Emits `SHB -> IDB -> EPB` blocks
//!    via [`pcap::PcapWriter`] with `LINKTYPE_ETHERNET` and `IfTsResol(9)` (`10^-9`s) resolution,
//!    and decompiles `.pcap` / `.pcapng` captures into canonical `.frasm` code via
//!    [`reverse::reverse_pcap_reader`], [`reverse::reverse_pcap_bytes`], and
//!    [`reverse::reverse_pcap_file`] across a 5-stage reverse pipeline (`container.rs`,
//!    `topology.rs`, `oracle.rs`, `shadow_emit.rs`, and `src/reverse/{l2,l3,l4,l7}/<protocol>.rs`)
//!    with per-packet self-checking compiler oracle verification.
//!
//! ## Supported Protocol Matrix (81 Native Protocols)
//!
//! | OSI Layer | Count | Supported Protocols |
//! | :--- | :---: | :--- |
//! | **Layer 2 (Data Link & Switching)** | 8 | `arp`, `vlan` (802.1Q), `qinq` (802.1ad), `mpls`, `lldp`, `stp` / `rstp`, `lacp`, `eapol` (802.1X) |
//! | **Layer 3 (Control, Tunnel, VPN, Routing)** | 20 | `icmp` / `ICMPv6`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow` |
//! | **Layer 4 (Transport)** | 3 | `tcp`, `udp`, `sctp` |
//! | **Layer 7 (SNMP, Infra, Time, AAA, Telemetry)** | 14 | `snmp1`, `snmp2`, `snmp3`, `dns`, `mdns`, `dhcp` / `DHCPv6`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow` |
//! | **Layer 7 (Web, Cloud, Security, VoIP, Access)** | 16 | `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, `ssdp` |
//! | **Layer 7 (Mail, Auth, Storage, DB, Brokers)** | 14 | `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp` |
//! | **Layer 7 (Industrial ICS / SCADA / OT)** | 6 | `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua` |
//!
//! ## Canonical Documentation Guides (`docs/`)
//!
//! * [Getting Started Guide](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/01_getting_started.md) — Step-by-step tutorial to writing `.frasm` code, defaults vs. overrides, automatic TCP `SEQ`/`ACK` & reply ports, and Wireshark/`tshark` + `tcpreplay` workflows.
//! * [Practical Use-Case Cookbook](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/02_use_cases.md) — Ready-to-run recipes for SNMPv1/v2c/v3 traps, firewall ACL verification, VLAN/QinQ/MPLS QoS tagging, IDS/IPS validation, and OT/SCADA testing.
//! * [Layer 2 Switching & Data-Link Protocols](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/03_l2_protocols.md) — `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, and `mpls`.
//! * [Layer 3 Control, Tunneling, VPN & Routing](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/04_l3_protocols.md) — `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, and `openflow`.
//! * [Layer 4 Transports (`tcp`, `udp`, `sctp`)](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/05_l4_transports.md) — 4-tuple state tracking, RFC 7323 TCP options, and SCTP multi-chunk signaling.
//! * [Layer 7 SNMPv1, SNMPv2c & SNMPv3 USM](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/06_l7_snmp.md) — USM authentication (`md5`/`sha`/`sha256`/`sha384`/`sha512`), privacy (`des`/`aes`), and all 9 SMI `varbind` types.
//! * [Layer 7 Infrastructure, Time, AAA & Telemetry](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/07_l7_infra_and_telemetry.md) — `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, and `sflow`.
//! * [Layer 7 Web, Cloud, Security, VoIP & Remote Access](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/08_l7_web_and_cloud.md) — `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `tftp`, `ftp`, `ssh`, `telnet`, `whois`, `sip`, `rtp`, `rtsp`, `stun`, and `ssdp`.
//! * [Layer 7 Mail, Auth, Storage, Databases & Brokers](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/09_l7_mail_auth_storage_db.md) — `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, and `amqp`.
//! * [Layer 7 Industrial Control Systems (ICS) & SCADA/OT](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/10_l7_industrial_ot.md) — `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, and `opcua`.
//! * [Multi-Host Topologies & Dual-Stack IPv4/IPv6 Reuse](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/11_topologies_and_dual_stack.md) — Enterprise WAN, EVPN-VXLAN data center, and Zero-Trust 802.1X NAC architectures.
//! * [`.frasm` File Format & Media Type Specification (`text/vnd.frameassembly`)](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/12_frasm_specification.md) — Normative RFC 6838 media type specification, UTF-8 encoding, lexical magic rules, `.frasm` extension disambiguation, and Wikidata/IANA mappings.
//! * [For Nerds: Compiler Internals, Rust API & Formal Grammars](https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/13_for_nerds.md) — Deep dive into the 6-stage zero-copy compiler, public Rust library API, EBNF/GBNF/Lark constrained decoding, and RLVR/SFT corpus design.
//!
//! ## FrameAssembly DSL Syntax Example
//!
//! ```frameassembly
//! // Define the client and HTTP server endpoints
//! host client {
//!     ip 10.0.0.10
//!     mac 00:11:22:33:44:55
//! }
//!
//! host web_server {
//!     ip 10.0.0.80
//!     mac aa:bb:cc:dd:ee:ff
//! }
//!
//! // TCP 3-way handshake followed by an HTTP GET request and 200 OK response
//! flow web_session(c, s) {
//!     c -> s tcp syn srcport 51234 dstport 80 win 65535 mss 1460 wait 1ms
//!     c <- s tcp syn ack win 65535 mss 1460 wait 1ms
//!     c -> s tcp ack wait 1ms
//!     c -> s http get uri "/index.html" hosthdr "example.com" wait 5ms
//!     c <- s http status 200 reason "OK" body "<h1>Hello</h1>" wait 2ms
//! }
//!
//! // Build the output capture
//! compile {
//!     web_session(client, web_server)
//! }
//! ```
//!
//! ## Rust Library Quickstart
//!
//! Parse a `.frasm` program and synthesize raw Ethernet frames paired with nanosecond timestamps in memory:
//!
//! ```rust
//! use frameassembly::backend::compile_program;
//! use frameassembly::parser::parse_program;
//!
//! let frasm_source = r#"
//!     host sensor { ip 192.168.10.5  mac 00:1a:2b:3c:4d:5e }
//!     host plc    { ip 192.168.10.20 mac 00:1a:2b:3c:4d:5f }
//!
//!     flow modbus_poll(c, s) {
//!         c -> s modbus txid 1 unitid 1 readholdingregisters addr 100 count 4 wait 5ms
//!         c <- s modbus txid 1 unitid 1 readholdingregisters isresponse value 42 wait 5ms
//!     }
//!
//!     compile {
//!         modbus_poll(sensor, plc)
//!     }
//! "#;
//!
//! let program = parse_program(frasm_source).expect("valid FrameAssembly program");
//! let packets = compile_program(&program).expect("successful packet synthesis");
//! assert_eq!(packets.len(), 2);
//! assert!(packets[0].0.len() > 54);
//! assert_eq!(packets[1].1 - packets[0].1, 5_000_000); // 5ms delta in nanoseconds
//! ```
//!
//! Inspect structured [`error::CompilerError`] diagnostics and byte-offset spans when validating
//! untrusted `.frasm` input:
//!
//! ```rust
//! use frameassembly::error::CompilerError;
//! use frameassembly::parser::parse_program;
//!
//! let invalid_frasm = r#"
//!     host v4_host { ip 10.0.0.1 }
//!     host v6_host { ip 2001:db8::1 }
//!     flow bad_ping(a, b) { a -> b icmp echorequest }
//!     compile { bad_ping(v4_host, v6_host) }
//! "#;
//!
//! let err = parse_program(invalid_frasm).expect_err("mixed address families must fail");
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
pub mod reverse;
/// SNMP packet builder (backwards compatibility alias).
pub use builders::snmp::builder as snmp_builder;
/// SNMPv3 Cryptography (backwards compatibility alias).
pub use builders::snmp::crypto as snmp_crypto;
