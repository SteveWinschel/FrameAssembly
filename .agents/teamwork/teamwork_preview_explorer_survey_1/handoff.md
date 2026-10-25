# Corpus Survey & Parallel Sharding Partition Plan

## 1. Observation

### 1.1 Verification Test Suite (`tests/corpus_verification_tests.rs` & `tests/`)
Inspection of `tests/corpus_verification_tests.rs` shows the following validation mechanisms:
1. **Header Checks (`verify_example_file`, lines 33–69)**:
   - File length: `lines.len() >= 3`.
   - Line 1: Must begin with `// PROMPT: ` (non-empty body).
   - Line 2: Must begin with `// TOKENS: ` (non-empty body).
   - Instruction: Must contain `// INSTRUCTION:` comments before blocks.
2. **Syntax and Wire Compilation (`verify_example_file`, lines 71–97)**:
   - Calls `frameassembly::parser::parse_program(&content)`.
   - Calls `frameassembly::backend::generate_pcap(&program, temp_pcap_path)`.
   - Checks that generated PCAP file exists and has size `> 0` bytes.
3. **Repository Layout and Naming Rules**:
   - `test_corpus_no_root_examples` (lines 124–139): Verifies zero `.fasm` files exist directly in `examples/`.
   - `test_corpus_non_numeric_naming_conventions` (lines 143–165): Verifies file count `>= 205`, filename ends with `.fasm`, and does NOT start with a numeric character (`!first_char.is_ascii_digit()`).
   - `test_corpus_protocol_folder_coverage` (lines 169–236): Verifies that 82 directories exist and each contains at least 2 scenarios (and `>= 10` for `examples/topologies`):
     - L2 (8 dirs): `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`.
     - L3 (20 dirs): `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow`.
     - L4 (3 dirs): `tcp`, `udp`, `sctp`.
     - L7 standard (47 dirs): `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `syslog`, `netflow`, `ipfix`, `sflow`, `tftp`, `ftp`, `ssh`, `telnet`, `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`, `stun`, `sip`, `rtp`, `rtsp`, `smtp`, `imap`, `pop3`, `kerberos`, `ldap`, `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp`, `ssdp`, `whois`, `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua`.
     - L7 SNMP subdirectories (3 dirs): `examples/l7/snmp/snmpv1`, `examples/l7/snmp/snmpv2c`, `examples/l7/snmp/snmpv3`.
     - Topologies (1 dir): `examples/topologies`.
   - `test_corpus_all_examples_headers_and_compilation` (lines 240–262): Iterates over all `.fasm` files and runs `verify_example_file`.

#### Test Execution Commands and Verbatim Output
- Command: `cargo test --test corpus_verification_tests`
  Output:
  ```text
  running 4 tests
  test test_corpus_no_root_examples ... ok
  test test_corpus_protocol_folder_coverage ... ok
  test test_corpus_non_numeric_naming_conventions ... ok
  test test_corpus_all_examples_headers_and_compilation ... ok

  test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.39s
  ```
- Command: `cargo test`
  Output:
  ```text
  test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.39s
  test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s (snmp_spec_tests)
  test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s (doctests)
  ```

### 1.2 Line Length and Pre-Training Rules (`.agents/rules/frameassembly-dsl.md`)
In `.agents/rules/frameassembly-dsl.md` (lines 10–11) and `ORIGINAL_REQUEST.md` (lines 29, 47):
- **Line length limits**: `avg_line_length <= 85` and `max_line_length <= 200` to pass pre-training filters (The Stack v2, FineWeb, Dolma, StarCoder2 avg <= 100, max <= 1,000).
- **Repetition filters**: Intra-file repetition `< 25%` (Gopher / FineWeb filter `< 30%`).
- **MinHash LSH Near-Deduplication**: Diversify host names, IP addresses, MAC addresses, port combinations, and payloads.

#### Empirical Line Length Scan of Current 397 Files
A scan across all 397 existing `.fasm` files revealed:
- **0 header format defects**: All 397 files begin with `// PROMPT: `, `// TOKENS: `, and include `// INSTRUCTION:`.
- **51 files violate line length rules** (`max_line_length > 200` or `avg_line_length > 85`), concentrated exclusively in 4 directories:
  1. `examples/l7/snmp/snmpv1`: 10 files (max line length up to 465 chars)
  2. `examples/l7/snmp/snmpv2c`: 13 files (max line length up to 520 chars)
  3. `examples/l7/snmp/snmpv3`: 20 files (max line length up to 684 chars)
  4. `examples/topologies`: 8 files (max line length up to 289 chars)
- **78 directories (all L2, L3, L4, and non-SNMP L7) are 100% compliant**.
- **Lexer/Parser multiline verification**: In `src/lexer/mod.rs:21`, `#[logos(skip r"[ \t\n\f]+")]` skips all whitespace including newlines. Testing multiline statement wrapping (e.g. splitting `VARBIND` clauses across lines) in `frameassembly` succeeded with returncode `0` and valid PCAP generation.

---

### 1.3 Complete Inventory of All 82 Directories

| # | Layer | Directory | Current Files | Needed to Reach >=15 | Target Files |
|---|---|---|---|---|---|
| 1 | L2 | `examples/l2/arp` | 16 | 0 | 16 |
| 2 | L2 | `examples/l2/eapol` | 3 | 12 | 15 |
| 3 | L2 | `examples/l2/lacp` | 3 | 12 | 15 |
| 4 | L2 | `examples/l2/lldp` | 3 | 12 | 15 |
| 5 | L2 | `examples/l2/mpls` | 3 | 12 | 15 |
| 6 | L2 | `examples/l2/qinq` | 3 | 12 | 15 |
| 7 | L2 | `examples/l2/stp` | 3 | 12 | 15 |
| 8 | L2 | `examples/l2/vlan` | 3 | 12 | 15 |
| 9 | L3 | `examples/l3/ah` | 3 | 12 | 15 |
| 10 | L3 | `examples/l3/bfd` | 3 | 12 | 15 |
| 11 | L3 | `examples/l3/bgp` | 3 | 12 | 15 |
| 12 | L3 | `examples/l3/esp` | 3 | 12 | 15 |
| 13 | L3 | `examples/l3/geneve` | 3 | 12 | 15 |
| 14 | L3 | `examples/l3/gre` | 3 | 12 | 15 |
| 15 | L3 | `examples/l3/hsrp` | 3 | 12 | 15 |
| 16 | L3 | `examples/l3/icmp` | 3 | 12 | 15 |
| 17 | L3 | `examples/l3/igmp` | 3 | 12 | 15 |
| 18 | L3 | `examples/l3/ikev2` | 3 | 12 | 15 |
| 19 | L3 | `examples/l3/ipsec` | 3 | 12 | 15 |
| 20 | L3 | `examples/l3/mld` | 3 | 12 | 15 |
| 21 | L3 | `examples/l3/ndp` | 3 | 12 | 15 |
| 22 | L3 | `examples/l3/openflow` | 3 | 12 | 15 |
| 23 | L3 | `examples/l3/ospf` | 3 | 12 | 15 |
| 24 | L3 | `examples/l3/pim` | 3 | 12 | 15 |
| 25 | L3 | `examples/l3/rip` | 3 | 12 | 15 |
| 26 | L3 | `examples/l3/vrrp` | 3 | 12 | 15 |
| 27 | L3 | `examples/l3/vxlan` | 3 | 12 | 15 |
| 28 | L3 | `examples/l3/wireguard` | 3 | 12 | 15 |
| 29 | L4 | `examples/l4/sctp` | 4 | 11 | 15 |
| 30 | L4 | `examples/l4/tcp` | 25 | 0 | 25 |
| 31 | L4 | `examples/l4/udp` | 17 | 0 | 17 |
| 32 | L7 | `examples/l7/amqp` | 3 | 12 | 15 |
| 33 | L7 | `examples/l7/bacnet` | 3 | 12 | 15 |
| 34 | L7 | `examples/l7/coap` | 3 | 12 | 15 |
| 35 | L7 | `examples/l7/dhcp` | 3 | 12 | 15 |
| 36 | L7 | `examples/l7/dnp3` | 3 | 12 | 15 |
| 37 | L7 | `examples/l7/dns` | 3 | 12 | 15 |
| 38 | L7 | `examples/l7/ethernetip` | 3 | 12 | 15 |
| 39 | L7 | `examples/l7/ftp` | 3 | 12 | 15 |
| 40 | L7 | `examples/l7/grpc` | 3 | 12 | 15 |
| 41 | L7 | `examples/l7/http` | 3 | 12 | 15 |
| 42 | L7 | `examples/l7/http2` | 3 | 12 | 15 |
| 43 | L7 | `examples/l7/imap` | 3 | 12 | 15 |
| 44 | L7 | `examples/l7/ipfix` | 3 | 12 | 15 |
| 45 | L7 | `examples/l7/kerberos` | 3 | 12 | 15 |
| 46 | L7 | `examples/l7/ldap` | 3 | 12 | 15 |
| 47 | L7 | `examples/l7/mdns` | 3 | 12 | 15 |
| 48 | L7 | `examples/l7/memcached` | 3 | 12 | 15 |
| 49 | L7 | `examples/l7/modbus` | 3 | 12 | 15 |
| 50 | L7 | `examples/l7/mqtt` | 3 | 12 | 15 |
| 51 | L7 | `examples/l7/mysql` | 3 | 12 | 15 |
| 52 | L7 | `examples/l7/netflow` | 3 | 12 | 15 |
| 53 | L7 | `examples/l7/nfs` | 3 | 12 | 15 |
| 54 | L7 | `examples/l7/ntp` | 3 | 12 | 15 |
| 55 | L7 | `examples/l7/opcua` | 3 | 12 | 15 |
| 56 | L7 | `examples/l7/pop3` | 3 | 12 | 15 |
| 57 | L7 | `examples/l7/postgres` | 3 | 12 | 15 |
| 58 | L7 | `examples/l7/ptp` | 3 | 12 | 15 |
| 59 | L7 | `examples/l7/quic` | 3 | 12 | 15 |
| 60 | L7 | `examples/l7/radius` | 3 | 12 | 15 |
| 61 | L7 | `examples/l7/redis` | 3 | 12 | 15 |
| 62 | L7 | `examples/l7/rtp` | 3 | 12 | 15 |
| 63 | L7 | `examples/l7/rtsp` | 3 | 12 | 15 |
| 64 | L7 | `examples/l7/s7comm` | 3 | 12 | 15 |
| 65 | L7 | `examples/l7/sflow` | 3 | 12 | 15 |
| 66 | L7 | `examples/l7/sip` | 3 | 12 | 15 |
| 67 | L7 | `examples/l7/smb` | 3 | 12 | 15 |
| 68 | L7 | `examples/l7/smtp` | 3 | 12 | 15 |
| 69 | L7 SNMP | `examples/l7/snmp/snmpv1` | 15 | 0 | 15 |
| 70 | L7 SNMP | `examples/l7/snmp/snmpv2c` | 21 | 0 | 21 |
| 71 | L7 SNMP | `examples/l7/snmp/snmpv3` | 24 | 0 | 24 |
| 72 | L7 | `examples/l7/ssdp` | 3 | 12 | 15 |
| 73 | L7 | `examples/l7/ssh` | 3 | 12 | 15 |
| 74 | L7 | `examples/l7/stun` | 3 | 12 | 15 |
| 75 | L7 | `examples/l7/syslog` | 3 | 12 | 15 |
| 76 | L7 | `examples/l7/tacacs` | 3 | 12 | 15 |
| 77 | L7 | `examples/l7/telnet` | 3 | 12 | 15 |
| 78 | L7 | `examples/l7/tftp` | 3 | 12 | 15 |
| 79 | L7 | `examples/l7/tls` | 3 | 12 | 15 |
| 80 | L7 | `examples/l7/websocket` | 3 | 12 | 15 |
| 81 | L7 | `examples/l7/whois` | 3 | 12 | 15 |
| 82 | Topo | `examples/topologies` | 53 | 0 | 53 |
| **Total** | | **82 Directories** | **397** | **899** | **1,296** |

---

## 2. Logic Chain

1. **Baseline Invariants (Obs 1.1)**:
   - All `.fasm` files must compile to valid PCAP without errors and have strict 2-line headers (`// PROMPT: ...`, `// TOKENS: ...`) plus `// INSTRUCTION: ...` above each block.
   - Naming must not use numeric prefixes, e.g. `tcp_handshake.fasm`, not `01_tcp.fasm`.
2. **Current Capacity vs. Target (Obs 1.3)**:
   - Total current `.fasm` files = 397 across 82 directories.
   - 7 directories already have `>= 15` files (`arp` 16, `tcp` 25, `udp` 17, `snmpv1` 15, `snmpv2c` 21, `snmpv3` 24, `topologies` 53).
   - 75 directories have `< 15` files: 74 directories have exactly 3 files, and `examples/l4/sctp` has 4 files.
   - Adding 12 new files to each of the 74 directories (74 * 12 = 888) plus 11 new files to `sctp` brings every single directory to at least 15 files.
   - 397 existing + 899 new = **1,296 total `.fasm` files**, comfortably exceeding the 1,200+ milestone requirement.
3. **Zero-Collision Sharding by Directory Disjointness**:
   - Because each `.fasm` file lives under its dedicated directory `examples/<layer>/<protocol>/<protocol>_<scenario>.fasm`, partitioning work by **disjoint subsets of directories** ensures that parallel worker agents never modify or write to the same directory or file.
   - This provides mathematically provable zero file write collisions.
4. **Line-Length Discipline (Obs 1.2)**:
   - To satisfy `avg_line_length <= 85` and `max_line_length <= 200`, any long statement (e.g. multi-parameter protocols, multiple `VARBIND`s, long HTTP/JSON payloads) must wrap parameters onto separate indented lines.
   - The 51 existing files in SNMP and topologies that currently exceed line lengths must be formatted to wrap long lines onto multiple lines.

---

## 3. Parallel Worker Sharding Partition Plan

### Recommended 7-Shard Partitioning (Optimal for 6–8 Parallel Workers)

Every shard is assigned a completely disjoint group of directories. Each shard worker creates the specified number of scenarios, verifies them locally via `cargo test --test corpus_verification_tests`, and exits.

#### **Shard 1: L2 Data Link & L4 SCTP**
- **Assigned Directories (8 dirs)**:
  1. `examples/l2/eapol` (12 new files -> 15 total)
  2. `examples/l2/lacp` (12 new files -> 15 total)
  3. `examples/l2/lldp` (12 new files -> 15 total)
  4. `examples/l2/mpls` (12 new files -> 15 total)
  5. `examples/l2/qinq` (12 new files -> 15 total)
  6. `examples/l2/stp` (12 new files -> 15 total)
  7. `examples/l2/vlan` (12 new files -> 15 total)
  8. `examples/l4/sctp` (11 new files -> 15 total)
- **Workload**: 95 new files.
- **Focus Scenarios**:
  - EAPOL: 802.1X start/logoff, EAP-TLS packet flows, RADIUS bridging.
  - LACP: Actor/Partner state flags, aggregation key negotiation, link churn.
  - LLDP: Chassis ID, Port ID, TTL, System Capability and Port Description TLVs.
  - MPLS: Stacked labels (BGP-LU, L3VPN inner/outer labels, Traffic Class, S-bit, Penultimate Hop Popping).
  - QinQ: 802.1ad Service Provider S-VLAN 0x88A8 wrapping C-VLAN 0x8100, PCP translation.
  - STP: IEEE 802.1D BPDU, RSTP 802.1w Proposal/Agreement, root bridge election.
  - VLAN: 802.1Q PCP/DEI prioritizations, voice VLAN tags, trunking frames.
  - SCTP: INIT/INIT_ACK, HEARTBEAT/HEARTBEAT_ACK, DATA chunks, SACK chunk multi-homing.

#### **Shard 2: L3 Network & Routing Protocols A**
- **Assigned Directories (10 dirs)**:
  1. `examples/l3/ah` (12 new files -> 15 total)
  2. `examples/l3/bfd` (12 new files -> 15 total)
  3. `examples/l3/bgp` (12 new files -> 15 total)
  4. `examples/l3/esp` (12 new files -> 15 total)
  5. `examples/l3/geneve` (12 new files -> 15 total)
  6. `examples/l3/gre` (12 new files -> 15 total)
  7. `examples/l3/hsrp` (12 new files -> 15 total)
  8. `examples/l3/icmp` (12 new files -> 15 total)
  9. `examples/l3/igmp` (12 new files -> 15 total)
  10. `examples/l3/ikev2` (12 new files -> 15 total)
- **Workload**: 120 new files.
- **Focus Scenarios**:
  - AH & ESP: SPI indexing, sequence increments, auth verification, tunnel mode.
  - BFD: Control packets, asynchronous mode, echo function, poll/final state transitions.
  - BGP: OPEN, UPDATE with AS-PATH, MED, NEXT-HOP, NOTIFICATION, KEEPALIVE.
  - GENEVE & GRE: VNI 24-bit identifiers, option TLVs, GRE checksums, nested L3 encapsulation.
  - HSRP: Hello, Coup, Resign states, priority failover, virtual MAC mapping.
  - ICMP: Echo Request/Reply, Destination Unreachable (code 0..15), Time Exceeded, Redirect.
  - IGMP: v1/v2/v3 membership queries, report groups, leave group multicast frames.
  - IKEv2: IKE_SA_INIT, IKE_AUTH exchanges, Child SA establishment.

#### **Shard 3: L3 Network & Routing Protocols B**
- **Assigned Directories (10 dirs)**:
  1. `examples/l3/ipsec` (12 new files -> 15 total)
  2. `examples/l3/mld` (12 new files -> 15 total)
  3. `examples/l3/ndp` (12 new files -> 15 total)
  4. `examples/l3/openflow` (12 new files -> 15 total)
  5. `examples/l3/ospf` (12 new files -> 15 total)
  6. `examples/l3/pim` (12 new files -> 15 total)
  7. `examples/l3/rip` (12 new files -> 15 total)
  8. `examples/l3/vrrp` (12 new files -> 15 total)
  9. `examples/l3/vxlan` (12 new files -> 15 total)
  10. `examples/l3/wireguard` (12 new files -> 15 total)
- **Workload**: 120 new files.
- **Focus Scenarios**:
  - IPsec: Encapsulating Security Payload policy associations and multi-SA flows.
  - MLD: IPv6 MLDv1/MLDv2 Query and Report frames with solicited-node multicast.
  - NDP: Neighbor Solicitation (NS), Neighbor Advertisement (NA), Router Solicitation (RS), Router Advertisement (RA).
  - OpenFlow: OFPT_HELLO, FEATURES_REQUEST, FLOW_MOD, PACKET_IN/OUT frames.
  - OSPF: Hello packets, DBD exchanges, LSR, LSU, LSA Type 1–5 flooding.
  - PIM: Hello, Join/Prune messages, Register and Register-Stop messages.
  - RIP: RIPv2 and RIPng route update vectors with metric infinity (16).
  - VRRP: VRRPv2 and VRRPv3 advertisement heartbeats, preemption, VIP failover.
  - VXLAN: VNI headers, UDP port 4789 encapsulation, inner L2 frame delivery.
  - WireGuard: Handshake Initiation, Handshake Response, Cookie Reply, Transport Data.

#### **Shard 4: L7 Core Applications & Messaging**
- **Assigned Directories (12 dirs)**:
  1. `examples/l7/amqp` (12 new files -> 15 total)
  2. `examples/l7/bacnet` (12 new files -> 15 total)
  3. `examples/l7/coap` (12 new files -> 15 total)
  4. `examples/l7/dhcp` (12 new files -> 15 total)
  5. `examples/l7/dnp3` (12 new files -> 15 total)
  6. `examples/l7/dns` (12 new files -> 15 total)
  7. `examples/l7/ethernetip` (12 new files -> 15 total)
  8. `examples/l7/ftp` (12 new files -> 15 total)
  9. `examples/l7/grpc` (12 new files -> 15 total)
  10. `examples/l7/http` (12 new files -> 15 total)
  11. `examples/l7/http2` (12 new files -> 15 total)
  12. `examples/l7/imap` (12 new files -> 15 total)
- **Workload**: 144 new files.
- **Focus Scenarios**:
  - AMQP: Connection.Start/Tune/Open, Channel.Open, Basic.Publish, Basic.Deliver.
  - BACnet & DNP3 & EtherNet/IP: Read/Write property, object identifiers, SCADA link frames.
  - CoAP: Confirmable/Non-confirmable GET/PUT/POST, message ID, token, option headers.
  - DHCP: DORA (Discover, Offer, Request, Ack) cycle, option 53, 54, 51, 61.
  - DNS: Standard A/AAAA queries, MX, SRV, CNAME, reverse PTR lookups, EDNS0.
  - FTP: USER/PASS, PASV, RETR, STOR, 220 banners, 230 logged in.
  - HTTP & HTTP/2 & gRPC: REST APIs, HEAD/GET/POST/DELETE, headers, HPACK, HTTP/2 SETTINGS and DATA frames, protobuf gRPC payloads.
  - IMAP: CAPABILITY, LOGIN, SELECT INBOX, FETCH, LOGOUT.

#### **Shard 5: L7 Telemetry, Directory & Database**
- **Assigned Directories (12 dirs)**:
  1. `examples/l7/ipfix` (12 new files -> 15 total)
  2. `examples/l7/kerberos` (12 new files -> 15 total)
  3. `examples/l7/ldap` (12 new files -> 15 total)
  4. `examples/l7/mdns` (12 new files -> 15 total)
  5. `examples/l7/memcached` (12 new files -> 15 total)
  6. `examples/l7/modbus` (12 new files -> 15 total)
  7. `examples/l7/mqtt` (12 new files -> 15 total)
  8. `examples/l7/mysql` (12 new files -> 15 total)
  9. `examples/l7/netflow` (12 new files -> 15 total)
  10. `examples/l7/nfs` (12 new files -> 15 total)
  11. `examples/l7/ntp` (12 new files -> 15 total)
  12. `examples/l7/opcua` (12 new files -> 15 total)
- **Workload**: 144 new files.
- **Focus Scenarios**:
  - IPFIX & NetFlow: Flow records, template flowsets, sampling exporters.
  - Kerberos & LDAP: AS-REQ/AS-REP, TGS-REQ/TGS-REP, bind requests, search requests.
  - mDNS: `.local` service discovery, PTR/SRV/TXT record resolution.
  - Memcached: set/get/delete, CAS commands, text & binary protocol variants.
  - Modbus: Read Holding Registers (FC03), Write Single Coil (FC05), Write Multiple Registers (FC16).
  - MQTT: CONNECT, CONNACK, PUBLISH (QoS 0/1/2), SUBSCRIBE, SUBACK, PINGREQ.
  - MySQL: HandshakeInitialization, HandshakeResponse41, Query, OK/ERR packets.
  - NFS: RPC CALL/REPLY, LOOKUP, READ, WRITE.
  - NTP: Client/Server mode 3/4, Stratum 1/2 clock sync, timestamp fields.
  - OPC UA: Hello (HEL), Acknowledge (ACK), OpenSecureChannel, CreateSession.

#### **Shard 6: L7 Media, Storage, Redundancy & Databases**
- **Assigned Directories (12 dirs)**:
  1. `examples/l7/pop3` (12 new files -> 15 total)
  2. `examples/l7/postgres` (12 new files -> 15 total)
  3. `examples/l7/ptp` (12 new files -> 15 total)
  4. `examples/l7/quic` (12 new files -> 15 total)
  5. `examples/l7/radius` (12 new files -> 15 total)
  6. `examples/l7/redis` (12 new files -> 15 total)
  7. `examples/l7/rtp` (12 new files -> 15 total)
  8. `examples/l7/rtsp` (12 new files -> 15 total)
  9. `examples/l7/s7comm` (12 new files -> 15 total)
  10. `examples/l7/sflow` (12 new files -> 15 total)
  11. `examples/l7/sip` (12 new files -> 15 total)
  12. `examples/l7/smb` (12 new files -> 15 total)
- **Workload**: 144 new files.
- **Focus Scenarios**:
  - POP3: USER, PASS, STAT, LIST, RETR, QUIT.
  - Postgres: StartupMessage, AuthenticationOk, ReadyForQuery, Query, CommandComplete.
  - PTP: Sync, Follow_Up, Delay_Req, Delay_Resp IEEE 1588 nanosecond clock sync.
  - QUIC: Initial packets, Handshake, Short header packets, Connection IDs.
  - RADIUS: Access-Request, Access-Accept, Accounting-Request (Start/Stop).
  - Redis: RESP inline and array commands (PING, SET, GET, HSET, LRANGE).
  - RTP & RTSP: Real-time audio/video payload sequencing, DESCRIBE, SETUP, PLAY, TEARDOWN.
  - S7comm: Job/Ack-Data, Read Var, Write Var, CPU functions.
  - sFlow: Flow sample datagrams, counter samples.
  - SIP: INVITE, 100 Trying, 180 Ringing, 200 OK, ACK, BYE.
  - SMB: SMB2 NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, CLOSE.

#### **Shard 7: L7 Security, Remote Access, Utilities & Line-Length Normalization**
- **Assigned Directories (11 dirs)**:
  1. `examples/l7/smtp` (12 new files -> 15 total)
  2. `examples/l7/ssdp` (12 new files -> 15 total)
  3. `examples/l7/ssh` (12 new files -> 15 total)
  4. `examples/l7/stun` (12 new files -> 15 total)
  5. `examples/l7/syslog` (12 new files -> 15 total)
  6. `examples/l7/tacacs` (12 new files -> 15 total)
  7. `examples/l7/telnet` (12 new files -> 15 total)
  8. `examples/l7/tftp` (12 new files -> 15 total)
  9. `examples/l7/tls` (12 new files -> 15 total)
  10. `examples/l7/websocket` (12 new files -> 15 total)
  11. `examples/l7/whois` (12 new files -> 15 total)
- **Workload**: 132 new files + Line-length reformatting of the 51 long files in `snmpv1` (10), `snmpv2c` (13), `snmpv3` (20), `topologies` (8).
- **Focus Scenarios**:
  - SMTP: HELO/EHLO, MAIL FROM, RCPT TO, DATA, QUIT.
  - SSDP: M-SEARCH, NOTIFY ssdp:alive, ssdp:byebye multicast.
  - SSH: Protocol version exchange (`SSH-2.0-...`), SSH_MSG_KEXINIT.
  - STUN: Binding Request, Binding Response with XOR-MAPPED-ADDRESS.
  - Syslog: RFC 5424 PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID.
  - TACACS+: Authentication, Authorization, Accounting packet headers.
  - Telnet: IAC DO/DONT/WILL/WONT terminal negotiation.
  - TFTP: RRQ, WRQ, DATA, ACK, ERROR packets.
  - TLS: ClientHello, ServerHello, Certificate, Finished, ApplicationData.
  - WebSocket: Upgrade handshake, Client/Server masked text/binary frames, Close, Ping, Pong.
  - WHOIS: Query string, NIC response payload.
  - Reformatting: Wrap long VARBIND and multi-modifier lines across multiple lines with 4-space indentation.

---

### Alternative 5-Shard Partitioning (For 5 Parallel Workers)

1. **Shard 1 (L2 7 dirs + L4 1 dir + L3 first 5 dirs)**:
   - Dirs: `l2/{eapol,lacp,lldp,mpls,qinq,stp,vlan}`, `l4/sctp`, `l3/{ah,bfd,bgp,esp,geneve}` (13 dirs, 155 files).
2. **Shard 2 (L3 remaining 15 dirs)**:
   - Dirs: `l3/{gre,hsrp,icmp,igmp,ikev2,ipsec,mld,ndp,openflow,ospf,pim,rip,vrrp,vxlan,wireguard}` (15 dirs, 180 files).
3. **Shard 3 (L7 dirs 1–16)**:
   - Dirs: `l7/{amqp,bacnet,coap,dhcp,dnp3,dns,ethernetip,ftp,grpc,http,http2,imap,ipfix,kerberos,ldap,mdns}` (16 dirs, 192 files).
4. **Shard 4 (L7 dirs 17–32)**:
   - Dirs: `l7/{memcached,modbus,mqtt,mysql,netflow,nfs,ntp,opcua,pop3,postgres,ptp,quic,radius,redis,rtp,rtsp}` (16 dirs, 192 files).
5. **Shard 5 (L7 dirs 33–47 + line length normalization)**:
   - Dirs: `l7/{s7comm,sflow,sip,smb,smtp,ssdp,ssh,stun,syslog,tacacs,telnet,tftp,tls,websocket,whois}` (15 dirs, 180 files + 51 rewrapped files).

---

## 4. Caveats

1. **Directories with Existing >= 15 Files**:
   - `examples/l2/arp` (16), `examples/l4/tcp` (25), `examples/l4/udp` (17), `examples/l7/snmp/snmpv1` (15), `examples/l7/snmp/snmpv2c` (21), `examples/l7/snmp/snmpv3` (24), `examples/topologies` (53) already have `>= 15` files. Shards should NOT overwrite them.
2. **51 Long Files in SNMP and Topologies**:
   - These 51 files pass `cargo test --test corpus_verification_tests` currently, but fail the AI training data line length guardrails (`max_line_length <= 200` or `avg_line_length <= 85`).
   - Normalizing them by wrapping long statements across multiple lines is safe and valid FrameAssembly DSL syntax.
3. **No Code Edits in `src/`**:
   - As per hard guardrail R4, all changes must remain strictly in `examples/` and metadata folders. `src/` must remain untouched.

---

## 5. Conclusion

1. The FrameAssembly corpus currently contains **397 valid `.fasm` files across 82 directories**, all of which compile cleanly into valid PCAP files.
2. 7 directories already have `>= 15` files, while 75 directories have `< 15` files (74 directories with 3 files, 1 with 4 files).
3. Expanding each of the 74 directories by 12 new files and `sctp` by 11 new files creates **899 new scenarios**, bringing total corpus size to **1,296 verified `.fasm` files** (comfortably above the 1,200+ requirement).
4. The **7-Shard Partition Plan** divides the 75 target directories into strictly disjoint subsets with balanced workloads (~95 to 144 files per shard), providing mathematically guaranteed **zero file write collisions**.
5. Every generated scenario must include `// PROMPT: ` (line 1), `// TOKENS: ` (line 2), and `// INSTRUCTION: ` before each block, wrap long parameters to enforce `avg_line_length <= 85` and `max_line_length <= 200`, and use diverse hostnames and IPs to defeat MinHash LSH deduplication.

---

## 6. Verification Method

To independently verify all observations and test results:
1. **Run Corpus Verification Suite**:
   ```bash
   cargo test --test corpus_verification_tests
   ```
   *Expected result*: 4 passed, 0 failed.
2. **Verify Protocol Directory Counts and File Totals**:
   ```bash
   python3 -c "
   import os
   dirs = {}
   for root, _, files in os.walk('examples'):
       fasm_files = [f for f in files if f.endswith('.fasm')]
       if fasm_files:
           dirs[root] = len(fasm_files)
   print('Directories:', len(dirs))
   print('Total files:', sum(dirs.values()))
   "
   ```
   *Expected result*: Directories: 82, Total files: 397.
3. **Verify Line Length and Header Invariants**:
   ```bash
   python3 -c "
   import os
   for root, _, files in os.walk('examples'):
       for f in files:
           if not f.endswith('.fasm'): continue
           p = os.path.join(root, f)
           with open(p) as fh: lines = fh.readlines()
           assert lines[0].startswith('// PROMPT: '), f'{p}: line 1'
           assert lines[1].startswith('// TOKENS: '), f'{p}: line 2'
           assert any('// INSTRUCTION:' in l for l in lines), f'{p}: instruction'
   print('All headers 100% compliant')
   "
   ```
4. **Verify Multiline Statement Syntax**:
   ```bash
   target/debug/frameassembly examples/l7/snmp/snmpv3/snmpv3_auth_sha512_priv_aes_high_security.fasm -o /tmp/test_out.pcap
   ```
   *Expected result*: Exits 0 with non-empty PCAP output.
