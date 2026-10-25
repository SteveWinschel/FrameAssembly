---
name: frameassembly
description: Comprehensive architecture guide, canonical DSL syntax specification, AST design, protocol-scoped parser dispatch, wire builders, and PCAPNG serialization patterns for FrameAssembly in Rust.
---

# FrameAssembly Architecture, Canonical DSL & Protocol Engine Skill

Use this skill when designing, implementing, extending, testing, or auditing the `frameassembly` Domain-Specific Language (DSL), AST structures, two-phase `logos` + `winnow` parser, 81 protocol payload builders, native RFC packet assembly, and PCAPNG serialization in Rust.

---

## 1. Quick Reference & Selection Matrix (Canonical Syntax Only)

| FrameAssembly Capability | Canonical Pattern / Implementation | Strictly Forbidden (Hallucinated / Pre-v1 Syntax) |
| :--- | :--- | :--- |
| **CLI Execution Entry Point** | `frameassembly <input.fasm> [-o output.pcap]` | Creating output files before semantic validation |
| **Programmatic Compilation Pipeline** | `parser::parse_program(&src)` $\rightarrow$ `parser::validate_semantics(&prog, &src)` $\rightarrow$ `backend::compile_program(&prog)` / `backend::generate_pcap(&prog, path)` | Non-existent 1-arg `validate_semantics(&prog)`, `compile_file`, `compile_source`, `lexer::tokenize`, or `codegen::generate_packets` |
| **Host Endpoint Declaration** | `HOST <id> { IP <ip> [MAC <mac>] }` (space-separated, no `=`, no `:`, no `,`) | `HOST x = { IP: ..., MAC: ..., MASK: ... }` or `IPV4` / `IPV6` inside `HOST` |
| **Parameterized Flow Block** | `FLOW <id>(<param1>, <param2>) { <param1> -> <param2> <PROTO> ... }` | Parameterless `FLOW name { ... }`, `FLOW name = { ... }`, or `FROM a TO b` / `REVERSE` / `SEND` |
| **Timing & Delay Offsets** | Inline `WAIT <int><unit>` modifier on a frame statement (`ns`, `us`, `ms`, `s`, `m`) | Standalone `WAIT 5ms` statements on their own line or `+5ms` / `[+delay]` prefixes |
| **Compile & Loop Execution** | `COMPILE { <flow>(<host1>, <host2>) LOOP 10 { <flow>(<host1>, <host2>) } }` | Named `COMPILE Name { ... }`, bare `COMPILE`, or argumentless flow calls `<flow>` |
| **L2 Modifiers** | `VLAN <id> [PCP <p>] [DEI <d>]`, `QINQ <svlan> [INNER_VLAN <cvlan>]`, `MPLS <label> [EXP <e>] [BOS <b>] [MPLS_TTL <t>]` | `QINQ <outer> <inner>` without `INNER_VLAN` or `CVLAN` |
| **L3 Modifiers** | `TTL <val>`, `DSCP <d>`, `ECN <e>`, `IPID <id>`, `DF`, `MF`, `FRAGOFFSET <off>`, `FLOWLABEL <fl>` | `HOPLIMIT` or `HOP_LIMIT` (always use `TTL` for both IPv4 and IPv6) |
| **L4 Modifiers** | `SRCPORT <p>`, `DSTPORT <p>`, `SEQ <seq>`, `ACKNUM <ack>`, `WINDOW <w>`, `URGENT <u>`, bare flags `SYN ACK FIN RST PSH URG ECE CWR` | `SPORT`, `DPORT`, `ACK <n>`, `FLAGS [SYN, ACK]` |
| **ARP Sub-Keywords** | `ARP [REQUEST \| REPLY] [GRATUITOUS] [SENDERMAC <mac>] [SENDERIP <ip>] [TARGETMAC <mac>] [TARGETIP <ip>]` | Non-existent `HWTYPE` or `PROTOTYPE` tokens |
| **SNMPv3 USM Syntax** | `SNMP3 GET REQID 1 USER "u" AUTH SHA256 "p" PRIV AES "k" ENGINEID "80..." ENGINEBOOTS 1 ENGINETIME 100 VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 100` | Quoted `AUTH "SHA256"`, `PRIV "AES"`, `AUTHPASS`, `PRIVPASS`, `BOOTS`, `TIME`, `ENGINE_ID`, or `= TIMETICKS(100)` |
| **Protocol-Scoped Field Parsing** | Dispatch statement modifiers via `dispatch_protocol_field(proto: &Protocol, input: &mut Stream<'i, 'a>)` in `src/parser/fields.rs` | Flat `alt((...))` chains where `cut_err` on `VALUE`, `VERSION`, `STATUS`, `TOKEN`, `MSGID` or 0-arg `DATA`, `COOKIE`, `RESPONSE`, `REPLY`, `KEEPALIVE` shadows other protocols |
| **Header Discipline for AI Corpus** | Line 1: `// PROMPT:`, Line 2: `// TOKENS:` (bijective with `src/lexer/mod.rs`), Block headers: `// INSTRUCTION:` | Omitting headers, exceeding `avg <= 85` / `max <= 200` line length, or `< 50` words |

---

## 2. Architecture Decision Guide

### 2.1 The Five-Stage FrameAssembly Compiler Pipeline
1. **Lexical Analysis (`src/lexer/mod.rs`)**:
   - Zero-copy `logos 0.14` tokenizer producing spanned `Token<'a>` slices across all 81 protocols, L2–L4 modifiers, SNMPv3 USM parameters, time units (`ns`, `us`, `ms`, `s`, `m`), IPv4/IPv6 addresses, MAC addresses, and ASN.1 OIDs.
2. **AST & Two-Phase Combinator Parsing (`src/ast/` & `src/parser/`)**:
   - Strongly-typed AST nodes in `src/ast/mod.rs` (`Program<'a>`, `HostDef<'a>`, `FlowDef<'a>`, `FrameStatement<'a>`, `Protocol`, `ProtocolSpec<'a>`) and `src/ast/{l2,l3,l4,l7}/<protocol>.rs`. Every AST `*Spec` struct includes `/// Syntax mapping: \`...\`` and `#[doc(alias = "...")]`.
   - Two-phase `winnow 1.0` parser over `Stream<'i, 'a>` (`&'i [(Token<'a>, Range<usize>)]`) in `src/parser/mod.rs`, `src/parser/fields.rs`, and `src/parser/{l2,l3,l4,l7}/<protocol>.rs` (`pub(crate) mod` for internal parser submodules), followed by `validate_semantics(&program, &source)`.
   - **Critical Parser Invariant (No Cross-Protocol Shadowing)**: Shared keyword tokens (`Token::Value`, `Token::Version`, `Token::Status`, `Token::Token`, `Token::MsgId`, `Token::Group`, `Token::Data`, `Token::Cookie`, `Token::Response`, `Token::Reply`, `Token::Keepalive`) are used by multiple protocols with different argument types (`u8`/`u32`/`u64`/`&str`/0-arg flag). `dispatch_protocol_field` in `src/parser/fields.rs` routes modifier parsing to the active `Protocol` first before falling back to cross-layer modifiers.
3. **Stateful Backend & 4-Tuple Progression (`src/backend/mod.rs`, `src/backend/l7_dispatch.rs`)**:
   - Expands `COMPILE` flow invocations and `LOOP` blocks.
   - Tracks bidirectional ports (`EndpointPairPorts`) and 4-tuple TCP sequence/acknowledgment numbers (`Canonical4Tuple`, initial sequence number `1000`) shared across raw `TCP` and TCP-based L7 protocols.
   - Preserves builder-returned `(payload, sport, dport)` and `target_ip` tuples in `src/backend/l7_dispatch.rs` (`DHCP` `546/547` vs `68/67`, `MDNS` `224.0.0.251`/`ff02::fb` port `5353`, `PTP` `319` vs `320`, `RADIUS` `1812` vs `1813`).
4. **Zero-Heap Protocol Payload Synthesis & Native Wire Framing (`src/builders/` & `src/packet.rs`)**:
   - 81 native RFC protocol builders in `src/builders/{l2,l3,l4,l7}/<protocol>.rs` and `src/builders/l7/snmp/{builder,crypto}.rs`.
   - `src/packet.rs` is a 100% native, zero-external-dependency wire framing engine (Ethernet II, IEEE 802.1Q VLAN, IEEE 802.1ad QinQ, RFC 3032 MPLS, IPv4/IPv6, TCP/UDP/SCTP, RFC 1071 / RFC 9260 CRC32c checksums).
5. **PCAPNG Serialization (`src/pcap.rs`)**:
   - Writes deterministic, nanosecond-resolution `.pcap` / `.pcapng` packet captures via `pcap-file 2.0.0` with mandatory `InterfaceDescriptionOption::IfTsResol(9)` and transactional file creation.

---

### 2.2 The Full 81-Protocol Native Matrix

- **Layer 2 (8 Protocols)**:
  `ARP`, `VLAN`, `QINQ`, `LLDP`, `STP`, `LACP`, `EAPOL`, `MPLS`.
- **Layer 3 (20 Protocols)**:
  `ICMP`, `NDP`, `IGMP`, `MLD`, `GRE`, `VXLAN`, `GENEVE`, `IPSEC`, `ESP`, `AH`, `IKEV2`, `WIREGUARD`, `OSPF`, `BGP`, `RIP`, `VRRP`, `HSRP`, `PIM`, `BFD`, `OPENFLOW`.
- **Layer 4 (3 Protocols)**:
  `TCP`, `UDP`, `SCTP`.
- **Layer 7 Application, Management & OT (50 Protocols)**:
  - Network Management & Telemetry: `SNMP1`, `SNMP2`, `SNMP3`, `NETFLOW`, `IPFIX`, `SFLOW`, `SYSLOG`.
  - Core Infrastructure & AAA: `DNS`, `MDNS`, `DHCP`, `NTP`, `PTP`, `RADIUS`, `TACACS`, `WHOIS`, `SSDP`.
  - Remote Access & File Transfer: `TFTP`, `FTP`, `SSH`, `TELNET`.
  - Web, Cloud & Transport Security: `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `QUIC`.
  - Voice & Multimedia: `SIP`, `RTP`, `RTSP`, `STUN`.
  - Mail & Directory: `SMTP`, `IMAP`, `POP3`, `KERBEROS`, `LDAP`.
  - Storage, Databases & Messaging: `SMB`, `NFS`, `REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`, `MQTT`, `COAP`, `AMQP`.
  - Industrial Control Systems (ICS) & SCADA/OT: `MODBUS`, `BACNET`, `DNP3`, `S7COMM`, `ETHERNETIP`, `OPCUA`.

---

### 2.3 Compiler Pipeline QA & Dissector Checklist

Whenever adding or modifying a protocol, keyword, or builder, verify the full end-to-end checklist:
1. **Stage 1 — 5-Way Grammar & Lexer Lockstep**:
   - Every uppercase `#[token("...")]` in `src/lexer/mod.rs` is wired into `src/parser/`, `parse_spanned_ident` (`src/parser/ident.rs`), `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`.
2. **Stage 2 — Two-Phase Parsing & Semantic Validation (`parse_program` $\rightarrow$ `validate_semantics(&prog, &src)`)**:
   - `parse_program(&src)` constructs `Program<'a>` and invokes `validate_semantics(&prog, &src)` to verify host IP family homogeneity (no IPv4 $\leftrightarrow$ IPv6 mixing), VLAN/DSCP/ECN/TTL/FLOWLABEL numeric bounds, and zero duplicate modifiers.
3. **Stage 3 — AST `*Spec` Field Completeness & `l7_dispatch.rs` Return Tuples (`compile_program(&prog)`)**:
   - Every field on `<Proto>Spec` in `src/ast/{l2,l3,l4,l7}/<proto>.rs` is populated in `src/parser/finish.rs` / `l7_apply.rs` and consumed in `src/builders/{l2,l3,l4,l7}/<proto>.rs`.
   - `src/backend/l7_dispatch.rs` honors dynamic builder return tuples for `DHCP` (`(pkt, sport, dport)`), `MDNS` (`(payload, target_ip, 5353)`), `PTP` (`(result, dport)`), and `RADIUS` (`(pkt, dport)`).
4. **Stage 4 — Wire & Wireshark (`tshark`) Dissector Verification**:
   - Checksums & TTLs: `GRE` `CHECKSUM` (`0x8000`) computed at `gre[4..6]`; `VRRPv3` IPv4/IPv6 pseudo-header (`112`) + TTL/Hop Limit `255`; `NDP` Hop Limit `255`; `UDP` `0x0000 -> 0xFFFF`; `SCTP` little-endian CRC32c at `8..12`.
   - Inner Frames & Lengths: `GENEVE` `0x6558` encapsulates a 14B Ethernet + 20B IPv4 frame; `WIREGUARD` Type `4` (`DATA`) appends a 16B Poly1305 AEAD tag ($\ge 32$B); `QUIC` Long Header encodes a 2B varint (`0x4000 | len`); `IPFIX` `total_len`/`set_len` include payload; `SFLOW` Flow Sample has 8 `u32`s (32B); `LDAP` `SearchRequest` has all 8 RFC 4511 elements; `KERBEROS` `KDC-REQ-BODY` includes `[7] till` and `[8] nonce`.
5. **Stage 5 — Corpus & Markdown Block Gate (`tests/corpus_verification_tests.rs`)**:
   - All `2,611` `.fasm` files (`13,055` synthetic training instances) in `examples/` and all ````frameassembly` / ````fasm` blocks in `README.md`, `docs/*.md`, `src/**/*.rs`, and `.agents/skills/**/*.md` compile cleanly into valid PCAPNG captures.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable, compiler-verified production implementations:
1. **Programmatic Compiler Pipeline Invocation (`parse_program`, `validate_semantics(&prog, &src)`, `compile_program`, `generate_pcap`)**
2. **Canonical AST Structures & `/// Syntax mapping:` Docstring Pattern (`Program<'a>`, `HostDef<'a>`, `FlowDef<'a>`, `FrameStatement<'a>`, `ArpSpec<'a>`)**
3. **Protocol-Scoped Field Parser Dispatch Pattern (`dispatch_protocol_field` in `src/parser/fields.rs`)**
4. **Canonical `.fasm` Scenario Archetypes (SNMPv3 USM over IPv6, Industrial OT Modbus/QinQ)**
