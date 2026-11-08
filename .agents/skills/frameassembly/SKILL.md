---
name: frameassembly
description: Comprehensive architecture guide, canonical DSL syntax specification, AST design, 6-stage forward compiler + reverse PCAP decompiler, protocol-scoped parser dispatch, wire builders, and PCAPNG serialization patterns for FrameAssembly in Rust.
---

# FrameAssembly Architecture, Canonical DSL & Protocol Engine Skill

Use this skill when designing, implementing, extending, testing, or auditing the `frameassembly` Domain-Specific Language (DSL), AST structures, two-phase `logos 0.14.4` + `winnow 1.0.5` parser, 81 protocol payload builders, native RFC packet assembly, PCAPNG serialization, and reverse PCAP/PCAPNG-to-`.fasm` decompilation in Rust.

---

## 1. Quick Reference & Selection Matrix (Canonical Syntax Only)

| FrameAssembly Capability | Canonical Pattern / Implementation | Strictly Forbidden (Hallucinated / Pre-v1 Syntax) |
| :--- | :--- | :--- |
| **CLI Execution Entry Points** | `frameassembly <input.fasm> [-o output.pcap]`, `frameassembly show <input.fasm>`, `frameassembly reverse <input.pcap> [-o output.fasm]` | Creating output files before semantic validation |
| **Programmatic Forward & Reverse Pipeline** | `parser::parse_program(&src)` $\rightarrow$ `parser::validate_semantics(&prog, &src)` $\rightarrow$ `backend::compile_program(&prog)` / `backend::generate_pcap(&prog, path)`; `reverse::reverse_pcap_bytes` / `reverse_pcap_file` | Non-existent 1-arg `validate_semantics(&prog)`, `compile_file`, `compile_source`, `lexer::tokenize`, or `codegen::generate_packets` |
| **Host Endpoint Declaration** | `HOST <id> { [IP <ip>] [MAC <mac>] }` (at least one of `IP` or `MAC` required; space-separated, no `=`, no `:`, no `,`; pure L2 protocols `LLDP`, `STP`, `LACP`, `EAPOL`, `VLAN`, `QINQ`, `MPLS`, `ARP` allow MAC-only via `protocol_requires_ip`) | `HOST x = { IP: ..., MAC: ..., MASK: ... }`, `IPV4` / `IPV6` inside `HOST`, or empty `HOST x {}` |
| **Parameterized Flow Block** | `FLOW <id>(<param1>, <param2>) { <param1> -> <param2> <PROTO> ... }` | Parameterless `FLOW name { ... }`, `FLOW name = { ... }`, or `FROM a TO b` / `REVERSE` / `SEND` |
| **Timing & Delay Offsets** | Inline `WAIT <int><unit>` modifier on a frame statement (`ns`, `us`, `ms`, `s`, `m`) | Standalone `WAIT 5ms` statements on their own line or `+5ms` / `[+delay]` prefixes |
| **Compile & Loop Execution (`RunStatement`)** | `COMPILE { <flow>(<h1>, <h2>) <h1> -> <h2> <PROTO> ... LOOP 10 { <flow>(<h1>, <h2>) } }` (`RunStatement::{Invocation, Frame, Loop}`) | Named `COMPILE Name { ... }`, bare `COMPILE`, or argumentless flow calls `<flow>` |
| **L2 Modifiers** | `VLAN <id> [PCP <p>] [DEI <d>]`, `QINQ <svlan> [INNER_VLAN <cvlan>]`, `MPLS <label> [EXP <e>] [BOS <b>] [MPLS_TTL <t>]` | `QINQ <outer> <inner>` without `INNER_VLAN` or `CVLAN` |
| **L3 Modifiers** | `TTL <val>`, `DSCP <d>`, `ECN <e>`, `IPID <id>`, `DF`, `MF`, `FRAGOFFSET <off>`, `FLOWLABEL <fl>` | `HOPLIMIT` or `HOP_LIMIT` (always use `TTL` for both IPv4 and IPv6) |
| **L4 Modifiers** | `SRCPORT <p>`, `DSTPORT <p>`, `SEQ <seq>`, `ACKNUM <ack>`, `WINDOW <w>`, `URGENT <u>`, bare flags `SYN ACK FIN RST PSH URG ECE CWR` | `SPORT`, `DPORT`, `ACK <n>`, `FLAGS [SYN, ACK]` |
| **ARP Sub-Keywords** | `ARP [REQUEST \| REPLY] [GRATUITOUS] [SENDERMAC <mac>] [SENDERIP <ip>] [TARGETMAC <mac>] [TARGETIP <ip>]` | Non-existent `HWTYPE` or `PROTOTYPE` tokens |
| **SNMPv3 USM Syntax** | `SNMP3 GET REQID 1 USER "u" AUTH SHA256 "p" PRIV AES "k" ENGINEID "80..." ENGINEBOOTS 1 ENGINETIME 100 VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 100` | Quoted `AUTH "SHA256"`, `PRIV "AES"`, `AUTHPASS`, `PRIVPASS`, `BOOTS`, `TIME`, `ENGINE_ID`, or `= TIMETICKS(100)` |
| **Protocol-Scoped Field Parsing** | 3-tier statement loop (`parse_universal_field` $\rightarrow$ `dispatch_protocol_field(proto, input)` $\rightarrow$ `parse_fallback_field`) in `src/parser/fields.rs` | Flat `alt((...))` chains where `cut_err` on `VALUE`, `VERSION`, `STATUS`, `TOKEN`, `MSGID` or 0-arg `DATA`, `COOKIE`, `RESPONSE`, `REPLY`, `KEEPALIVE` shadows other protocols |
| **Header Discipline for AI Corpus** | Line 1: `// PROMPT:`, Line 2: `// TOKENS:` (bijective with `src/lexer/mod.rs`), Block headers: `// INSTRUCTION:` | Omitting headers, exceeding `avg <= 85` / `max <= 200` line length, or `< 50` words |

---

## 2. Architecture Decision Guide

### 2.1 The 6-Stage FrameAssembly Compiler Pipeline & Reverse PCAP Decompiler
1. **Stage 1 — Lexical Analysis (`src/lexer/mod.rs`)**:
   - Zero-copy `logos 0.14.4` case-insensitive tokenizer (`#[token("...", ignore(ascii_case))]`, `#[logos(skip r"//[^\r\n]*")]`) producing spanned `Token<'a>` slices across all 81 protocols, L2–L4 modifiers, SNMPv3 USM parameters, time units (`ns`, `us`, `ms`, `s`, `m`), IPv4/IPv6 addresses, MAC addresses, and ASN.1 OIDs via a strict 6-tier priority ladder.
2. **Stage 2 — AST & Two-Phase Combinator Parsing (`src/ast/` & `src/parser/`)**:
   - Strongly-typed AST nodes in `src/ast/mod.rs` (`Program<'a>`, `HostDef<'a>` with `pub ip: Option<IpAddr>` and `pub mac: Option<[u8; 6]>`, `FlowDef<'a>`, `FrameStatement<'a>`, `RunStatement<'a>`, `Protocol`, `ProtocolSpec<'a>`) and `src/ast/{l2,l3,l4,l7}/<protocol>.rs`. Every AST `*Spec` struct includes `/// Syntax mapping: \`...\`` and `#[doc(alias = "...")]`.
   - Two-phase `winnow 1.0.5` parser over `Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)]` in `src/parser/mod.rs`, `src/parser/statement.rs`, `src/parser/fields.rs`, and `src/parser/{l2,l3,l4,l7}/<protocol>.rs` (`pub(crate) mod` for internal parser submodules).
   - **Critical Parser Invariant (3-Tier Protocol-Scoped Dispatch)**: Statement modifiers run through `parse_universal_field` (bypassing `Token::Ack` and `Token::Rst` when `current_protocol` is `Coap`, `Dhcp`, `Tftp`, or `Sip`) $\rightarrow$ `dispatch_protocol_field` $\rightarrow$ `parse_fallback_field` so shared keywords never shadow across protocols.
3. **Stage 3 — Semantic Validation (`src/parser/validation.rs`, `src/error.rs`)**:
   - `validate_semantics(&program, &source)` enforces symbol uniqueness, flow arity, IPv4/IPv6 endpoint homogeneity, L2 MAC-only vs IP-required protocol checks (`protocol_requires_ip` allows MAC-only `HOST` blocks on `LLDP`, `STP`, `LACP`, `EAPOL`, `VLAN`, `QINQ`, `MPLS`, `ARP`), numeric bounds (`VLAN`, `DSCP`, `ECN`, `TTL`, `FLOWLABEL`, `GENTRAP`), and modifier exclusivity with `(start, len)` `miette 7.6.0` spans.
4. **Stage 4 — Zero-Heap Protocol Payload Synthesis & Native Wire Framing (`src/builders/` & `src/packet.rs`)**:
   - 81 native RFC protocol builders in `src/builders/{l2,l3,l4,l7}/<protocol>.rs` and `src/builders/l7/snmp/{builder,crypto}.rs`.
   - `src/packet.rs` is a 100% native, rootless, offline slice-based wire framing engine (`L7 -> L4 -> L3 -> MPLS/QinQ/VLAN/Ethernet II`, RFC 1071 / RFC 9260 CRC32c / IEEE 1815 DNP3 CRC-16 checksums) requiring no `libpcap` or raw sockets.
5. **Stage 5 — Stateful Backend & 4-Tuple Progression (`src/backend/mod.rs`, `src/backend/l7_dispatch.rs`)**:
   - Expands `COMPILE` `RunStatement::{Invocation, Loop, Frame}` items (flow calls, `LOOP <n>` blocks, and inline directional frame statements).
   - Tracks bidirectional ports (`EndpointPairPorts`) and 4-tuple TCP sequence/acknowledgment numbers (`Canonical4Tuple`, initial sequence number `1000`) shared across raw `TCP` and TCP-based L7 protocols, and honors dynamic `L7DispatchResult` ports/multicast targets (`DHCP`, `MDNS`, `PTP`, `RADIUS`).
6. **Stage 6 — PCAPNG Serialization (`src/pcap.rs`) & Reverse PCAP Decompiler (`src/reverse/`)**:
   - Forward compiler buffers all `(Vec<u8>, u64)` frames in memory before transactionally writing `SHB -> IDB (ETHERNET, snaplen 65535, IfTsResol(9)) -> EPBs` via `pcap-file 2.0.0`.
   - Reverse decompiler (`src/reverse/`) normalizes `.pcap`/`.pcapng` containers (`ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL`, `LINUX_SLL2`, `NULL`, `LOOP`), dissects all 81 L2–L7 protocols, infers deterministic `host_N` topologies, verifies each frame against a per-packet self-check oracle, and emits canonical lowercase `.fasm` with shadow-state elision and `loop <N>` folding.

---

### 2.2 The Full 81-Protocol Native Matrix

- **Layer 2 (8 Protocols — Support MAC-Only `HOST` Endpoints via `protocol_requires_ip`)**:
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

### 2.3 Compiler Pipeline QA & 6-Way Lockstep Checklist

Whenever adding or modifying a protocol, keyword, or builder, verify the full end-to-end checklist:
1. **Stage 1 — 6-Way Grammar, Lexer, IDE & WASM Lockstep**:
   - Every uppercase `#[token("...")]` in `src/lexer/mod.rs` is wired into `src/parser/`, `parse_spanned_ident` (`src/parser/ident.rs`), `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, and synchronized with `frameassembly-wasm`, `docs/fasm-specification.md`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml`.
2. **Stage 2 — Two-Phase Parsing & Semantic Validation (`parse_program` $\rightarrow$ `validate_semantics(&prog, &src)`)**:
   - `parse_program(&src)` constructs `Program<'a>` and invokes `validate_semantics(&prog, &src)` to verify host IP family homogeneity (no IPv4 $\leftrightarrow$ IPv6 mixing), `protocol_requires_ip` L2 MAC-only vs L3+ IP rules, VLAN/DSCP/ECN/TTL/FLOWLABEL numeric bounds, and zero duplicate modifiers.
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
1. **Programmatic Forward & Reverse Compiler Pipeline Invocation (`parse_program`, `validate_semantics(&prog, &src)`, `compile_program`, `generate_pcap`, `reverse_pcap_bytes`)**
2. **Canonical AST Structures & `/// Syntax mapping:` Docstring Pattern (`Program<'a>`, `HostDef<'a>`, `FlowDef<'a>`, `RunStatement<'a>`, `FrameStatement<'a>`, `ArpSpec<'a>`)**
3. **3-Tier Protocol-Scoped Field Parser Dispatch Pattern (`parse_universal_field` $\rightarrow$ `dispatch_protocol_field` $\rightarrow$ `parse_fallback_field` in `src/parser/fields.rs`)**
4. **Canonical `.fasm` Scenario Archetypes (SNMPv3 USM over IPv6, Industrial OT Modbus/QinQ, Pure L2 MAC-Only LLDP/STP & Inline `COMPILE` Frame Statements)**
