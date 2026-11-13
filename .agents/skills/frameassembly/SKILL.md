---
name: frameassembly
description: Comprehensive architecture guide, canonical v3.0.0 strict-lowercase DSL syntax specification, AST design, 6-stage forward compiler + reverse PCAP decompiler, protocol-scoped parser dispatch, wire builders, and PCAPNG serialization patterns for FrameAssembly in Rust.
---

# FrameAssembly v3.0.0 Architecture, Canonical DSL & Protocol Engine Skill

Use this skill when designing, implementing, extending, testing, or auditing the `frameassembly` v3.0.0 Domain-Specific Language (DSL), AST structures, two-phase strict-lowercase `logos 0.14.4` + `winnow 1.0.5` parser, 81 protocol payload builders, native RFC packet assembly, PCAPNG serialization, and reverse PCAP/PCAPNG-to-`.frasm` decompilation in Rust.

---

## 1. Quick Reference & Selection Matrix (Canonical v3.0.0 Syntax Only)

| FrameAssembly Capability | Canonical v3.0.0 Pattern / Implementation | Strictly Forbidden (Hallucinated / Legacy v1 Syntax) |
| :--- | :--- | :--- |
| **CLI Execution Entry Points (Default Compile + 4 Subcommands)** | `frameassembly <input.frasm> [output.pcap]` (default root command), `frameassembly show <input.frasm>`, `frameassembly reverse <input.pcap> [output.frasm]`, `frameassembly help [subcommand]`, `frameassembly version` | Non-existent `compile` CLI subcommand, legacy `-o` / `--output` or `--show` / `--reverse` flags, bare `.pcap` at arg 1, `.frasm` as `OUTPUT.pcap`, or creating output files before semantic validation |
| **Built-In Keyword Lexical Rule (`[a-z0-9]+`)** | Strictly lowercase alphanumeric with `_` mechanically stripped and **no** `ignore(ascii_case)` (`host`, `ip`, `mac`, `flow`, `compile`, `wait`, `srcport`, `dstport`, `acknum`, `echorequest`, `innervlan`, `clienthello`, `hosthdr`, `transporthdr`, `sackperm`, `agentip`, `hellotime`, `whois`, `pkttype`, `read`, `write`, `nop`, `error`, `shutdownack`, `readholdingregisters`), while user `host`/`flow`/param identifiers allow uppercase, `_`, and `-` (`[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*`) | Uppercase, underscored, or hyphenated built-in keywords (`HOST`, `ECHO_REQUEST`, `INNER_VLAN`, `CLIENT_HELLO`, `HOST_HDR`, `TRANSPORT_HDR`, `SACK_PERM`, `WHO_IS`) |
| **Programmatic Forward & Reverse Pipeline** | `parser::parse_program(&src)` $\rightarrow$ `parser::validate_semantics(&prog, &src)` $\rightarrow$ `backend::compile_program(&prog)` / `backend::generate_pcap(&prog, path)`; `reverse::reverse_pcap_bytes` / `reverse_pcap_file` | Non-existent 1-arg `validate_semantics(&prog)`, `compile_file`, `compile_source`, `lexer::tokenize`, or `codegen::generate_packets` |
| **Host Endpoint Declaration** | `host <id> { [ip <ip>] [mac <mac>] }` (at least one of `ip` or `mac` required; space-separated, no `=`, no `:`, no `,`; pure L2 protocols `lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp` allow MAC-only via `protocol_requires_ip`) | `host x = { ip: ..., mac: ..., mask: ... }`, `ipv4` / `ipv6` inside `host`, or empty `host x {}` |
| **Parameterized Flow Block** | `flow <id>(<param1>, <param2>) { <param1> -> <param2> <proto> ... }` | Parameterless `flow name { ... }`, `flow name = { ... }`, or `from a to b` / `reverse` / `send` |
| **Timing & Delay Offsets** | Inline `wait <int><unit>` modifier on a frame statement (`ns`, `us`, `ms`, `s`, `m` — strictly lowercase) | Standalone `wait 5ms` statements on their own line, uppercase `5MS`, or `+5ms` / `[+delay]` prefixes |
| **Compile Block Execution (`RunStatement`)** | `compile { <flow>(<h1>, <h2>) <h1> -> <h2> <proto> ... }` (`RunStatement::{Invocation, Frame}`) | Removed `loop <n> { ... }` (`Token::Loop` & `RunStatement::Loop` removed in v2.0.0), named `compile name { ... }`, bare `compile`, or argumentless flow calls |
| **L2 Modifiers** | `vlan <id> [pcp <p>] [dei <d>]`, `qinq <svlan> [innervlan <cvlan>]`, `mpls <label> [exp <e>] [bos <b>] [mplsttl <t>]` | `INNER_VLAN`, `MPLS_TTL`, or `qinq <outer> <inner>` without `innervlan` |
| **L3 Modifiers** | `ttl <val>`, `dscp <d>`, `ecn <e>`, `ipid <id>`, `df`, `mf`, `fragoffset <off>`, `flowlabel <fl>` | `hoplimit` or `hop_limit` (always use `ttl` for both IPv4 and IPv6) |
| **L4 Modifiers** | `srcport <p>`, `dstport <p>`, `seq <seq>`, `acknum <ack>`, `window <w>`, `urgent <u>`, `mss <m>`, `wscale <w>`, `sackperm`, `tsval <t>`, `tsecr <t>`, bare flags `syn ack fin rst psh urg ece cwr` | `sport`, `dport`, `ack <n>`, `flags [syn, ack]`, `sack_perm` |
| **ARP Sub-Keywords** | `arp [request \| reply] [gratuitous] [sendermac <mac>] [senderip <ip>] [targetmac <mac>] [targetip <ip>]` | Non-existent `hwtype` or `prototype` tokens |
| **SNMPv3 USM Syntax** | `snmp3 get reqid 1 user "u" auth sha256 "p" priv aes "k" engineid "80..." engineboots 1 enginetime 100 varbind 1.3.6.1.2.1.1.3.0 timeticks 100` | Quoted `auth "sha256"`, `priv "aes"`, `boots`, `time`, `engine_id`, or `= timeticks(100)` |
| **Protocol-Scoped Field Parsing** | Protocol-first check before `parse_fallback_field` when `current_protocol.is_none()` (so `a -> b whois domain "example.com"` sets `Protocol::Whois` instead of BACnet `whois` shadowing it) + 3-tier statement loop (`parse_universal_field` $\rightarrow$ `dispatch_protocol_field(proto, input)` $\rightarrow$ `parse_fallback_field`) | Letting fallback modifier parsers shadow protocol names (`whois`) or flat `alt((...))` chains where `cut_err` on `value`, `version`, `status`, `token`, `msgid` or 0-arg `data`, `cookie`, `response`, `reply`, `keepalive` shadows other protocols |
| **Header Discipline for AI Corpus** | Line 1: `// PROMPT:`, Line 2: `// TOKENS:` (bijective with v3.0.0 lowercase `src/lexer/mod.rs` tokens), Block headers: `// INSTRUCTION:` | Omitting headers, uppercase/underscored tokens in `// TOKENS:`, exceeding `avg <= 85` / `max <= 200` line length, or `< 50` words |

---

## 2. Architecture Decision Guide

### 2.1 The 6-Stage FrameAssembly v3.0.0 Compiler Pipeline & Reverse PCAP Decompiler
1. **Stage 1 — Strict-Lowercase Lexical Analysis (`src/lexer/mod.rs`)**:
   - Zero-copy `logos 0.14.4` strict-lowercase tokenizer (`#[token("host")]`, `#[token("echorequest")]`, `#[token("arp")]` with zero `_`, zero `-`, and **no** `ignore(ascii_case)`; `#[logos(skip r"//[^\r\n]*")]`) producing spanned `Token<'a>` slices across all 81 protocols, L2–L4 modifiers, SNMPv3 USM parameters, time units (`ns`, `us`, `ms`, `s`, `m`), IPv4/IPv6 addresses, MAC addresses, and ASN.1 OIDs via a strict 6-tier priority ladder.
   - **v3.0.0 Token Consolidation**: `Token::Loop` is removed; `SackPerm` (`#[token("sackperm")]`), `AgentIp` (`#[token("agentip")]`), `HelloTime` (`#[token("hellotime")]`, unified across STP `u16` and HSRP `<= 255` `u8`; `HelloTimeHsrp` removed), and `Whois` (`#[token("whois")]`, unified across WHOIS and BACnet; `WhoIs` removed) are deduplicated; `pkttype`, `read`, `write`, `nop`, `error`, and `shutdownack` are promoted to first-class `Token` variants (no `PartialEq` pseudo-keyword hack on `Token::Ident`).
   - **Flexible User Identifiers**: `Token::Ident` uses `#[regex(r"[a-zA-Z_][a-zA-Z0-9_]*(-[a-zA-Z0-9_]+)*", priority = 1)]` so user-defined `host`, `flow`, and parameter names allow uppercase, `_`, and internal `-` (`fw-dmz-01`, `core_sw`) while stopping cleanly before `->`.
2. **Stage 2 — AST & Two-Phase Combinator Parsing (`src/ast/` & `src/parser/`)**:
   - Strongly-typed AST nodes in `src/ast/mod.rs` (`Program<'a>`, `HostDef<'a>` with `pub ip: Option<IpAddr>` and `pub mac: Option<[u8; 6]>`, `FlowDef<'a>`, `FrameStatement<'a>`, `RunStatement<'a>` with `{Invocation, Frame}` only, `Protocol`, `ProtocolSpec<'a>`) and `src/ast/{l2,l3,l4,l7}/<protocol>.rs`. Every AST `*Spec` struct includes `/// Syntax mapping: \`...\`` (in v3.0.0 lowercase) and `#[doc(alias = "...")]`.
   - Two-phase `winnow 1.0.5` parser over `Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)]` in `src/parser/mod.rs`, `src/parser/statement.rs`, `src/parser/fields.rs`, and `src/parser/{l2,l3,l4,l7}/<protocol>.rs` (`pub(crate) mod` for internal parser submodules).
   - **Critical Parser Invariants (Protocol-First Guard + 3-Tier Dispatch + Self-Healing Diagnostics)**:
     - When `current_protocol.is_none()` in `parse_frame_statement`, an explicit protocol-keyword matcher runs **before** `parse_fallback_field` so `a -> b whois domain "example.com"` always sets `Protocol::Whois` instead of being intercepted by BACnet's `whois` modifier.
     - Statement modifiers run through `parse_universal_field` (bypassing `Token::Ack` and `Token::Rst` when `current_protocol` is `Coap`, `Dhcp`, `Tftp`, or `Sip`) $\rightarrow$ `dispatch_protocol_field` $\rightarrow$ `parse_fallback_field`.
     - Self-healing diagnostics in `src/parser/mod.rs` & `src/error.rs` emit `"The 'loop' block was removed in FrameAssembly 2.0; invoke flows or frame statements directly inside 'compile { ... }'."` on `loop` and `"Keywords in FrameAssembly 3.0 are strictly lowercase without '_' or '-': replace '<raw>' with '<kw>'."` when an uppercase/underscored/hyphenated identifier matches a valid keyword.
3. **Stage 3 — Semantic Validation (`src/parser/validation.rs`, `src/error.rs`)**:
   - `validate_semantics(&program, &source)` enforces symbol uniqueness, flow arity, IPv4/IPv6 endpoint homogeneity, L2 MAC-only vs IP-required protocol checks (`protocol_requires_ip` allows MAC-only `host` blocks on `lldp`, `stp`, `lacp`, `eapol`, `vlan`, `qinq`, `mpls`, `arp`), numeric bounds (`vlan`, `dscp`, `ecn`, `ttl`, `flowlabel`, `gentrap`, HSRP `hellotime <= 255`), and modifier exclusivity with `(start, len)` `miette 7.6.0` spans.
4. **Stage 4 — Zero-Heap Protocol Payload Synthesis & Native Wire Framing (`src/builders/` & `src/packet.rs`)**:
   - 81 native RFC protocol builders in `src/builders/{l2,l3,l4,l7}/<protocol>.rs` and `src/builders/l7/snmp/{builder,crypto}.rs`. Wire builders normalize enum string modifiers via `.to_ascii_uppercase().replace(['_', '-'], "")` (supporting `"readholdingregisters"`, `initack`, `shutdownack`, `qtype "a"`, etc.) while preserving exact user casing on wire-literal strings (`uri`, `qname`, `sni`, `hosthdr`, `payload`, `body`).
   - `src/packet.rs` is a 100% native, rootless, offline slice-based wire framing engine (`L7 -> L4 -> L3 -> MPLS/QinQ/VLAN/Ethernet II`, RFC 1071 / RFC 9260 CRC32c / IEEE 1815 DNP3 CRC-16 checksums) requiring no `libpcap` or raw sockets.
5. **Stage 5 — Stateful Backend & 4-Tuple Progression (`src/backend/mod.rs`, `src/backend/l7_dispatch.rs`)**:
   - Expands `compile` `RunStatement::{Invocation, Frame}` items (flow calls and inline directional frame statements).
   - Tracks bidirectional ports (`EndpointPairPorts`) and 4-tuple TCP sequence/acknowledgment numbers (`Canonical4Tuple`, initial sequence number `1000`) shared across raw `tcp` and TCP-based L7 protocols, and honors dynamic `L7DispatchResult` ports/multicast targets (`dhcp`, `mdns`, `ptp`, `radius`).
6. **Stage 6 — PCAPNG Serialization (`src/pcap.rs`) & Reverse PCAP Decompiler (`src/reverse/`)**:
   - Forward compiler buffers all `(Vec<u8>, u64)` frames in memory before transactionally writing `SHB -> IDB (ETHERNET, snaplen 65535, IfTsResol(9)) -> EPBs` via `pcap-file 2.0.0`.
   - Reverse decompiler (`src/reverse/`) normalizes `.pcap`/`.pcapng` containers (`ETHERNET`, `RAW`, `IPV4`, `IPV6`, `LINUX_SLL`, `LINUX_SLL2`, `NULL`, `LOOP`), dissects all 81 L2–L7 protocols into strict v3.0.0 lowercase keywords without `_`, infers deterministic `host1`, `host2`, ... topologies (never `host_1`, `host_2`), verifies each frame against a per-packet self-check oracle (`verify_with_oracle`), and emits canonical v3.0.0 `.frasm` with shadow-state elision and direct `compile { ... }` statements (never `loop`).

---

### 2.2 The Full 81-Protocol Native Matrix (v3.0.0 Lowercase Keywords)

- **Layer 2 (8 Protocols — Support MAC-Only `host` Endpoints via `protocol_requires_ip`)**:
   `arp`, `vlan`, `qinq`, `lldp`, `stp`, `lacp`, `eapol`, `mpls`.
- **Layer 3 (20 Protocols)**:
  `icmp`, `ndp`, `igmp`, `mld`, `gre`, `vxlan`, `geneve`, `ipsec`, `esp`, `ah`, `ikev2`, `wireguard`, `ospf`, `bgp`, `rip`, `vrrp`, `hsrp`, `pim`, `bfd`, `openflow`.
- **Layer 4 (3 Protocols)**:
  `tcp`, `udp`, `sctp`.
- **Layer 7 Application, Management & OT (50 Protocols)**:
  - Network Management & Telemetry: `snmp1`, `snmp2`, `snmp3`, `netflow`, `ipfix`, `sflow`, `syslog`.
  - Core Infrastructure & AAA: `dns`, `mdns`, `dhcp`, `ntp`, `ptp`, `radius`, `tacacs`, `whois`, `ssdp`.
  - Remote Access & File Transfer: `tftp`, `ftp`, `ssh`, `telnet`.
  - Web, Cloud & Transport Security: `http`, `http2`, `grpc`, `websocket`, `tls`, `quic`.
  - Voice & Multimedia: `sip`, `rtp`, `rtsp`, `stun`.
  - Mail & Directory: `smtp`, `imap`, `pop3`, `kerberos`, `ldap`.
  - Storage, Databases & Messaging: `smb`, `nfs`, `redis`, `memcached`, `mysql`, `postgres`, `mqtt`, `coap`, `amqp`.
  - Industrial Control Systems (ICS) & SCADA/OT: `modbus`, `bacnet`, `dnp3`, `s7comm`, `ethernetip`, `opcua`.

---

### 2.3 Compiler Pipeline QA & 6-Way Lockstep Checklist

Whenever adding or modifying a protocol, keyword, or builder, verify the full end-to-end checklist:
1. **Stage 1 — 6-Way Grammar, Lexer, IDE & WASM Lockstep**:
   - Every strict-lowercase `[a-z0-9]+` `#[token("...")]` in `src/lexer/mod.rs` (zero `_`, zero `-`, no `ignore(ascii_case)`) is wired into `src/parser/`, `parse_spanned_ident` (`src/parser/ident.rs`), `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json`, and synchronized with `frameassembly-wasm`, `docs/frasm-specification.md`, `llms.txt`, `llms-full.txt`, and `contrib/mime/text-vnd.frameassembly.xml`.
2. **Stage 2 — Two-Phase Parsing & Semantic Validation (`parse_program` $\rightarrow$ `validate_semantics(&prog, &src)`)**:
   - `parse_program(&src)` constructs `Program<'a>` and invokes `validate_semantics(&prog, &src)` to verify host IP family homogeneity (no IPv4 $\leftrightarrow$ IPv6 mixing), `protocol_requires_ip` L2 MAC-only vs L3+ IP rules, `vlan`/`dscp`/`ecn`/`ttl`/`flowlabel`/HSRP `hellotime <= 255` numeric bounds, and zero duplicate modifiers.
3. **Stage 3 — AST `*Spec` Field Completeness & `l7_dispatch.rs` Return Tuples (`compile_program(&prog)`)**:
   - Every field on `<Proto>Spec` in `src/ast/{l2,l3,l4,l7}/<proto>.rs` is populated in `src/parser/finish.rs` / `l7_apply.rs` and consumed in `src/builders/{l2,l3,l4,l7}/<proto>.rs`.
   - `src/backend/l7_dispatch.rs` honors dynamic builder return tuples for `dhcp` (`(pkt, sport, dport)`), `mdns` (`(payload, target_ip, 5353)`), `ptp` (`(result, dport)`), and `radius` (`(pkt, dport)`).
4. **Stage 4 — Wire & Wireshark (`tshark`) Dissector Verification**:
   - Checksums & TTLs: `gre` `checksum` (`0x8000`) computed at `gre[4..6]`; `vrrp` v3 IPv4/IPv6 pseudo-header (`112`) + TTL/Hop Limit `255`; `ndp` Hop Limit `255`; `udp` `0x0000 -> 0xFFFF`; `sctp` little-endian CRC32c at `8..12`.
   - Inner Frames & Lengths: `geneve` `0x6558` encapsulates a 14B Ethernet + 20B IPv4 frame; `wireguard` Type `4` (`data`) appends a 16B Poly1305 AEAD tag ($\ge 32$B); `quic` Long Header encodes a 2B varint (`0x4000 | len`); `ipfix` `total_len`/`set_len` include payload; `sflow` Flow Sample has 8 `u32`s (32B); `ldap` `SearchRequest` has all 8 RFC 4511 elements; `kerberos` `KDC-REQ-BODY` includes `[7] till` and `[8] nonce`.
5. **Stage 5 — Corpus & Markdown Block Gate (`tests/corpus_verification_tests.rs`)**:
   - All `2,611` `.frasm` files in `examples/` and all ````frameassembly` / ````frasm` blocks in `README.md`, `docs/*.md`, `src/**/*.rs`, and `.agents/skills/**/*.md` compile cleanly under v3.0.0 strict-lowercase syntax into valid PCAPNG captures.

---

## 3. Production Reference Templates

Read [references/patterns.md](references/patterns.md) for complete, copy-pasteable, compiler-verified v3.0.0 production implementations:
1. **Programmatic Forward & Reverse Compiler Pipeline Invocation (`parse_program`, `validate_semantics(&prog, &src)`, `compile_program`, `generate_pcap`, `reverse_pcap_bytes`)**
2. **Canonical v3.0.0 AST Structures & `/// Syntax mapping:` Docstring Pattern (`Program<'a>`, `HostDef<'a>`, `FlowDef<'a>`, `RunStatement<'a>`, `FrameStatement<'a>`, `ArpSpec<'a>`)**
3. **Protocol-First Guard & 3-Tier Protocol-Scoped Field Parser Dispatch (`parse_explicit_protocol_kw` + `parse_universal_field` $\rightarrow$ `dispatch_protocol_field` $\rightarrow$ `parse_fallback_field`)**
4. **Canonical v3.0.0 `.frasm` Scenario Archetypes (SNMPv3 USM over IPv6, Industrial OT Modbus/QinQ, Pure L2 MAC-Only LLDP & Inline `compile` Frame Statements)**
