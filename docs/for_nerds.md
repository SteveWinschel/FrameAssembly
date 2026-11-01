# For Nerds: Six-Stage Compiler Architecture, Rust Library API & Formal Grammars

While FrameAssembly is designed so network engineers, firewall administrators, and NOC/SOC operators can generate deterministic `.pcap` / `.pcapng` captures without writing code, under the hood `frameassembly` (v1.3.0, Rust Edition 2024) is a six-stage, zero-copy optimizing compiler, a reusable Rust library crate, and a formally specified language (`text/vnd.frameassembly`) backed by five-way synchronized context-free grammars and a `2,611`-scenario compiler-verified training corpus.

This guide is the dedicated home for **systems engineers**, **Rust developers**, and **AI/ML practitioners**. For the formal RFC 6838 media type specification, UTF-8 encoding rules, lexical magic numbers, and `.fasm` extension disambiguation (IANA, Freedesktop `shared-mime-info`, Wikidata, and GitHub Linguist), see **[`docs/fasm-specification.md`](fasm-specification.md)** and **[`contrib/`](../contrib/)**.

---

## 1. Six-Stage Zero-Copy Rust Compiler Pipeline

FrameAssembly compiles `.fasm` source buffers into nanosecond-precision `.pcap` / `.pcapng` captures through a deterministic six-stage pipeline in pure userspace—requiring **zero root privileges** (`CAP_NET_RAW`), **zero kernel sockets**, and **zero external C libraries** (`libpcap` is not required at build time or runtime).

```text
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │                           .fasm Source Text (&'a str)                         │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 1: Zero-Copy Lexical Analysis (src/lexer/mod.rs — logos 0.14)           │
 │  • DFA scanner emitting SpannedToken<'a> = (Token<'a>, Range<usize>) slices   │
 │  • 640+ ASCII case-insensitive keywords, 81 protocols, priority rules (1..=6) │
 │  • Zero heap allocations during tokenization; O(N) comment & whitespace skip  │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 2: Two-Phase Token-Slice Parsing (src/parser/ — winnow 1.0)             │
 │  • Operates on TokenSlice<'i, 'a> (Stream<'i, 'a> over pre-lexed tokens)      │
 │  • dispatch_protocol_field (src/parser/fields.rs) scopes sub-keywords to the  │
 │    active protocol before fallback, eliminating cross-protocol shadowing      │
 │  • Contextual identifier recovery (parse_spanned_ident) allows any keyword    │
 │    to serve as a HOST, FLOW, or parameter name                                │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 3: Semantic Validation (src/parser/validation.rs — miette 7.6)          │
 │  • Case-insensitive symbol resolution & duplicate HOST/FLOW/param detection   │
 │  • Flow invocation arity checking & dual-stack IPv4/IPv6 homogeneity gate     │
 │  • IEEE/RFC numeric bounds (VLAN, DSCP, ECN, TTL, FLOWLABEL, GENTRAP)         │
 │  • Cross-protocol modifier exclusivity with byte-accurate miette SourceSpans  │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 4: Zero-Heap Wire Builders, Checksums & Crypto (src/builders/, packet.rs)│
 │  • Inner-outward encapsulation: L7 -> L4 -> L3 -> MPLS/QinQ/VLAN/Ethernet II  │
 │  • Disjoint-slice RFC 1071 checksums, RFC 8200 UDP 0x0000->0xFFFF rule,       │
 │    RFC 4443/5798 IPv6 pseudo-headers, SCTP CRC32c (LE), DNP3 CRC-16 (LE)      │
 │  • ASN.1 BER/DER (rasn 0.28) + SNMPv3 USM (RFC 3414/3826/7860) Ku -> Kul      │
 │    key localization, DES-CBC / AES-128-CFB, and HMAC-MD5/SHA-1/SHA-2          │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 5: Stateful 4-Tuple & Bidirectional Port Engine (src/backend/)          │
 │  • Stage 5a (EndpointPairPorts): Two-stage port inheritance across -> and <-  │
 │  • Stage 5b (Canonical4Tuple): Shared TCP SEQ/ACK state across raw TCP & L7,  │
 │    SYN/FIN +1 ghost-byte accounting, and automatic PSH ACK framing            │
 │  • Dynamic L7DispatchResult tuple preservation (DHCP, MDNS, PTP, RADIUS)      │
 │  • RFC 1112 (01:00:5e:...) & RFC 2464 (33:33:...) multicast MAC derivation    │
 └───────────────────────────────────────┬───────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 6: Nanosecond PCAPNG Serialization (src/pcap.rs — pcap-file 2.0)        │
 │  • Transactional in-memory synthesis prior to disk I/O                        │
 │  • Block order: SHB (0x0A0D0D0A) -> IDB (ETHERNET, IfTsResol(9)) -> EPBs      │
 └───────────────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Zero-Copy Lexical Analysis (`src/lexer/mod.rs`)

The front-end tokenizer is built on [`logos 0.14`](https://docs.rs/logos) and compiles the `Token<'a>` enum into a jump-table Deterministic Finite Automaton (DFA):

* **Zero-Copy Lifetimes (`Token<'a>`)**: Variable-length tokens—including `Token::Ident(&'a str)`, `Token::StringLit(&'a str)`, `Token::IpAddress(&'a str)`, `Token::MacAddress(&'a str)`, `Token::OidStr(&'a str)`, and `Token::Number(&'a str)`—borrow slices directly from the input `&'a str` source buffer without heap allocation.
* **Case-Insensitive Keywords (`ignore(ascii_case)`)**: All 640+ DSL keywords (`HOST`, `FLOW`, `COMPILE`, `LOOP`, all 81 protocol names, header modifiers, TCP flags, and enum constants) and time unit suffixes (`ns`, `us`, `ms`, `s`, `m`) use `#[token("...", ignore(ascii_case))]`, allowing `.fasm` specifications to be written in uppercase, lowercase, or mixed case while preserving exact wire casing for string literals and bareword payloads.
* **Explicit DFA Priority Disambiguation**: Overlapping lexical classes are resolved deterministically at compile time via `logos` priority weights:
  1. `priority = 6`: IEEE 802.3 MAC addresses across colon-separated (`00:1a:2b:3c:4d:5e`), Windows hyphen-separated (`00-1A-2B-3C-4D-5E`), and Cisco dotted-quad (`001a.2b3c.4d5e`) formats—outranks IPv6 hextets and dotted OIDs.
  2. `priority = 5`: Dotted-quad IPv4 literals (`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`)—outranks dotted ASN.1 OIDs.
  3. `priority = 4`: Signed decimal and hexadecimal integer literals (`-?[0-9]+|0[xX][0-9a-fA-F]+`).
  4. `priority = 3`: ASN.1 Object Identifiers (`\.?[0-9]+(\.[0-9]+)*`).
  5. `priority = 2`: IPv6 addresses (`::[0-9a-fA-F:.]*|...`) and nanosecond/microsecond/millisecond/second/minute time suffixes (`ns`, `us`, `ms`, `s`, `m`).
  6. `priority = 1`: User-defined identifiers (`[a-zA-Z_][a-zA-Z0-9_]*`).
* **Spanned Token Output (`SpannedToken<'a>`)**: `lexer::lex(input)` returns `Result<Vec<(Token<'a>, Range<usize>)>, CompilerError>` (conceptually `SpannedToken<'a> = (Token<'a>, Range<usize>)`), pairing every token with its exact byte offset range in `O(N)` time while skipping whitespace (`[ \t\r\n\f]+`) and single-line comments (`//.*`).

### Stage 2: Two-Phase Token-Slice Combinator Parsing (`src/parser/`)

Rather than parsing raw characters with backtracking regexes, FrameAssembly uses a two-phase [`winnow 1.0`](https://docs.rs/winnow) combinator architecture operating over a contiguous token slice (`TokenSlice<'i, 'a>`, aliased as `Stream<'i, 'a>` in `src/parser/mod.rs`):

```rust
pub type Stream<'i, 'a> = &'i [(Token<'a>, core::ops::Range<usize>, &'a str)];
```

* **Protocol-Scoped Field Dispatch (`dispatch_protocol_field` in `src/parser/fields.rs`)**: Across 81 network protocols, many domain keywords naturally overlap (such as `COOKIE`, `DATA`, `VALUE`, `VERSION`, `STATUS`, `TOKEN`, `MSGID`, `GROUP`, `GET`, `SET`, `RESPONSE`, `REQID`, `ECHO_REPLY`, `QUERY`, `REPORT`, `REQUEST`, `REPLY`, and `KEEPALIVE`). In a flat parser, a 0-argument flag or `cut_err` combinator in one protocol would shadow the same keyword when used as a key-value modifier in another protocol. FrameAssembly solves this in `src/parser/statement.rs` by parsing the statement's protocol token first and then running a three-tier loop for modifiers:
  1. `parse_universal_field`: Cross-layer L2 (`VLAN`, `QINQ`, `MPLS`, `SRCMAC`, `DSTMAC`, `ETHERTYPE`), L3 (`TTL`, `DSCP`, `ECN`, `FLOWLABEL`, `IPID`, `DF`, `MF`, `FRAGOFFSET`), L4 (`SRCPORT`, `DSTPORT`, `SEQ`, `ACKNUM`, `WIN`, `MSS`, `WSCALE`, `SACK_PERM`, `TSVAL`, `TSECR`, TCP flags), payload (`PAYLOAD`, `HEXPAYLOAD`), and timing (`WAIT`) modifiers.
  2. `dispatch_protocol_field(active_proto, input)`: Routes directly to the active protocol's dedicated combinator module (`src/parser/{l2,l3,l4,l7}/<protocol>.rs`).
  3. `parse_fallback_field`: Invoked only when diagnosing cross-protocol modifier errors so Stage 3 can report a rich semantic error rather than a generic syntax failure.
* **Contextual Keyword Recovery (`parse_spanned_ident` in `src/parser/ident.rs`)**: Every keyword token in `Token<'a>` is mapped in `parse_spanned_ident`, allowing users to name hosts, flows, or flow parameters `http`, `dns`, `client`, `server`, `token`, or `status` without reserved-word collisions.

### Stage 3: Semantic Validation (`src/parser/validation.rs`)

Once `parse_all` constructs the `Program<'a>` AST, `validate_semantics(&program, &source)` enforces domain invariants before any wire buffers are allocated, returning structured [`miette 7.6`](https://docs.rs/miette) diagnostics on failure:

1. **Case-Insensitive Symbol Uniqueness**: Rejects duplicate `HOST` declarations, duplicate `FLOW` declarations, and duplicate parameter names within a `FLOW` signature (comparing normalized ASCII lowercase keys while reporting the exact source span of the duplicate).
2. **Statement Modifier Uniqueness & Exclusivity**: Rejects duplicate modifiers on the same statement, duplicate TCP flags (e.g., `SYN SYN`), and simultaneous `PAYLOAD` + `HEXPAYLOAD` declarations.
3. **IEEE & RFC Numeric Field Bounds**:
   * `VLAN`: `1..=4094` (IEEE 802.1Q 12-bit VID; `0` and `4095` are reserved).
   * `DSCP`: `0..=63` (RFC 2474 6-bit Differentiated Services Code Point).
   * `ECN`: `0..=3` (RFC 3168 2-bit Explicit Congestion Notification).
   * `TTL`: `0..=255` (8-bit IPv4 Time-to-Live / IPv6 Hop Limit).
   * `FLOWLABEL`: `0..=0xFFFFF` (`0..=1,048,575`, RFC 8200 20-bit IPv6 Flow Label).
   * `GENTRAP`: `0..=6` (RFC 1157 SNMPv1 generic trap code).
4. **Cross-Protocol Modifier Gates**: Rejects TCP flags or `SEQ`/`ACKNUM`/`WIN` on `UDP`, rejects SNMP modifiers on raw `TCP`/`UDP`, rejects SNMPv3 USM fields (`USER`, `ENGINEID`, `AUTH`, `PRIV`) on `SNMP1`/`SNMP2`, rejects `GETBULK`/`INFORM` on `SNMP1`, and rejects `COMMUNITY` on `SNMP3`.
5. **Flow Arity & Dual-Stack Endpoint Homogeneity**: Verifies that every flow call in `COMPILE` (including inside `LOOP <count> { ... }` blocks) references a defined `FLOW` with the exact argument count, resolves every argument to a declared `HOST`, and verifies `caller_host.ip.is_ipv4() == callee_host.ip.is_ipv4()` on every statement. Mixing an IPv4 host and an IPv6 host in the same packet statement is caught at compile time with the exact statement span.

### Stage 4: Zero-Heap Protocol Wire Builders & Checksum/Crypto Engines (`src/builders/` & `src/packet.rs`)

FrameAssembly constructs frames **inner-outward** (`Application Layer 7 -> Transport Layer 4 -> Network Layer 3 -> Data-Link Layer 2`) so every outer header knows the exact byte length and checksum of its encapsulated payload before serialization:

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │ Ethernet II (14B) + Optional QinQ (8B) / VLAN (4B) + Optional MPLS (4B) │
 │  ┌───────────────────────────────────────────────────────────────────┐  │
 │  │ IPv4 Header (20B, RFC 791 cksum) OR IPv6 Header (40B, RFC 8200)   │  │
 │  │  ┌─────────────────────────────────────────────────────────────┐  │  │
 │  │  │ TCP (20B + RFC 7323 opts) / UDP (8B) / SCTP (12B + chunks)  │  │  │
 │  │  │  ┌───────────────────────────────────────────────────────┐  │  │  │
 │  │  │  │ Layer 7 Wire Builder Payload + Optional PAYLOAD Bytes │  │  │  │
 │  │  │  └───────────────────────────────────────────────────────┘  │  │  │
 │  │  └─────────────────────────────────────────────────────────────┘  │  │
 │  └───────────────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────┘
```

* **Disjoint-Slice RFC 1071 One's-Complement Checksum (`packet::internet_checksum`)**:
  Implemented over `&[&[u8]]` using Rust 1.88's `slice.as_chunks::<2>()` so pseudo-headers, transport headers, and payloads are summed in place without concatenating temporary heap vectors:
  * **IPv4 Header Checksum (RFC 791)**: Computed over the 20-byte IPv4 header (`bytes 10..12`).
  * **TCP & UDP Pseudo-Header Checksums (RFC 9293 / RFC 768 / RFC 8200)**: Computed over `[&pseudo_header, &l4_header, payload]` for both IPv4 (12-byte pseudo-header) and IPv6 (40-byte pseudo-header).
  * **Mandatory UDP `0x0000 -> 0xFFFF` Folding (RFC 768 / RFC 8200 §8.1)**: In UDP, a checksum field of `0x0000` indicates "no checksum computed" (which is illegal over IPv6 and dropped by strict stacks). Whenever the one's-complement sum evaluates to `0x0000`, `build_udp_datagram` maps it to `0xFFFF`.
  * **L3 Control & Routing Checksums**: Native RFC 1071 and IPv6 pseudo-header checksums (RFC 4443 / RFC 5798) are computed automatically for `ICMP` (IPv4 Type 8/0 & ICMPv6 Type 128/129), `NDP` (Types 133–137), `IGMP`, `MLD` (Types 130–132), `GRE` (RFC 2784 optional checksum when `C=1`), `OSPF` (RFC 2328 header checksum excluding the 64-bit authentication field), and `VRRP` (RFC 3768 v2 and RFC 5798 dual-stack v3 pseudo-header checksum).
* **SCTP Castagnoli CRC32c (`builders::l4::sctp::crc32c`, RFC 9260 §3.3.10)**:
  Uses a `const` 256-entry lookup table for the reflected Castagnoli polynomial `0x82F63B78` (normal `0x1EDC6F41`). The 32-bit CRC is computed with bytes `8..12` zeroed and written into the SCTP Common Header in **little-endian** byte order (`cksum.to_le_bytes()`) while all other SCTP fields remain big-endian.
* **DNP3 IEEE 1815-2012 Reflected CRC-16 (`builders::l7::dnp3::calculate_dnp3_crc`)**:
  Computes the reflected polynomial `0xA653` (normal `0x3D65`) with inverted remainder (`!crc`) written in **little-endian** order after the 8-byte Data Link header (`0x0564` sync) and after every 16-byte chunk of Transport + Application user data.
* **ASN.1 BER/DER & SNMPv3 USM Cryptography (`src/builders/l7/snmp/`)**:
  * Uses [`rasn 0.28`](https://docs.rs/rasn), `rasn-smi`, and `rasn-snmp` to encode SMIv1/SMIv2 `VarBind` lists across all 9 ASN.1 application/universal types (`INT`, `STRING`, `OID`, `IPADDR`, `COUNTER32`, `GAUGE32`, `TIMETICKS`, `OPAQUE`, `COUNTER64`) and SNMPv1/v2c/v3 PDUs. Over IPv6, SNMPv1 `TrapV1` automatically falls back to `0.0.0.0` for the 4-byte `agent-addr` field per RFC 3584 §3.1.
  * **RFC 3414 & RFC 7860 Key Localization (`Ku -> Kul`)**: `password_to_key_generic<D>` stretches the passphrase to `1,048,576` bytes (1 MB) in 64-byte blocks through `Md5`, `Sha1`, `Sha256`, `Sha384`, or `Sha512` to derive the master key $K_u$, then hashes $K_u \parallel \text{snmpEngineID} \parallel K_u$ to produce the localized key $K_{ul}$.
  * **Privacy Encryption (`DES-CBC` & `AES-128-CFB`)**:
    * `PRIV DES` (RFC 3414 §8.1.1): Splits the 16-byte localized key into an 8-byte DES key and 8-byte pre-IV, XORs the pre-IV with the 8-byte salt to form the CBC IV, zero-pads the BER `ScopedPDU` to an 8-byte multiple, and encrypts via `cbc::Encryptor<Des>`.
    * `PRIV AES` (RFC 3826 §3.1.2.1): Forms the 128-bit CFB IV by concatenating `snmpEngineBoots (4B BE) || snmpEngineTime (4B BE) || 64-bit salt (8B)` and encrypts the `ScopedPDU` stream in-place via `cfb_mode::Encryptor<Aes128>`.
  * **Two-Pass Whole-Message HMAC Signing**: Inserts a zeroed placeholder of the exact RFC truncation length—12 bytes for `MD5`/`SHA` (RFC 3414 96-bit) or 24/32/48 bytes for `SHA256`/`SHA384`/`SHA512` (RFC 7860 192/256/384-bit)—into `msgAuthenticationParameters`, BER-encodes the outer `SnmpV3Message`, computes the truncated HMAC over the serialized message, and splices the digest into `msgAuthenticationParameters` before re-encoding.

### Stage 5: Stateful 4-Tuple & Bidirectional Port Engine (`src/backend/`)

`backend::compile_program` evaluates the `COMPILE` block (unrolling `LOOP <count>` blocks deterministically) and maintains two complementary state machines across statements:

* **Stage 5a — Two-Stage Bidirectional Port Inheritance (`EndpointPairPorts`)**:
  For every `(caller, callee)` endpoint pair in a `FLOW`:
  * On a forward arrow (`c -> s`), `src_port` defaults to the remembered `caller_port` (or `12345` on first use) unless overridden by `SRCPORT`, and `dst_port` defaults to the protocol's RFC well-known destination port (or an explicitly set `callee_port`).
  * On a reverse arrow (`c <- s`), the source and destination ports automatically flip: `src_port` inherits the server's port and `dst_port` inherits `caller_port` (`12345` or the custom `SRCPORT` from the request).
* **Dynamic L7 Builder Return-Tuple Preservation (`src/backend/l7_dispatch.rs`)**:
  Several protocols dynamically select ports or multicast destination IPs based on address family or message type. `build_l7_packet_payload` returns an `L7DispatchResult` struct `{ payload, is_tcp, src_port, dst_port, target_ip }` that preserves:
  * `DHCP`: `(payload, 68, 67)` for DHCPv4 vs. `(payload, 546, 547)` for DHCPv6.
  * `MDNS`: `(payload, 224.0.0.251, 5353)` over IPv4 vs. `(payload, ff02::fb, 5353)` over IPv6.
  * `PTP`: `(payload, 319)` for IEEE 1588 Event messages (`SYNC`, `DELAY_REQ`, `PDELAY_REQ`, `PDELAY_RESP`) vs. `(payload, 320)` for General messages (`FOLLOW_UP`, `DELAY_RESP`, `ANNOUNCE`, `SIGNALING`, `MANAGEMENT`).
  * `RADIUS`: `(payload, 1812)` for Authentication (`ACCESS_REQUEST`, `ACCESS_ACCEPT`, `ACCESS_REJECT`, `ACCESS_CHALLENGE`) vs. `(payload, 1813)` for Accounting (`ACCOUNTING_REQUEST`, `ACCOUNTING_RESPONSE`), automatically assigning the server source port on `<-` replies.
* **Stage 5b — Canonical 4-Tuple TCP State Machine (`Canonical4Tuple` & `TcpStreamState`)**:
  All TCP-based protocols (`TCP`, `BGP`, `OPENFLOW`, `TACACS`, `FTP`, `SSH`, `TELNET`, `HTTP`, `HTTP2`, `GRPC`, `WEBSOCKET`, `TLS`, `RTSP`, `SMTP`, `IMAP`, `POP3`, `LDAP`, `SMB`, `REDIS`, `MYSQL`, `POSTGRES`, `MQTT`, `AMQP`, `WHOIS`, `S7COMM`, `OPCUA`, default-TCP `MODBUS`/`NFS`/`MEMCACHED`/`DNP3`/`ETHERNETIP`, and `TRANSPORT TCP` overrides on `DNS`/`SIP`/`SYSLOG`/`KERBEROS`) share a canonical 4-tuple table keyed by sorted endpoints `((IpAddr, u16), (IpAddr, u16))`:
  * Each new stream initializes `seq1 = 1000` and `seq2 = 1000`.
  * Every frame uses the sender's current sequence counter (unless overridden by `SEQ <u32>`, which resynchronizes the counter) and sets `ACKNUM` to the peer's current sequence counter.
  * After each frame, the sender's sequence counter advances by `payload_len + (1 if SYN) + (1 if FIN)` using wrapping 32-bit arithmetic.
  * TCP-based L7 statements without explicit TCP flags automatically emit `PSH ACK` (`0x18`) frames on that connection, seamlessly continuing the sequence numbers established by a preceding raw `TCP` 3-way handshake.
* **Automatic Multicast & Unicast MAC Derivation (`derive_mac`)**:
  When a `HOST` omits `MAC` (and the statement omits `SRCMAC`/`DSTMAC`) or when a protocol targets a multicast group (`NDP`, `IGMP`, `MLD`, `OSPF`, `RIP`, `VRRP`, `HSRP`, `PIM`, `MDNS`), FrameAssembly derives the IEEE 802.3 MAC automatically:
  * **IPv6 Multicast (`ff00::/8`, RFC 2464 §7)**: Maps the low 32 bits of the IPv6 address to `33:33:xx:xx:xx:xx`.
  * **IPv4 Multicast (`224.0.0.0/4`, RFC 1112 §6.4)**: Maps the low 23 bits of the IPv4 address to `01:00:5e:xx:xx:xx` (`octets[1] & 0x7F`).
  * **Unicast Fallback**: Uses `00:00:00:00:00:01` for the forward caller and `00:00:00:00:00:02` for the callee.
  * **RFC Hop Limit Defaults**: Automatically sets IPv6 Hop Limit / IPv4 TTL to `255` for `NDP` (RFC 4861) and `VRRP` (RFC 5798) when `TTL` is not explicitly specified.

### Stage 6: Nanosecond PCAPNG Serialization (`src/pcap.rs`)

`pcap::PcapWriter` wraps [`pcap-file 2.0`](https://docs.rs/pcap-file) to emit standards-compliant PCAP Next Generation (`PCAPNG`) captures:

1. **Transactional Synthesis**: `backend::generate_pcap` executes `compile_program(program)` in memory first, creating the output file on disk only after all frames have been synthesized without error.
2. **Block Ordering (`SHB -> IDB -> EPB`)**:
   * **Section Header Block (`SHB`)**: Emitted automatically by `PcapNgWriter::new(file)` with magic bytes `0x0A0D0D0A`.
   * **Interface Description Block (`IDB`)**: Configured with `DataLink::ETHERNET` (`LINKTYPE_ETHERNET = 1`), `snaplen = 65535`, and `InterfaceDescriptionOption::IfTsResol(9)` (`10^-9` nanosecond resolution). Including `IfTsResol(9)` prevents the $1000\times$ timestamp skew that occurs when nanosecond timestamps are interpreted as default microseconds (`10^-6`).
   * **Enhanced Packet Blocks (`EPB`)**: Starts at deterministic epoch `1_700_000_000_000_000_000` ns (`2023-11-14T22:13:20Z`) and advances by each statement's `WAIT` duration (default `10ms` = `10_000_000` ns), writing `Duration::from_nanos(ts_nanos_total)` and `Cow::Borrowed(packet_data)`.

---

## 2. Repository `<layer>/<protocol>` Symmetry & Design Invariants

FrameAssembly enforces a 1-to-1 structural symmetry across `src/`, `examples/`, and `docs/`:

```text
frameassembly/
├── Cargo.toml                         # Crate manifest (Rust 1.85+, Edition 2024, centralized [lints])
├── grammar.ebnf                       # Formal ISO/IEC 14977 EBNF grammar (all 81 protocols)
├── frameassembly.gbnf                 # GGML BNF grammar for llama.cpp / XGrammar constrained decoding
├── frameassembly.lark                 # Earley/LALR Lark grammar for Outlines / vLLM / Guidance / SGLang
├── llms.txt / llms-full.txt           # AI agent discovery index & single-fetch RAG context bundle
├── frameassembly-vscode/              # VS Code extension & TextMate grammar (frameassembly.tmLanguage.json)
├── src/
│   ├── lib.rs                         # Crate root & public library re-exports
│   ├── main.rs                        # Clap 4.6 CLI entrypoint (-o, `frameassembly show`)
│   ├── error.rs                       # CompilerError enum with miette::Diagnostic source spans
│   ├── packet.rs                      # Ethernet/VLAN/QinQ/MPLS/IPv4/IPv6/TCP/UDP framing & RFC 1071 checksums
│   ├── pcap.rs                        # PcapWriter PCAPNG serializer with IfTsResol(9) nanosecond timestamps
│   ├── lexer/
│   │   └── mod.rs                     # Logos 0.14 zero-copy Token<'a> DFA & lex() entrypoint
│   ├── ast/
│   │   ├── mod.rs                     # Program, HostDef, FlowDef, FrameStatement, Protocol, Spanned<T>
│   │   ├── l2/                        # 8 L2 *Spec structs (arp, vlan, qinq, lldp, stp, lacp, eapol, mpls)
│   │   ├── l3/                        # 20 L3 *Spec structs (icmp, ndp, igmp, mld, gre, vxlan, geneve, ...)
│   │   ├── l4/                        # 3 L4 *Spec structs (tcp, udp, sctp)
│   │   └── l7/                        # 50 L7 *Spec structs (snmp, dns..sflow, http..whois, modbus..opcua)
│   ├── parser/
│   │   ├── mod.rs                     # Stream<'i, 'a>, parse_program(), top-level combinators
│   │   ├── fields.rs                  # ParsedField, parse_universal_field, dispatch_protocol_field
│   │   ├── statement.rs               # FrameBuilder accumulation & protocol-scoped modifier loop
│   │   ├── validation.rs              # validate_semantics() semantic invariant pass
│   │   └── {l2,l3,l4,l7}/             # 81 per-protocol winnow field combinators
│   ├── builders/
│   │   ├── mod.rs                     # WireContext<'a> & layer builder exports
│   │   ├── {l2,l3,l4}/                # L2, L3, and L4 wire encoders (including SCTP CRC32c)
│   │   └── l7/
│   │       ├── snmp/                  # builder.rs (rasn BER/DER) & crypto.rs (USM Ku->Kul, DES/AES, HMAC)
│   │       └── *.rs                   # 47 infrastructure, web/cloud, mail/auth/db, and OT wire builders
│   └── backend/
│       ├── mod.rs                     # compile_program(), generate_pcap(), 4-tuple & port inheritance state
│       └── l7_dispatch.rs             # L7DispatchResult dynamic port & multicast IP preservation
├── docs/                              # 12 canonical Markdown guides
├── examples/                          # 2,611 verified .fasm scenarios across 82 directories
│   ├── l2/{arp,vlan,qinq,lldp,stp,lacp,eapol,mpls}/
│   ├── l3/{icmp,ndp,igmp,mld,gre,vxlan,geneve,ipsec,esp,ah,ikev2,wireguard,ospf,bgp,rip,vrrp,hsrp,pim,bfd,openflow}/
│   ├── l4/{tcp,udp,sctp}/
│   ├── l7/{snmp/{snmpv1,snmpv2c,snmpv3},dns,mdns,dhcp,...,modbus,bacnet,dnp3,s7comm,ethernetip,opcua}/
│   └── topologies/                    # 101 multi-host enterprise, EVPN-VXLAN, 802.1X, and OT scenarios
└── tests/
    └── corpus_verification_tests.rs   # 7-gate automated verification suite
```

### Core Architectural & DSL Design Invariants

1. **Strict `<layer>/<protocol>` Symmetry**: Every one of the 81 protocols maps 1-to-1 across `src/ast/<layer>/<protocol>.rs` (`*Spec` struct with `/// Syntax mapping:` docstring), `src/parser/<layer>/<protocol>.rs` (`winnow` field combinator), `src/builders/<layer>/<protocol>.rs` (wire payload encoder), and `examples/<layer>/<protocol>/<protocol>_<scenario>.fasm` (`>= 30` verified scenarios per protocol).
2. **Zero Mandatory Sub-Keywords**: Every protocol compiles with zero sub-keywords (emitting RFC-compliant default headers, EtherTypes, IP protocol numbers, and well-known ports) while exposing every AST `*Spec` field as an optional override (enforced by Gate 6 of `corpus_verification_tests`).
3. **1 Statement = 1 Frame & Shared 4-Tuple TCP State**: Each statement in a `FLOW` emits exactly one Ethernet frame. TCP-based Layer 7 statements automatically emit `PSH ACK` (`0x18`) frames on that protocol's well-known port and share 4-tuple sequence and acknowledgment counters with raw `TCP` statements on the same connection.
4. **Polymorphic Dual-Stack Flow Reuse**: A single `FLOW` executes identically over IPv4 and IPv6 host pairs without duplicating flow logic, while mixing IPv4 and IPv6 endpoints in the same packet statement is rejected at compile time by `validate_semantics`.
5. **Five-Way Grammar & Parser Lockstep**: Every uppercase keyword token in `src/lexer/mod.rs` is synchronized across `src/parser/`, `grammar.ebnf`, `frameassembly.gbnf`, `frameassembly.lark`, and `frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json` (enforced by Gate 4 of `corpus_verification_tests`).

---

## 3. Using `frameassembly` as a Rust Library

In addition to the `frameassembly` CLI binary, the crate exposes its full compiler pipeline as a library so Rust projects can synthesize deterministic network frames in memory for protocol parser unit tests, IDS/IPS engine benchmarks, or automated `.pcap` fixture generation.

### Public API Reference

| Function / Type | Signature & Purpose |
| :--- | :--- |
| [`lexer::lex`](../src/lexer/mod.rs) | `pub fn lex<'a>(input: &'a str) -> Result<Vec<(Token<'a>, Range<usize>)>, CompilerError>`<br>Tokenizes `.fasm` source text into zero-copy `Token<'a>` items paired with byte-offset ranges. |
| [`parser::parse_program`](../src/parser/mod.rs) | `pub fn parse_program<'a>(input_str: &'a str) -> Result<Program<'a>, CompilerError>`<br>Runs `lexer::lex`, parses the token stream into a `Program<'a>` AST, and automatically runs `validate_semantics`. |
| [`parser::validate_semantics`](../src/parser/validation.rs) | `pub fn validate_semantics(program: &Program, src: &str) -> Result<(), CompilerError>`<br>Validates symbol uniqueness, flow arity, dual-stack IPv4/IPv6 homogeneity, numeric ranges, and modifier rules. |
| [`backend::compile_program`](../src/backend/mod.rs) | `pub fn compile_program(program: &Program) -> Result<Vec<(Vec<u8>, u64)>, String>`<br>Evaluates `COMPILE` in memory, returning `(raw_ethernet_frame_bytes, timestamp_nanos)` for each emitted frame. |
| [`backend::generate_pcap`](../src/backend/mod.rs) | `pub fn generate_pcap(program: &Program, output_path: &str) -> Result<(), String>`<br>Compiles `program` and writes a nanosecond-resolution PCAPNG capture file to `output_path`. |
| [`packet::build_wire_packet`](../src/packet.rs) | `pub fn build_wire_packet(...) -> Result<Vec<u8>, CompilerError>`<br>Low-level builder constructing a complete Ethernet/VLAN/QinQ/MPLS + IPv4/IPv6 + TCP/UDP frame with RFC 1071 checksums. |
| [`pcap::PcapWriter`](../src/pcap.rs) | `PcapWriter::create(path: &str)` & `writer.write_packet(packet_data: &[u8], ts_nanos_total: u64)`<br>Streaming PCAPNG writer initialized with `LINKTYPE_ETHERNET` and `IfTsResol(9)`. |
| [`error::CompilerError`](../src/error.rs) | Structured diagnostic enum implementing `std::error::Error` and `miette::Diagnostic`:<br>• `LexError { src: String, span: (usize, usize) }` (`frameassembly::lex_error`)<br>• `ParseError { message: String, src: String, span: (usize, usize) }` (`frameassembly::parse_error`)<br>• `SemanticError { message: String, src: String, span: (usize, usize) }` (`frameassembly::semantic_error`)<br>• `BackendError(String)` (`frameassembly::backend_error`) |

### Example 1: In-Memory Frame Synthesis & Byte-Offset Assertions

Use `parse_program` and `compile_program` in Rust integration tests to synthesize multi-frame conversations directly into `Vec<(Vec<u8>, u64)>` without touching the filesystem:

```rust
use frameassembly::backend::compile_program;
use frameassembly::parser::parse_program;

fn main() {
    let fasm = r#"
        HOST hmi { IP 192.168.10.5  MAC 00:1a:2b:3c:4d:5e }
        HOST plc { IP 192.168.10.20 MAC 00:1a:2b:3c:4d:5f }

        FLOW modbus_poll(c, s) {
            c -> s TCP SYN SRCPORT 50100 DSTPORT 502 SEQ 1000 WIN 64240 MSS 1460 WAIT 1ms
            c <- s TCP SYN ACK SEQ 2000 ACKNUM 1001 WIN 64240 MSS 1460 WAIT 1ms
            c -> s TCP ACK WAIT 1ms
            c -> s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS ADDR 100 COUNT 4 WAIT 5ms
            c <- s MODBUS TXID 1 UNITID 1 READ_HOLDING_REGISTERS IS_RESPONSE VALUE 42 WAIT 5ms
        }

        COMPILE {
            modbus_poll(hmi, plc)
        }
    "#;

    let program = parse_program(fasm).expect("valid .fasm specification");
    let frames = compile_program(&program).expect("in-memory wire synthesis succeeds");

    // 5 statements -> 5 Ethernet frames
    assert_eq!(frames.len(), 5);

    // Verify Ethernet II EtherType is IPv4 (0x0800 at bytes 12..14)
    let (req_frame, req_ts_ns) = &frames[3];
    assert_eq!(&req_frame[12..14], &[0x08, 0x00]);

    // Verify TCP destination port is 502 (0x01F6 at bytes 36..38) and PSH|ACK (0x18 at byte 47)
    assert_eq!(u16::from_be_bytes([req_frame[36], req_frame[37]]), 502);
    assert_eq!(req_frame[47], 0x18);

    // Verify nanosecond timestamp delta between frame 3 and frame 4 is 5ms (5,000,000 ns)
    let (resp_frame, resp_ts_ns) = &frames[4];
    assert_eq!(*resp_ts_ns - *req_ts_ns, 5_000_000);

    // Verify bidirectional port inheritance flipped ports on `c <- s` (src_port = 502, dst_port = 50100)
    assert_eq!(u16::from_be_bytes([resp_frame[34], resp_frame[35]]), 502);
    assert_eq!(u16::from_be_bytes([resp_frame[36], resp_frame[37]]), 50100);
}
```

### Example 2: Writing Deterministic `.pcap` Fixtures to Disk

```rust
use frameassembly::backend::generate_pcap;
use frameassembly::parser::parse_program;

fn write_dns_fixture(output_path: &str) {
    let fasm = r#"
        HOST stub_v6     { IP 2001:db8:10::5 }
        HOST resolver_v6 { IP 2001:4860:4860::8888 }

        FLOW dns_lookup(c, s) {
            c -> s DNS QUERY TXID 0x1a2b QNAME "api.example.com" QTYPE AAAA WAIT 2ms
            c <- s DNS RESPONSE TXID 0x1a2b QNAME "api.example.com" QTYPE AAAA RDATA "2001:db8:99::80" ANS_TTL 300 WAIT 5ms
        }

        COMPILE {
            dns_lookup(stub_v6, resolver_v6)
        }
    "#;

    let program = parse_program(fasm).expect("valid dual-stack DNS specification");
    generate_pcap(&program, output_path).expect("PCAPNG written with IfTsResol(9)");
}
```

### Example 3: Inspecting Structured `miette` Diagnostics Programmatically

All front-end error variants carry the source string (`src`) and byte-offset tuple `span: (start_byte, byte_len)`, allowing callers to pattern-match on errors or render graphical terminal reports via `miette::GraphicalReportHandler`:

```rust
use frameassembly::error::CompilerError;
use frameassembly::parser::parse_program;

fn verify_mixed_ip_family_rejection() {
    let invalid_fasm = r#"
        HOST v4_node { IP 10.0.0.1 }
        HOST v6_node { IP 2001:db8::1 }
        FLOW mismatch(a, b) {
            a -> b ICMP ECHO_REQUEST
        }
        COMPILE {
            mismatch(v4_node, v6_node)
        }
    "#;

    let err = parse_program(invalid_fasm).expect_err("mixed IPv4/IPv6 endpoints must fail");
    match err {
        CompilerError::SemanticError { message, span, .. } => {
            assert!(message.contains("Mixed IPv4 and IPv6 endpoints"));
            assert!(span.1 > 0);
        }
        other => panic!("Expected SemanticError, got: {:?}", other),
    }
}
```

---

## 4. Formal Grammars, Constrained LLM Decoding & RLVR Architecture

Because `.fasm` is a compact, non-Turing-complete specification language with zero mandatory protocol sub-keywords, it is uniquely suited for **constrained LLM decoding** (guaranteed 100% syntactically valid generation) and **Reinforcement Learning with Verifiable Rewards (RLVR)**.

### Five-Way Grammar & Lexer Lockstep

FrameAssembly maintains five grammar and syntax artifacts in strict automated lockstep verified by Gate 4 of `tests/corpus_verification_tests.rs` (which checks that all 640+ uppercase `#[token("...")]` literals in `src/lexer/mod.rs` exist in every grammar and that every RHS non-terminal resolves to a defined LHS rule):

| Artifact | Format | Target Inference Engines & Tooling |
| :--- | :--- | :--- |
| [`src/lexer/mod.rs`](../src/lexer/mod.rs) | Rust `logos 0.14` DFA | Authoritative compiler token vocabulary (`Token<'a>`) |
| [`grammar.ebnf`](../grammar.ebnf) | ISO/IEC 14977 EBNF | Canonical human and compiler context-free grammar specification |
| [`frameassembly.gbnf`](../frameassembly.gbnf) | GGML BNF (`GBNF`) | `llama.cpp` (`--grammar-file`), `MLC-LLM`, `XGrammar`, `KoboldCpp`, `TabbyAPI` |
| [`frameassembly.lark`](../frameassembly.lark) | Lark Earley / LALR | `Outlines`, `vLLM` (`guided_grammar`), `SGLang`, `Guidance`, `llguidance` |
| [`frameassembly.tmLanguage.json`](../frameassembly-vscode/syntaxes/frameassembly.tmLanguage.json) | TextMate JSON | VS Code, VSCodium, Cursor, Windsurf, and GitHub/Shiki syntax highlighting |

### Constrained Decoding with `llama.cpp` (`frameassembly.gbnf`)

Pass `--grammar-file frameassembly.gbnf` to `llama-cli` or `llama-server` to mask out invalid token logits at every decoding step:

```bash
llama-cli \
  -m qwen2.5-coder-7b-instruct-q8_0.gguf \
  --grammar-file frameassembly.gbnf \
  -p "Write a FrameAssembly (.fasm) program that performs a TCP 3-way handshake between 10.0.0.1 and 10.0.0.2 on port 443 and sends a TLS ClientHello with SNI 'secure.example.com'." \
  > generated.fasm && frameassembly generated.fasm -o synthesized.pcap
```

### Constrained Decoding with Python `Outlines` / `vLLM` (`frameassembly.lark`)

Use `frameassembly.lark` with `outlines` or `vLLM` structured outputs to guarantee valid `.fasm` generation from Python inference pipelines:

```python
from pathlib import Path
import outlines

lark_grammar = Path("frameassembly.lark").read_text(encoding="utf-8")
model = outlines.models.transformers("Qwen/Qwen2.5-Coder-7B-Instruct")
generator = outlines.generate.cfg(model, lark_grammar)

fasm_code = generator(
    "Generate a FrameAssembly (.fasm) specification for a BGP OPEN and KEEPALIVE "
    "session between peer_a (10.0.0.1, ASN 65001) and peer_b (10.0.0.2, ASN 65002)."
)
```

### Four-Stage Hierarchical Verifiable Compiler Reward (RLVR / GRPO)

Because `frameassembly` compiles in microseconds in pure memory with zero root privileges or network interfaces, the Rust library serves directly as a dense, deterministic reward oracle $R(x, y) \in [0.0, 1.0]$ for GRPO / PPO post-training:

1. **Stage 1 — Lexical Validity ($R = 0.10$, $+0.10$)**: `frameassembly::lexer::lex(candidate)` succeeds with zero `LexError` tokens.
2. **Stage 2 — Syntactic AST Validity ($R = 0.30$, $+0.20$)**: `frameassembly::parser::parse_program(candidate)` constructs a complete `Program<'a>` AST (`HOST` + `FLOW` + `COMPILE`).
3. **Stage 3 — Semantic Validity ($R = 0.60$, $+0.30$)**: `frameassembly::parser::validate_semantics(&program, candidate)` passes symbol resolution, flow arity, field range, and dual-stack IPv4/IPv6 homogeneity checks.
4. **Stage 4 — Wire & PCAPNG Synthesis ($R = 1.00$, $+0.40$)**: `frameassembly::backend::compile_program(&program)` emits deterministic Ethernet frames with valid RFC checksums (IPv4 header, TCP/UDP pseudo-header, ICMP/ICMPv6, SCTP CRC-32c, DNP3 CRC-16).

```rust
use frameassembly::backend::compile_program;
use frameassembly::lexer::lex;
use frameassembly::parser::parse_program;

/// Computes a dense verifiable reward in [0.0, 1.0] for an LLM-generated `.fasm` candidate.
pub fn compute_rlvr_reward(candidate_fasm: &str) -> f64 {
    if lex(candidate_fasm).is_err() {
        return 0.0;
    }
    let mut reward = 0.10; // Stage 1 passed (R = 0.10): 100% valid lexical tokens

    // parse_program runs both syntactic parsing (Stage 2) and validate_semantics (Stage 3)
    match parse_program(candidate_fasm) {
        Ok(program) => {
            reward += 0.50; // Stage 2 (+0.20 -> R = 0.30) + Stage 3 (+0.30 -> R = 0.60) passed
            if let Ok(frames) = compile_program(&program)
                && !frames.is_empty()
                && frames.iter().all(|(bytes, _)| bytes.len() >= 14)
            {
                reward += 0.40; // Stage 4 passed (R = 1.00): valid wire frames synthesized
            }
        }
        Err(frameassembly::error::CompilerError::SemanticError { .. }) => {
            reward += 0.20; // Stage 2 passed (R = 0.30, syntactically valid AST), failed Stage 3 semantics
        }
        Err(_) => {}
    }
    reward
}
```

---

## 5. Verified SFT / RLVR Corpus Architecture (`examples/`)

Every `.fasm` file across the **`2,611` verified scenarios** (`>= 30` per protocol across all 81 protocols plus `101` multi-host topologies in [`examples/`](../examples/)) is continuously validated by `cargo test --test corpus_verification_tests`:

* **Pre-Training Quality Filter Compliance**: Every corpus file satisfies the heuristic quality gates used by **The Stack v2**, **StarCoder2**, **FineWeb-Edu**, **Dolma**, **DeepSeek-Coder**, and **OpenCoder**:
  * Word count `>= 50` words and file size `< 50,000` bytes.
  * Average line length `<= 85` characters and maximum line length `<= 200` characters.
  * Descriptive `<protocol>_<scenario>.fasm` filenames without numeric prefixes.
* **Three-Tier Structured Metadata Headers** (used exclusively in `examples/**/*.fasm` and documented here for ML engineers—never required in user-written `.fasm` files):
  1. **Line 1 (`// PROMPT: <description>`)**: Natural-language task specification describing the protocol, topology, and wire behavior.
  2. **Line 2 (`// TOKENS: <T1, T2, ...>`)**: Exact, comma-separated uppercase `src/lexer/mod.rs` keywords exercised in the file body in first-appearance order (verified for 100% lexer bijection by Gate 2).
  3. **Block Annotations (`// INSTRUCTION: <step>`)**: Placed immediately above each `HOST`, `FLOW`, and `COMPILE` block to support 5 deterministic dataset export tasks (`13,055` total instances across `2,611` scenarios):
     * **Task 1 — Forward SFT (`2,611` pairs)**: Natural-language prompt $\rightarrow$ annotated `.fasm` specification.
     * **Task 2 — Repo/File-Level FIM (`2,611` triplets)**: `<|fim_prefix|>`, `<|fim_suffix|>`, `<|fim_middle|>` completion across `FLOW` bodies.
     * **Task 3 — Inverse Wire-to-DSL Walkthrough (`2,611` pairs)**: Deterministic PCAPNG packet dissection $\rightarrow$ `.fasm` reconstruction.
     * **Task 4 — Contrastive DPO (`2,611` triplets)**: `(prompt, chosen_valid_fasm, rejected_hallucinated_fasm)`.
     * **Task 5 — Execution-Feedback Repair & RLVR (`2,611` trajectories)**: Mutated `.fasm` + `miette` span diagnostic $\rightarrow$ repaired compilable `.fasm`.

### Corpus Header Example 1: Polymorphic Dual-Stack ICMPv4 / ICMPv6 Echo

```frameassembly
// PROMPT: Polymorphic dual-stack ICMPv4 and ICMPv6 Echo Request and Echo Reply using a single reusable FLOW.
// TOKENS: HOST, IP, FLOW, ICMP, ECHO_REQUEST, ID, SEQ, TTL, PAYLOAD, ECHO_REPLY, WAIT, COMPILE

// INSTRUCTION: Declare the IPv4 client endpoint.
HOST client_v4 { IP 10.0.0.10 }

// INSTRUCTION: Declare the IPv4 DNS responder endpoint.
HOST dns_v4    { IP 8.8.8.8 }

// INSTRUCTION: Declare the IPv6 client endpoint.
HOST client_v6 { IP 2001:db8::10 }

// INSTRUCTION: Declare the IPv6 DNS responder endpoint.
HOST dns_v6    { IP 2001:4860:4860::8888 }

// INSTRUCTION: Define a polymorphic ping flow that works over both IPv4 and IPv6.
FLOW dual_stack_ping(ep_a, ep_b) {
    ep_a -> ep_b ICMP ECHO_REQUEST ID 100 SEQ 1 TTL 64 PAYLOAD "polymorphic-ping"
    ep_a <- ep_b ICMP ECHO_REPLY ID 100 SEQ 1 TTL 57 PAYLOAD "polymorphic-ping" WAIT 5ms
}

// INSTRUCTION: Compile the flow for IPv4 and IPv6 endpoint pairs.
COMPILE {
    dual_stack_ping(client_v4, dns_v4)
    dual_stack_ping(client_v6, dns_v6)
}
```

### Corpus Header Example 2: Encrypted SNMPv3 USM (`authPriv` HMAC-SHA256 + AES-128) Trap

```frameassembly
// PROMPT: SNMPv3 USM authPriv encrypted trap using HMAC-SHA256 authentication and AES-128 privacy with sysUpTime and interface linkDown varbinds.
// TOKENS: HOST, IP, MAC, FLOW, SNMP3, TRAP, USER, ENGINEID, ENGINEBOOTS, ENGINETIME, AUTH, SHA256, PRIV, AES, REQID, OID, VARBIND, TIMETICKS, INT, COMPILE

// INSTRUCTION: Declare the managed core switch endpoint.
HOST core_sw { IP 10.100.0.254 MAC 00:1c:73:a0:00:fe }

// INSTRUCTION: Declare the NMS trap receiver endpoint.
HOST nms_srv { IP 10.100.0.10  MAC 00:50:56:a0:00:10 }

// INSTRUCTION: Define the encrypted SNMPv3 USM trap flow.
FLOW snmpv3_encrypted_trap(agent, mgr) {
    agent -> mgr SNMP3 TRAP USER "netops_v3" ENGINEID "80001f8880001c73a000fe"
        ENGINEBOOTS 5 ENGINETIME 43200
        AUTH SHA256 "AuthSecretKey2026!" PRIV AES "PrivSecretKey2026!"
        REQID 9001 OID 1.3.6.1.6.3.1.1.5.3
        VARBIND 1.3.6.1.2.1.1.3.0 TIMETICKS 4320000
        VARBIND 1.3.6.1.2.1.2.2.1.1.1 INT 1
}

// INSTRUCTION: Compile the SNMPv3 trap capture.
COMPILE {
    snmpv3_encrypted_trap(core_sw, nms_srv)
}
```

### Corpus Header Example 3: Cross-Layer IEEE 802.1Q VLAN + TCP Handshake + Modbus/TCP Poll

```frameassembly
// PROMPT: Industrial OT Modbus/TCP holding register poll over IEEE 802.1Q VLAN 200 with an explicit TCP 3-way handshake and DSCP EF marking.
// TOKENS: HOST, IP, MAC, FLOW, TCP, SYN, SRCPORT, DSTPORT, SEQ, WIN, MSS, VLAN, PCP, DSCP, WAIT, ACK, ACKNUM, MODBUS, TXID, UNITID, READ_HOLDING_REGISTERS, ADDR, COUNT, IS_RESPONSE, VALUE, COMPILE

// INSTRUCTION: Declare the SCADA HMI workstation endpoint.
HOST scada_hmi { IP 172.16.200.10 MAC 00:1b:21:aa:bb:01 }

// INSTRUCTION: Declare the substation RTU PLC endpoint.
HOST rtu_plc   { IP 172.16.200.50 MAC 00:1b:21:aa:bb:50 }

// INSTRUCTION: Define a VLAN-tagged TCP 3-way handshake followed by a Modbus Function 0x03 exchange.
FLOW ot_register_poll(hmi, plc) {
    hmi -> plc TCP SYN SRCPORT 52100 DSTPORT 502 SEQ 5000 WIN 64240 MSS 1460 VLAN 200 PCP 5 DSCP 46 WAIT 1ms
    hmi <- plc TCP SYN ACK SEQ 9000 ACKNUM 5001 WIN 64240 MSS 1460 VLAN 200 PCP 5 DSCP 46 WAIT 1ms
    hmi -> plc TCP ACK VLAN 200 PCP 5 DSCP 46 WAIT 1ms
    hmi -> plc MODBUS TXID 77 UNITID 1 READ_HOLDING_REGISTERS ADDR 40001 COUNT 2 VLAN 200 PCP 5 DSCP 46 WAIT 4ms
    hmi <- plc MODBUS TXID 77 UNITID 1 READ_HOLDING_REGISTERS IS_RESPONSE VALUE 1250 VLAN 200 PCP 5 DSCP 46 WAIT 4ms
}

// INSTRUCTION: Compile the industrial OT capture.
COMPILE {
    ot_register_poll(scada_hmi, rtu_plc)
}
```